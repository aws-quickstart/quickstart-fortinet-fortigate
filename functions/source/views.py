import json

from AutoScaleGroup import AutoScaleGroup
from Fortigate import Fortigate
try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse

import re
import boto3
import random

from django.http import HttpResponseBadRequest, HttpResponse, Http404
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
from utils import (verify_notification, approve_subscription)

from . import signals
from scheduled import process_scheduled, process_message
from boto3.dynamodb.conditions import Key, Attr
import time
import const

from fos_api import FortiOSAPI

VITAL_NOTIFICATION_FIELDS = [
    'Type', 'Message', 'Timestamp', 'Signature',
    'SignatureVersion', 'TopicArn', 'MessageId',
    'SigningCertURL'
]

ALLOWED_TYPES = [
    'Notification', 'SubscriptionConfirmation', 'UnsubscribeConfirmation'
]

STATUS_OK = 200


def respond_to_subscription_request(request):
    const.logger.debug("subscription request(): method = %s" % request.method)
    if request.method != 'POST':
        raise Http404

    # If necessary, check that the topic is correct
    if hasattr(settings, 'FGTSCEVT_TOPIC_ARN'):
        # Confirm that the proper topic header was sent
        if 'HTTP_X_AMZ_SNS_TOPIC_ARN' not in request.META:
            return HttpResponseBadRequest('No TopicArn Header')
        #
        # Check to see if the topic is in the settings
        # Because you can have bounces and complaints coming from multiple
        # topics, FGTSCEVT_TOPIC_ARN is a list
        #
        if (not request.META['HTTP_X_AMZ_SNS_TOPIC_ARN']
        in settings.FGTSCEVT_TOPIC_ARN):
            return HttpResponseBadRequest('Bad Topic')

    # Load the JSON POST Body
    if isinstance(request.body, str):
        # requests return str in python 2.7
        request_body = request.body
    else:
        # and return bytes in python 3.4
        request_body = request.body.decode()
    try:
        data = json.loads(request_body)
    except ValueError:
        const.logger.warning('Notification Not Valid JSON: {}'.format(request_body))
        return HttpResponseBadRequest('Not Valid JSON')
    const.logger.debug("subscription request(): data = %s" %
                 (json.dumps(data, sort_keys=True, indent=4, separators=(',', ': '))))

    # Ensure that the JSON we're provided contains all the keys we expect
    # Comparison code from http://stackoverflow.com/questions/1285911/
    if not set(VITAL_NOTIFICATION_FIELDS) <= set(data):
        const.logger.warning('Request Missing Necessary Keys')
        return HttpResponseBadRequest('Request Missing Necessary Keys')

    # Ensure that the type of notification is one we'll accept
    if not data['Type'] in ALLOWED_TYPES:
        const.logger.warning('Notification Type Not Known %s', data['Type'])
        return HttpResponseBadRequest('Unknown Notification Type')

    # Confirm that the signing certificate is hosted on a correct domain
    # AWS by default uses sns.{region}.amazonaws.com
    # On the off chance you need this to be a different domain, allow the
    # regex to be overridden in settings
    domain = urlparse(data['SigningCertURL']).netloc
    pattern = getattr(
        settings, 'FGTSCEVT_CERT_DOMAIN_REGEX', r"sns.[a-z0-9\-]+.amazonaws.com$"
    )
    const.logger.debug("subscription request(): domain = %s, pattern = %s" % (domain, pattern))
    if not re.search(pattern, domain):
        const.logger.warning(
            'Improper Certificate Location %s', data['SigningCertURL'])
        return HttpResponseBadRequest('Improper Certificate Location')

    # Verify that the notification is signed by Amazon
    if (getattr(settings, 'FGTSCVT_VERIFY_CERTIFICATE', True)
        and not verify_notification(data)):
        const.logger.warning('Verification Failure %s', )
        return HttpResponseBadRequest('Improper Signature')

    # Send a signal to say a valid notification has been received
    signals.notification.send(
        sender='fortigate_autscale', notification=data, request=request)

    # Handle subscription-based messages.
    if data['Type'] == 'SubscriptionConfirmation':
        # Allow the disabling of the auto-subscription feature
        if not getattr(settings, 'BOUNCY_AUTO_SUBSCRIBE', True):
            raise Http404
        return approve_subscription(data)
    elif data['Type'] == 'UnsubscribeConfirmation':
        # We won't handle unsubscribe requests here. Return a 200 status code
        # so Amazon won't redeliver the request. If you want to remove this
        # endpoint, remove it either via the API or the AWS Console
        const.logger.warning('UnsubscribeConfirmation Not Handled')
        return HttpResponse('UnsubscribeConfirmation Not Handled')

    try:
        message = json.loads(data['Message'])
    except ValueError:
        # This message is not JSON. But we need to return a 200 status code
        # so that Amazon doesn't attempt to deliver the message again
        const.logger.exception('Non-Valid JSON Message Received')
        return HttpResponse('Message is not valid JSON')

    const.logger.debug("subscription request(): message = %s, data = %s" % (message, data))
    return process_message(message, data)


def process_autoscale_group(asg_name):
    const.logger.info("process_autoscale_group(): asg = %s" % asg_name)
    table_found = False
    data = None
    g = AutoScaleGroup(data, asg_name)
    f = Fortigate(data, asg=g)
    try:
        t = g.db_client.describe_table(TableName=asg_name)
        if 'ResponseMetadata' in t:
            if t['ResponseMetadata']['HTTPStatusCode'] == const.STATUS_OK:
                table_found = True
    except g.db_client.exceptions.ResourceNotFoundException:
        const.logger.debug("process_autoscale_group_exception_1()")
        table_found = False
    if table_found is True:
        mt = g.db_resource.Table(asg_name)
        try:
            a = mt.get_item(Key={"Type": const.TYPE_AUTOSCALE_GROUP, "TypeId": "0000"})
        except dbc.db_client.exceptions.ResourceNotFoundException:
            const.logger.exception("process_autoscale_group()")
            return
        if 'Item' in a and 'UpdateCounts' in a['Item']:
            item = a['Item']
            if item['UpdateCounts'] == 'True':
                counts_updated = False
                while counts_updated is False:
                    counts_updated = g.update_instance_counts()
                    time.sleep(1)
                item['UpdateCounts'] = 'False'
                mt.put_item(Item=item)
        try:
            r = mt.query(KeyConditionExpression=Key('Type').eq(const.TYPE_ENI_ID))
        except Exception, ex:
            raise Http404
        if r['Count'] > 0:
            for i in r['Items']:
                f.delete_second_interface(i)
        try:
            instances = mt.query(KeyConditionExpression=Key('Type').eq(const.TYPE_INSTANCE_ID))
        except Exception, ex:
            return
        if 'Items' in instances:
            if len(instances['Items']) > 0:
                for i in instances['Items']:
                    if 'State' in i and i['State'] == "LCH_LAUNCH":
                        if 'CountDown' in i and i['CountDown'] > 0:
                            value = i['CountDown']
                            value = value - 60
                            i['CountDown'] = value
                            mt.put_item(Item=i)
                        elif 'CountDown' in i and i['CountDown'] == 0:
                            e = mt.get_item(Key={"Type": const.TYPE_ENI_ID, "TypeId": i['SecondENIId']})
                            if 'Item' in e:
                                lch_name = e['Item']['LifecycleHookName']
                                lch_token = e['Item']['LifecycleToken']
                                action = 'CONTINUE'
                                time.sleep(random.randint(1, 5))
                                try:
                                    g.asg_client.complete_lifecycle_action(LifecycleHookName=lch_name,
                                                                           AutoScalingGroupName=g.name,
                                                                           LifecycleActionToken=lch_token,
                                                                           LifecycleActionResult=action)
                                except Exception, ex:
                                    const.logger.exception('index lch(): ex = %s' % ex)
                                    pass
                            i['State'] = "InService"
                            mt.put_item(Item=i)
                        else:
                            pass
    g.verify_route_tables()
    return

#
# this function is only called via lambda due to a periodic cloudwatch cron
# see zappa_settings.json for configuration
#


@csrf_exempt
def start_scheduled(event, context):
    const.logger.debug("start_scheduled(): event = %s, context = %s" % (event, context))
    extra = "fortinet_autoscale_"
    account = event['account']
    region = event['region']
    master_table_name = extra + region + "_" + account
    const.logger.debug("start_scheduled1(): master_table_name = %s" % master_table_name)
    dbc = boto3.client('dynamodb')
    dbr = boto3.resource('dynamodb')
    t = dbc.list_tables(ExclusiveStartTableName=master_table_name, Limit=1)
    if 'TableNames' not in t:
        return
    if len(t['TableNames']) == 0:
        return
    table_found = False
    try:
        t = dbc.describe_table(TableName=master_table_name)
        if 'ResponseMetadata' in t:
            if t['ResponseMetadata']['HTTPStatusCode'] == const.STATUS_OK:
                table_found = True
    except Exception, ex:
        table_found = False
    if table_found is True:
        mt = dbr.Table(master_table_name)
        try:
            r = mt.query(KeyConditionExpression=Key('Type').eq(const.TYPE_AUTOSCALE_GROUP))
        except dbc.db_client.exceptions.ResourceNotFoundException:
            const.logger.exception("start_scheduled_except_2()")
            return
        if 'Items' in r:
            if len(r['Items']) > 0:
                for asg in r['Items']:
                    process_autoscale_group(asg['TypeId'])
    return

#
# This routine takes the place of start_scheduled() above, when running in django locally
#


@csrf_exempt
def start(event):
    const.logger.info("start(): event = %s" % event)
    if event.method != 'POST':
        raise Http404
    if isinstance(event.body, str):
        request_body = event.body
        try:
            data = json.loads(request_body)
        except ValueError:
            const.logger.exception('start(): Notification Not Valid JSON: {}'.format(request_body))
            return HttpResponseBadRequest('Not Valid JSON')
    const.logger.debug("start(): data = %s" % (json.dumps(data, sort_keys=True, indent=4, separators=(',', ': '))))
    rc = process_scheduled(event, data)
    return HttpResponse(rc)


@csrf_exempt
def index(request):
    const.logger.debug("====== index() ======")
    const.logger.debug("====== end index() ======")
    return HttpResponse('0')
    # dbc = boto3.client('dynamodb')
    # dbr = boto3.resource('dynamodb')
    # table_found = False
    # master_table_name = "fortinet_autoscale_us-west-1_123073262904"
    # t = dbc.list_tables(ExclusiveStartTableName=master_table_name, Limit=1)
    # if 'TableNames' not in t:
    #     return
    # if len(t['TableNames']) == 0:
    #     return
    # try:
    #     t = dbc.describe_table(TableName=master_table_name)
    #     if 'ResponseMetadata' in t:
    #         if t['ResponseMetadata']['HTTPStatusCode'] == const.STATUS_OK:
    #             table_found = True
    # except dbc.exceptions.ResourceNotFoundException:
    #     const.logger.exception("start_scheduled(): Waiting for an Autoscale Group. Master Table Not Found")
    #     table_found = False
    #     return HttpResponse('0')
    # if table_found is True:
    #     mt = dbr.Table(master_table_name)
    #     try:
    #         r = mt.query(KeyConditionExpression=Key('Type').eq(const.TYPE_AUTOSCALE_GROUP))
    #     except dbc.db_client.exceptions.ResourceNotFoundException:
    #         const.logger.exception("start_scheduled_except_2()")
    #         return
    #     const.logger.debug("start_scheduled3(): r = %s" % r)
    #     if 'Items' in r:
    #         if len(r['Items']) > 0:
    #             for asg in r['Items']:
    #                 process_autoscale_group(asg['TypeId'])
    #     return HttpResponse('0')


@csrf_exempt
def sns(request):
    """Endpoint that SNS accesses. Includes logic verifying request"""
    #
    # pylint: disable=too-many-return-statements,too-many-branches
    #
    # In order to 'hide' the endpoint, all non-POST requests should return
    # the site's default HTTP404
    #
    if isinstance(request.body, str):
        # requests return str in python 2.7
        request_body = request.body
    try:
        data = json.loads(request_body)
    except ValueError:
        const.logger.exception('sns(): Notification Not Valid JSON: {}'.format(request_body))
        return HttpResponseBadRequest('Not Valid JSON')
    const.logger.debug("sns(): request = %s" % (json.dumps(request.body, sort_keys=True, indent=4, separators=(',', ': '))))

    if 'TopicArn' not in data:
        return HttpResponseBadRequest('Not Valid JSON')
    url = None
    if 'HTTP_HOST' in request.META:
        url = 'https://' + request.META['HTTP_HOST']

    #
    # Handle Subscription Request up front. The first Subscription request will trigger a DynamoDB table creation
    # and it will not be responded to. The second request will have an ACTIVE table and the subscription request
    # will be responded to and start the flow of Autoscale Messages.
    #
    if request.method == 'POST' and data['Type'] == 'SubscriptionConfirmation':
        const.logger.info('SubscriptionConfirmation()')
        g = AutoScaleGroup(data)
        const.logger.debug('SubscriptionConfirmation 1(): g = %s' % g)
        #
        # Create the master table if it does not exist. Master table is just a list of autoscale group names.
        # The master table is named "fortinet_autoscale_<region>_<account_id>.
        # The scheduled cloudwatch process will read the master table every 60 seconds and execute
        # all the housekeeping functions for each managed autoscale group.
        #
        master_table_found = False
        master_table_name = "fortinet_autoscale_" + g.region + "_" + g.account
        try:
            t = g.db_client.describe_table(TableName=master_table_name)
            if 'ResponseMetadata' in t:
                if t['ResponseMetadata']['HTTPStatusCode'] == const.STATUS_OK:
                    master_table_found = True
        except g.db_client.exceptions.ResourceNotFoundException:
            master_table_found = False
        if master_table_found is False:
            try:
                g.db_client.create_table(AttributeDefinitions=const.attribute_definitions,
                                            TableName=master_table_name, KeySchema=const.schema,
                                            ProvisionedThroughput=const.provisioned_throughput)
            except Exception, ex:
                const.logger.debug('SubscriptionConfirmation master_table_create(): table_status = %s' % ex)
                return
        mt = g.db_resource.Table(master_table_name)
        asg = {"Type": const.TYPE_AUTOSCALE_GROUP, "TypeId": g.name}
        master_table_written = False
        while master_table_written is False:
            try:
                mt.put_item(Item=asg)
                master_table_written = True
            except g.db_client.exceptions.ResourceNotFoundException:
                master_table_written = False
                time.sleep(5)
        #
        # End of master table
        #
        r = None
        try:
            r = g.db_client.describe_table(TableName=g.name)
        except Exception, ex:
            table_status = 'NOTFOUND'

        if r is not None and 'Table' in r:
            table_status = r['Table']['TableStatus']

        const.logger.debug('SubscriptionConfirmation 2(): table_status = %s' % table_status)
        #
        # If NOTFOUND, fall through to write_to_db() and it will create the table
        #
        if table_status == 'NOTFOUND':
            pass
        #
        # If ACTIVE and we received a new Subscription Confirmation, delete everything in the table and start over
        #
        elif table_status == 'ACTIVE':
            table = g.db_resource.Table(g.name)
            response = table.scan()
            if 'Items' in response:
                for r in response['Items']:
                    table.delete_item(Key={"Type": r['Type'], "TypeId": r['TypeId']})
        #
        # If CREATING, this is the second Subscription Confirmation and AWS is still busy creating the table
        #   just ignore this request
        elif table_status == 'CREATING':
            return
        else:
            #
            # Unknown status. 404
            #
            raise Http404

        const.logger.debug('SubscriptionConfirmation pre write_to_db()')
        g.write_to_db(data, url)

        const.logger.debug('SubscriptionConfirmation post write_to_db(): g.status = %s' % g.status)
        if g.status == 'CREATING':
            return
        if g.asg is None:
            raise Http404

        if g.status == 'ACTIVE':
            const.logger.info('SubscriptionConfirmation respond_to_subscription request()')
            return respond_to_subscription_request(request)

    #
    # Handle the following NOTIFICATION TYPES: TEST, EC2_LCH_Launch, EC2_Launch, EC2_LCH_Terminate, EC2_Terminate
    #
    if request.method == 'POST' and 'Type' in data and data['Type'] == 'Notification':
        #
        # if this is a TEST_NOTIFICATION, just respond 200. Autoscale group is likely in te process of being created
        #
        if 'Message' in data:
            try:
                msg = json.loads(data['Message'])
            except ValueError:
                const.logger.exception('sns(): Notification Not Valid JSON: {}'.format(data['Message']))
                return HttpResponseBadRequest('Not Valid JSON')
            if 'Event' in msg and msg['Event'] == 'autoscaling:TEST_NOTIFICATION':
                return HttpResponse(0)
            g = AutoScaleGroup(data)
            g.write_to_db(data, url)
            if g.asg is None:
                raise Http404
            g.process_notification(data)
            return HttpResponse(0)

@csrf_exempt
def callback(request):
    ip = None
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    const.logger.info('received callback connection from: {}' .format(ip))
    if request.method != 'POST':
        raise Http404
    rpath = request.path
    a,b,c = rpath.split("/")
    group = c
    request_body = request.body
    if request_body is not None and request_body != '':
        data = json.loads(request_body)
        const.logger.debug('callback url path: {}' .format(request.path))
        const.logger.debug('callback post data: {}' .format(data))
        const.logger.debug('parsed asg_name: {}' .format(group))
    if ip is not None and group is not None:
        g = AutoScaleGroup(data=None, asg_name=group)
        g.callback_add_member_to_lb(ip, False)
    return HttpResponse(0)
