import json
import boto3

instanceList = []
regionList = []
targetInstanceId = ''
targetPublicIpAddress = ''
targetPrivateIpAddress = ''

def list_regions(region):
    global regionList
    regionList = []
    ec2 = boto3.client('ec2', region_name=region)
    response = ec2.describe_regions()
    print '-=-=-=-=-=-'
    print 'Getting a list of Regions:'
    print
    for region in response['Regions']:
        regionList.append(region["RegionName"])
    print regionList
    print '-=-=-=-=-=-'

def list_instances_by_taginfo(region, tagKey, tagValue):
    global instanceList
    instanceList = []
    ec2 = boto3.client('ec2', region_name=region)
    response = ec2.describe_instances(
        Filters=[
            {
                'Name': 'tag:'+tagKey,
                'Values': [tagValue]
            }
        ]
    )
    for reservation in (response["Reservations"]):
        for instance in reservation["Instances"]:
            instanceList.append(instance["InstanceId"])
    print '-=-=-=-=-=-'
    print('Searching region: %s instances with tag: %s value: %s' % (region, tagKey, tagValue))
    print
    print instanceList
    print '-=-=-=-=-=-'

def get_instance_details(region, instanceid):
    global targetInstanceId
    global targetPublicIpAddress
    global targetPrivateIpAddress
    targetInstanceId = ''
    targetPublicIpAddress = ''
    targetPrivateIpAddress = ''
    ec2 = boto3.client('ec2', region_name=region)
    response = ec2.describe_instances(
        Filters=[
            {
                'Name': 'instance-id',
                'Values': [instanceid]
            }
        ]
    )
    print '-=-=-=-=-=-'
    targetInstanceId = response["Reservations"][0]["Instances"][0]["InstanceId"]
    targetPublicIpAddress = response["Reservations"][0]["Instances"][0]["PublicIpAddress"]
    targetPrivateIpAddress = response["Reservations"][0]["Instances"][0]["PrivateIpAddress"]
    print targetInstanceId
    print targetPublicIpAddress
    print targetPrivateIpAddress
    print '-=-=-=-=-=-'

##
## end of file
##
