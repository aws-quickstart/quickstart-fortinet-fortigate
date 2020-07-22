'use strict';

/*
FortiGate Autoscale Project - AWS Lambda - FortiAnalyzer handler
Author: Fortinet
*/
/* eslint-disable no-inner-declarations */
exports = module.exports;
const cfnResponse = require('./cfn-response');
const apiClient = require('./api-client'); // FAZ api client
const fgtAutoscaleAws = require('fortigate-autoscale-aws');
let timer,
    responseData = {
        PrivateIp: null,
        InstanceId: null,
        VIP: null
    },
    responseStatus = cfnResponse.FAILED;
function timeout() {
    throw new Error('Execution is about to time out, sending failure response to CloudFormation');
}

exports.handler = async (event, context) => {
    console.log('incoming event:', event);
    console.log(`Script time out in : ${context.getRemainingTimeInMillis() - 500} ms`);
    timer = setTimeout(timeout, context.getRemainingTimeInMillis() - 500);
    try {
        // const path = require('path');
        const AWS = require('aws-sdk');
        const fgtAutoscale = require('fortigate-autoscale-aws');

        // lock the API versions
        AWS.config.apiVersions = {
            ec2: '2016-11-15',
            lambda: '2015-03-31',
            dynamodb: '2012-08-10',
            apiGateway: '2015-07-09',
            s3: '2006-03-01'
        };

        AWS.config.update({ region: process.env.AWS_REGION });

        const RESOURCE_TAG_PREFIX = process.env.RESOURCE_TAG_PREFIX || '',
            docClient = new AWS.DynamoDB.DocumentClient(),
            DB = fgtAutoscaleAws.AutoScaleCore.dbDefinitions.getTables(RESOURCE_TAG_PREFIX),
            logger = new fgtAutoscale.AutoScaleCore.DefaultLogger(console),
            FortiAnalyzerSettingItem = fgtAutoscale.settingItems.FortiAnalyzerSettingItem;
        const lambda = new AWS.Lambda();
        const kms = new AWS.KMS();

        async function registerFaz(instanceId, ip, primary = '', vip = '') {
            logger.info('calling registerFaz');
            let params = {
                Item: {
                    instanceId: instanceId,
                    ip: ip,
                    primary: !!primary,
                    vip: vip ? vip : ip
                },
                TableName: DB.FORTIANALYZER.TableName
            };
            let result = await docClient.put(params).promise();
            let settingItem = new FortiAnalyzerSettingItem(instanceId, ip, vip ? vip : ip);
            params = {
                Item: settingItem.toDb(),
                TableName: DB.SETTINGS.TableName
            };
            return result && (await docClient.put(params).promise());
        }

        async function deregisterFaz(instanceId) {
            logger.info('calling deregisterFaz');
            // remove the db entry for this faz
            let params = {
                TableName: DB.FORTIANALYZER.TableName,
                Key: { instanceId: instanceId }
            };
            let result = await docClient.delete(params).promise();
            params = {
                TableName: DB.SETTINGS.TableName,
                KeyConditionExpression: '#SettingKey = :SettingKey',
                ExpressionAttributeNames: {
                    '#SettingKey': 'settingKey'
                },
                ExpressionAttributeValues: {
                    ':SettingKey': FortiAnalyzerSettingItem.SETTING_KEY
                }
            };
            let response = await docClient.query(params).promise();
            // check if it is also registered as the faz HA primary instance, then remove it
            if (response.Items && Array.isArray(response.Items) && response.Items.length === 1) {
                let settingItem = FortiAnalyzerSettingItem.fromDb(response.Items[0]);
                if (settingItem.instanceId === instanceId) {
                    return await docClient
                        .delete({
                            TableName: DB.SETTINGS.TableName,
                            Key: {
                                settingKey: FortiAnalyzerSettingItem.SETTING_KEY
                            }
                        })
                        .promise();
                }
            } else {
                return result;
            }
        }

        async function authorizeFgt(host, port, adminUsername, adminPassword) {
            logger.info('calling authorizeFgt');
            let client = new apiClient.fazApiClient(host, port);
            try {
                let connected = await client.connect(adminUsername, adminPassword);
                if (!connected) {
                    // if cannot connect to the faz, don't show error, but return fals directly
                    logger.info('called authorizeFgt. not connected to faz. return false.');
                    return false;
                }
                let devices = await client.listDevices();
                await client.authorizeDevice(devices);
                logger.info(
                    `called authorizeFgt: ${(devices && devices.length) || ''} ` +
                        'devices in total have been authorized.'
                );
                return true;
            } catch (error) {
                let errorSting = JSON.stringify(error);
                // mask sensitive data.
                errorSting
                    .replace(
                        new RegExp(adminUsername, 'g'),
                        '[username is masked for security purposes]'
                    )
                    .replace(
                        new RegExp(adminPassword, 'g'),
                        '[password is masked for security purposes]'
                    );
                logger.warn('called authorizeFgt: error:', errorSting);
            }
        }

        async function retrieveLoggingSetting() {
            const params = {
                TableName: DB.SETTINGS.TableName,
                KeyConditionExpression: '#SettingKey = :SettingKey',
                ExpressionAttributeNames: {
                    '#SettingKey': 'settingKey'
                },
                ExpressionAttributeValues: {
                    ':SettingKey': FortiAnalyzerSettingItem.SETTING_KEY
                }
            };
            let response = await docClient.query(params).promise();
            if (response.Items && Array.isArray(response.Items) && response.Items.length === 1) {
                return FortiAnalyzerSettingItem.fromDb(response.Items[0]);
            } else {
                return null;
            }
        }

        async function getDecryptedEnvironmentVariable(name) {
            const encrypted = process.env[name];
            try {
                const data = await kms
                    .decrypt({ CiphertextBlob: Buffer.from(encrypted, 'base64') })
                    .promise();
                logger.info('Environment variable is decrypted. Use the decrpted value.');
                return data.Plaintext.toString('ascii');
            } catch (error) {
                // if the string cannot be decrypted, use the original one
                if (error.code && error.code === 'InvalidCiphertextException') {
                    logger.info(
                        'Unseccessfully decrypt the given varable probably because ' +
                            'the input is a non-encrypted value. Use its original value instead.'
                    );
                } else {
                    throw error;
                }
            }
            return encrypted;
        }

        /**
         * need lambda:GetFunction permission on the function arn.
         * @param {*} functionName the name of function to get variable
         */
        async function getFunctionEnvironmentVariables(functionName) {
            let params = {
                FunctionName: functionName
            };
            return await new Promise((resolve, reject) => {
                lambda.updateFunctionConfiguration(params, (err, data) => {
                    if (err) {
                        reject(err);
                    } else {
                        resolve(data.Environment.Variables);
                    }
                });
            });
        }

        /**
         * update the lambda function to use a predefined auto-scale account or not
         * need lambda:GetFunction, ambda:GetFunctionConfiguration and
         * lambda:UpdateFunctionConfiguration permission on the function arn.
         * @param {*} functionName the name of function to update
         * @param {*} enabled a flag to toggle this feature
         */
        async function SetUseAutoscaleAdminAccount(functionName, enabled = true) {
            let envVars = await getFunctionEnvironmentVariables(functionName);
            envVars.USE_AUTOSCALE_ADMIN_ACCOUNT = enabled ? 'true' : 'false';
            let params = {
                FunctionName: functionName,
                Environment: {
                    Variables: envVars
                }
            };

            return await new Promise((resolve, reject) => {
                lambda.updateFunctionConfiguration(params, err => {
                    if (err) {
                        reject(err);
                    } else {
                        resolve(true);
                    }
                });
            });
        }

        logger.info('requested event:', event);
        let serviceType = event.ResourceProperties.ServiceType;
        // if do faz registration
        if (serviceType === 'registration') {
            // only the creating stack can register faz
            if (event.StackId !== process.env.STACK_ID) {
                throw new Error('Invalid registration caller.');
            }
            logger.info('FortiAnalyzer registration process starts.');
            switch (event.RequestType) {
                case 'Create':
                    logger.info(`register Faz by a ${event.RequestType} event.`);
                    await registerFaz(
                        event.ResourceProperties.InstanceId,
                        event.ResourceProperties.PrivateIp
                    );
                    break;
                case 'Update':
                    logger.info(`register Faz by a ${event.RequestType} event.`);
                    await registerFaz(
                        event.ResourceProperties.InstanceId,
                        event.ResourceProperties.PrivateIp
                    );
                    await deregisterFaz(event.OldResourceProperties.InstanceId);
                    break;
                case 'Delete':
                    logger.info(`deregister Faz by a ${event.RequestType} event.`);
                    await deregisterFaz(event.ResourceProperties.InstanceId);
                    break;
                default:
                    throw new Error(`Unexpected request type: ${event.RequestType}`);
            }
            responseData.PrivateIp = event.ResourceProperties.PrivateIp;
            responseData.InstanceId = event.ResourceProperties.InstanceId;
            responseData.VIP = event.ResourceProperties.PrivateIp;
        } else if (serviceType === 'retrieveSetting') {
            logger.info('FortiAnalyzer logging setting retrieval starts.');
            let settingItem = await retrieveLoggingSetting();
            responseData.PrivateIp = settingItem ? settingItem.ip : '';
            responseData.InstanceId = settingItem ? settingItem.instanceId : '';
            responseData.VIP = settingItem ? settingItem.vip : responseData.PrivateIp;
        } else if (serviceType === 'authorizeFgt') {
            const decryptedHost = await getDecryptedEnvironmentVariable('FORTIANALYZER_IP');
            const decryptedPort = await getDecryptedEnvironmentVariable('FORTIANALYZER_PORT');
            let decryptedName, decryptedPass;
            let authorizationDone = false;
            let shouldUseAutoscaleAdminAccount = false;
            // if ever successfully connected to the FAZ using the user-specified account, keep
            // using it. if it's unkown yet. try it once. otherwise, use the default admin account
            // and instance id as initial password.
            // the unknown state should appear only once. it will get updated to either true
            // or false.
            if (
                process.env.USE_AUTOSCALE_ADMIN_ACCOUNT === 'true' ||
                process.env.USE_AUTOSCALE_ADMIN_ACCOUNT === 'unknown'
            ) {
                decryptedName = await getDecryptedEnvironmentVariable('AUTOSCALE_ADMIN_USERNAME');
                decryptedPass = await getDecryptedEnvironmentVariable('AUTOSCALE_ADMIN_PASSWORD');
                authorizationDone = await authorizeFgt(
                    decryptedHost,
                    decryptedPort,
                    decryptedName,
                    decryptedPass
                );
                shouldUseAutoscaleAdminAccount = authorizationDone;
            } else {
                // try to connect to the faz using the default admin and instance id as initial
                // password. if users have changed the initial password, they must create the
                // autoscale admin account with name and password they provided in the template.
                // otherwise, this function using the initial password ends up as bad attempts.
                // Thus causing the admin account to be locked.
                decryptedName = 'admin';
                decryptedPass = process.env.INSTANCE_ID;
                authorizationDone = await authorizeFgt(
                    decryptedHost,
                    decryptedPort,
                    decryptedName,
                    decryptedPass
                );
                // if can authorize using the default admin and initial password, assume no need
                // to switch to use the user-specified account.
                shouldUseAutoscaleAdminAccount = !authorizationDone;
            }
            // make decision whether should use (or not use) the user-specified autoscale admin
            // to login faz from next time onword.

            if (
                process.env.USE_AUTOSCALE_ADMIN_ACCOUNT === 'unknown' ||
                (process.env.USE_AUTOSCALE_ADMIN_ACCOUNT !== 'true') ===
                    shouldUseAutoscaleAdminAccount
            ) {
                console.log('context.functionName:', context.functionName);
                await SetUseAutoscaleAdminAccount(
                    context.functionName,
                    shouldUseAutoscaleAdminAccount
                );
            }
        } else {
            throw new Error(`Unknown service type: ${serviceType}`);
        }
        responseStatus = cfnResponse.SUCCESS;
    } catch (error) {
        console.log(error);
        responseStatus = cfnResponse.FAILED;
    } finally {
        clearTimeout(timer);
        if (event.StackId && event.RequestId && event.ResponseURL) {
            await cfnResponse.sendAsync(event, context, responseStatus, responseData);
        }
    }
};
/* eslint-enable no-inner-declarations */
