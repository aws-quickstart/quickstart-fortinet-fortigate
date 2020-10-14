'use strict';

/*
FortiGate Autoscale Project - AWS Lambda - FortiAnalyzer remote api client
Author: Fortinet
*/

exports = module.exports;
const https = require('https');
const axios = require('axios');

class fazApiClient {
    constructor(host, port = 80) {
        this.host = host;
        this.port = port;
    }
    async requestAsync(data) {
        // original command:
        // eslint-disable-next-line max-len
        // let command = `curl -m 5 --silent -k -H "Accept: application/json" -X POST "https://${this.host}:${this.port}/jsonrpc" -d '${JSON.stringify(data)}'`;
        let options = {
            method: 'POST',
            headers: {
                Accept: 'application/json'
            },
            url: `https://${this.host}:${this.port}/jsonrpc`,
            data: data, // data in JSON form to sent as request bodydata: data, // data in JSON form to sent as request body
            timeout: 30000,
            httpsAgent: new https.Agent({
                rejectUnauthorized: false
            }) // resolve self signed certificate issue
        };
        return await axios(options).then(response => {
            return response.data;
        }); // error will be thrown.
    }

    async connect(username, password) {
        this.username = username;
        this.password = password;
        this.connectData = {
            method: 'exec',
            params: [
                {
                    url: '/sys/login/user',
                    data: {
                        user: username,
                        passwd: password
                    }
                }
            ],
            id: 1
        };
        try {
            let data = await this.requestAsync(this.connectData);
            if (data && data.session) {
                this.token = data.session;
                return this.token;
            }
        } catch (error) {
            console.log('error occur:', error);
            return null;
        }
    }

    async listDevices() {
        let data = {
            method: 'get',
            id: '1',
            params: [
                {
                    url: '/dvmdb/device'
                }
            ],
            jsonrpc: '1.0',
            session: this.token
        };
        try {
            let result = await this.requestAsync(data);
            if (result && result.result && result.result.length > 0 && result.result[0].data) {
                return Promise.resolve(result.result[0].data);
            }
        } catch (error) {
            console.log('error occur:', error);
            return Promise.reject(error);
        }
    }

    async authorizeDevice(deviceList) {
        // filter the unregistered device and authorize them
        let devices = deviceList
            .filter(device => {
                // TODO: what criteria to distinguish a unregister device?
                return device;
            })
            .map(device => {
                device.adm_usr = this.username;
                device.adm_pass = this.password;
                device.mgmt_mode = 2; // what it means?
                device.mr = 6; // what it means?
                device.platform_Id = -1; // what it means?
                return device;
            }, this);
        let req = {
            method: 'exec',
            id: '1',
            params: [
                {
                    url: '/dvm/cmd/add/dev-list',
                    data: {
                        flags: ['create_task', 'noblocking'],
                        adom: 'root',
                        'add-dev-list': devices
                    }
                }
            ],
            session: this.token
        };

        try {
            let result = await this.requestAsync(req);
            return result;
        } catch (error) {
            console.log('error occur:', error);
            return Promise.reject(error);
        }
    }
}

exports.fazApiClient = fazApiClient;
