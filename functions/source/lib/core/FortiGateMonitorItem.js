'use strict';

/*
Author: Fortinet
*
* Contains all the relevant information needed to handle FortiGate HeartBeat.
*/

module.exports = class FortiGateMonitorItem {
    constructor(intanceId, ip, heartBeatLossCount, nextheartBeatTime) {
        this.intanceId = intanceId;
        this.ip = ip;
        this.heartBeatLossCount = heartBeatLossCount;
        this.nextheartBeatTime = nextheartBeatTime;
    }

    get healthy() {
        throw new Error('getter healthy not implemented');
    }

    toDb() {
        throw new Error('toDb() not implemented');
    }

    static fromDb(entry) {
        return new FortiGateMonitorItem(entry.instanceId, entry.ip,
            entry.heartBeatLossCount, entry.nextheartBeatTime);
    }

    toJSON() {
        return {
            intanceId: this.intanceId,
            ip: this.ip,
            heartBeatLossCount: this.heartBeatLossCount,
            nextheartBeatTime: this.nextheartBeatTime
        };
    }
};

