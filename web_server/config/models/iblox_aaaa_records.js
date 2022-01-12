'use strict';

/**
 * Copyright 2022 Adobe. All rights reserved.
 * This file is licensed to you under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under
 * the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR REPRESENTATIONS
 * OF ANY KIND, either express or implied. See the License for the specific language
 * governing permissions and limitations under the License.
 */

const mongoose = require('mongoose');
const Schema = mongoose.Schema;

// Infoblox aaaa model
const ipv6AddrSchema = new Schema({
    name: String, // fqdn
    zone: String,
    infoblox_zone: String,
    ipv6addr: String,
    _ref: String,
    created: Date,
    updated: Date,
    view: String, // External
}, {
    collection: 'iblox_aaaa_records',
});

const ipv6AddrModel = mongoose.model('ipv6AddrModel', ipv6AddrSchema);

module.exports = {
    ipv6AddrModel: ipv6AddrModel,
    getIBIPv6AddrByZonePromise: function (zone) {
        return ipv6AddrModel.find({
            'zone': zone,
        }).exec();
    },
    getIBIPv6AddrByIBloxZonePromise: function (zone) {
        return ipv6AddrModel.find({
            'infoblox_zone': zone,
        }).exec();
    },
    getIBIPv6AddrByNamePromise: function (name) {
        return ipv6AddrModel.find({
            'name': name,
        }).exec();
    },
    getIBIPv6AddrByIPPromise: function (ip) {
        return ipv6AddrModel.find({
            'ipv6addr': ip,
        }).exec();
    },
    getIBIPv6AddrByIPRangePromise: function (ipRange) {
        let reZone = new RegExp('^' + ipRange + '\\..*');
        return ipv6AddrModel.find({
            'ipv6addr': { '$regex': reZone },
        }).exec();
    },
    getIBIPv6AddrCountPromise: function (zone) {
        let query = {};
        if (zone) {
            query = { 'zone': zone };
        }
        return ipv6AddrModel.countDocuments(query).exec();
    },
};
