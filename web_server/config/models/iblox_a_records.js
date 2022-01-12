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

// Infoblox a model
const ipAddrSchema = new Schema({
    name: String, // fqdn
    zone: String,
    infoblox_zone: String,
    ipv4addr: String,
    _ref: String,
    view: String, // External
}, {
    collection: 'iblox_a_records',
});

const ipAddrModel = mongoose.model('ipAddrModel', ipAddrSchema);

module.exports = {
    IPAddrModel: ipAddrModel,
    getIBAddrByZonePromise: function (zone) {
        return ipAddrModel.find({
            'zone': zone,
        }).exec();
    },
    getIBAddrByIBloxZonePromise: function (zone) {
        return ipAddrModel.find({
            'infoblox_zone': zone,
        }).exec();
    },
    getIBAddrByNamePromise: function (name) {
        return ipAddrModel.find({
            'name': name,
        }).exec();
    },
    getIBAddrByIPPromise: function (ip) {
        return ipAddrModel.find({
            'ipv4addr': ip,
        }).exec();
    },
    getIBAddrByIPRangePromise: function (ipRange) {
        let reZone = new RegExp('^' + ipRange + '\\..*');
        return ipAddrModel.find({
            'ipv4addr': { '$regex': reZone },
        }).exec();
    },
    getIBAddrCountPromise: function (zone) {
        let query = {};
        if (zone) {
            query = { 'zone': zone };
        }
        return ipAddrModel.countDocuments(query).exec();
    },
};
