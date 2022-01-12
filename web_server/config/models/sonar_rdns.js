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

/**
 * This model represents the relevant records from the Sonar RDNS service.
 */
const rdnsSchema = new Schema({
    status: String,
    fqdn: String,
    ip: String,
    zone: String,
    sonar_timestamp: Number,
    created: Date,
    updated: Date,
}, {
    collection: 'sonar_rdns',
});

const rdnsModel = mongoose.model('rdnsModel', rdnsSchema);

module.exports = {
    RdnsModel: rdnsModel,
    getSRDNSByZonePromise: function (zone) {
        return rdnsModel.find({
            'zone': zone,
        }).exec();
    },
    getSRDNSByIPPromise: function (ip) {
        return rdnsModel.find({
            'ip': ip,
        }).exec();
    },
    getSRDNSByIPRangePromise: function (ipRange) {
        let reZone = new RegExp('^' + ipRange + '\\..*');
        return rdnsModel.find({
            'ip': { '$regex': reZone },
        }).exec();
    },
    getSRDNSByDomainPromise: function (domain) {
        return rdnsModel.find({
            'fqdn': domain,
        }).exec();
    },
    getSRDNSCount: function (zone) {
        let query = {};
        if (zone) {
            query = { 'zone': zone };
        }
        return rdnsModel.find(query).countDocuments().exec();
    },
};
