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

// IPv6 model
const ipv6ZoneSchema = new Schema({
    status: String,
    zone: String,
    updated: Date,
    source: String,
    created: Date,
    notes: [],
}, {
    collection: 'ipv6_zones',
});

const ipv6ZoneModel = mongoose.model('ipv6ZoneModel', ipv6ZoneSchema);

module.exports = {
    Ipv6ZoneModel: ipv6ZoneModel,
    getZoneByNamePromise: function (name) {
        return ipv6ZoneModel.findOne({
            'zone': name,
        }).exec();
    },
    getZoneByIdPromise: function (id) {
        return ipv6ZoneModel.findById(id).exec();
    },
    getZoneCount: function (source, status) {
        let query = {};
        if (!(source === undefined || source.length === 0)) {
            query['source'] = source;
        }
        if (!(status === undefined || status.length === 0)) {
            query['status'] = status;
        } else {
            query['status'] = { '$ne': 'false_positive' };
        }
        return ipv6ZoneModel.countDocuments(query).exec();
    },
    getUniqueSources: function () {
        return ipv6ZoneModel.find().distinct('source').exec();
    },
    getAllZones: function (includeFalsePositives) {
        let query = { 'status': { '$ne': 'false_positive' } };
        if (includeFalsePositives === true) {
            query = {};
        }
        return ipv6ZoneModel.find(query).sort({ 'zone': 1 }).exec();
    },
};
