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

// zone model
const zoneSchema = new Schema({
    zone: String,
    reporting_sources: [{ source: String, updated: Date, created: Date, status: String }],
    sub_zones: [{ sub_zone: String, updated: Date, created: Date, status: String, source: String }],
    updated: Date,
    created: Date,
    status: String,
    notes: [],
}, {
    collection: 'zones',
});

const zoneModel = mongoose.model('zoneModel', zoneSchema);

module.exports = {
    ZoneModel: zoneModel,
    getZoneByNamePromise: function (name) {
        return zoneModel.findOne({
            'zone': name,
        }).exec();
    },
    getZoneByIBloxNamePromise: function (name) {
        return zoneModel.findOne({
            'infoblox_zone': name,
        }).exec();
    },
    getZoneByIdPromise: function (id) {
        return zoneModel.findById(id).exec();
    },
    getZoneCount: function (source, status) {
        let query = {};
        if (!(source === undefined || source.length === 0)) {
            query['reporting_sources.source'] = source;
        }
        if (!(status === undefined || status.length === 0)) {
            query['status'] = status;
        } else {
            query['status'] = { '$nin': ['false_positive', 'expired'] };
        }
        return zoneModel.countDocuments(query).exec();
    },
    getUniqueSources: function () {
        return zoneModel.distinct('reporting_sources.source').exec();
    },
    getAllZones: function (pattern, includeFps) {
        let promise;
        let query = {};
        let regex;
        if (pattern != null) {
            regex = new RegExp('.*' + pattern + '.*');
            query['zone'] = regex;
        }
        if (includeFps === true) {
            promise = zoneModel.find(query).sort({ 'zone': 1 }).exec();
        } else {
            query['status'] = { '$nin': ['false_positive', 'expired'] };
            promise = zoneModel.find(query).sort({ 'zone': 1 }).exec();
        }
        return promise;
    },
};
