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

const tpdSchema = new Schema({
    total: Number,
    tld: String,
    zones: [{
        zone: String,
        records: [{
            host: String,
            target: String,
        }],
    }],
}, {
    collection: 'tpds',
});

const tpdModel = mongoose.model('tpdModel', tpdSchema);

module.exports = {
    TPDModel: tpdModel,
    getTPDsByZone: function (zone, listOnly) {
        let promise;
        if (!listOnly) {
            promise = tpdModel.find({ 'zones.zone': zone }).exec();
        } else {
            promise = tpdModel.find({
                'zones.zone': zone,
            }, { 'tld': 1, 'zones.zone': 1 }).exec();
        }
        return (promise);
    },
    getTPDsByTPD: function (tpd) {
        return tpdModel.findOne({ 'tld': tpd });
    },
    getTPDsByWildcard: function (search, listOnly) {
        let promise;
        let AWSregex = new RegExp('.*' + search + '$');
        if (listOnly) {
            promise = tpdModel.find({
                'tld': { '$regex': AWSregex },
            }, { 'tld': 1, 'zones.zone': 1 }).exec();
        } else {
            promise = tpdModel.find({ 'tld': { '$regex': AWSregex } }).exec();
        }
        return (promise);
    },
    getAllTPDs: function () {
        return tpdModel.find({}).sort({ 'total': -1 }).exec();
    },
};
