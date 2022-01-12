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

// Infoblox cname model
const cnameSchema = new Schema({
    name: String, // fqdn
    zone: String,
    infoblox_zone: String,
    canonical: String, // cname value
    _ref: String,
    view: String, // External
}, {
    collection: 'iblox_cname_records',
});

const cnameModel = mongoose.model('cnameModel', cnameSchema);

module.exports = {
    CnameModel: cnameModel,
    getIBCNameByZonePromise: function (zone) {
        return cnameModel.find({
            'zone': zone,
        }).exec();
    },
    getIBCNameByIBloxZonePromise: function (zone) {
        return cnameModel.find({
            'infoblox_zone': zone,
        }).exec();
    },
    getIBCNameByNamePromise: function (name) {
        return cnameModel.find().or([{
            'name': name,
        }, {
            'canonical': name,
        }]).exec();
    },
    getIBCNameCountPromise: function (zone) {
        let query = {};
        if (zone) {
            query = { 'zone': zone };
        }
        return cnameModel.countDocuments(query).exec();
    },
    getIBCNameByCanonicalSearch: function (search, zone) {
        let reSearch = new RegExp('.*' + search + '$');
        let promise;
        if (zone) {
            promise = cnameModel.find({
                'canonical': { '$regex': reSearch },
                'zone': zone,
            }).exec();
        } else {
            promise = cnameModel.find({
                'canonical': { '$regex': reSearch },
            }).exec();
        }
        return promise;
    },
};
