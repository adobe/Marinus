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

// Infoblox MX model
const mxSchema = new Schema({
    updated: Date,
    name: String,
    zone: String,
    created: Date,
    mail_exchanger: String,
    preference: Number,
    _ref: String,
    infoblox_zone: String,
    view: String
}, {
    collection: 'iblox_mx_records',
});

const mxModel = mongoose.model('mxModel', mxSchema);

module.exports = {
    mxModel: mxModel,
    getIBMXByZonePromise: function (zone) {
        return mxModel.find({
            'zone': zone,
        }).exec();
    },
    getIBMXByIBloxZonePromise: function (zone) {
        return mxModel.find({
            'infoblox_zone': zone,
        }).exec();
    },
    getIBMXByNamePromise: function (name) {
        return mxModel.find({
            'name': name,
        }).exec();
    },
    getIBMXByMailExchanger: function (mail_exchanger, zone) {
        let query = { 'mail_exchanger': mail_exchanger };
        if (zone) {
            query['zone'] = zone;
        }
        return mxModel.find(query);
    },
    getIBMXCountPromise: function (zone) {
        let query = {};
        if (zone) {
            query = { 'zone': zone };
        }
        return mxModel.countDocuments(query).exec();
    },
};
