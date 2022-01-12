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

// Infoblox TXT model
const txtSchema = new Schema({
    updated: Date,
    name: String,
    zone: String,
    created: Date,
    text: String,
    _ref: String,
    infoblox_zone: String,
    view: String
}, {
    collection: 'iblox_txt_records',
});

const txtModel = mongoose.model('txtModel', txtSchema);

module.exports = {
    txtModel: txtModel,
    getIBTXTByZonePromise: function (zone) {
        return txtModel.find({
            'zone': zone,
        }).exec();
    },
    getIBTXTByIBloxZonePromise: function (zone) {
        return txtModel.find({
            'infoblox_zone': zone,
        }).exec();
    },
    getIBTXTByNamePromise: function (name) {
        return txtModel.find({
            'name': name,
        }).exec();
    },
    getIBTXTByRegex: function (regex) {
        let reTxt = new RegExp('.*' + regex + '.*');

        return txtModel.find({
            'text': { '$regex': reTxt },
        });
    },
    getIBTXTCountPromise: function (zone) {
        let query = {};
        if (zone) {
            query = { 'zone': zone };
        }
        return txtModel.countDocuments(query).exec();
    },
};
