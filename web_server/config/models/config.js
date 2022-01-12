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

const configSchema = new Schema({
    updated: Date,
    DNS_Admins: [String],
    SSL_Orgs: [String],
    Whois_Orgs: [String],
}, {
    collection: 'config',
});

const configModel = mongoose.model('configModel', configSchema);

module.exports = {
    configModel: configModel,
    getDNSAdminsPromise: function () {
        return configModel.find({}, { 'DNS_Admins': 1, '_id': 0 }).exec();
    },
    getSSLOrgsPromise: function () {
        return configModel.find({}, { 'SSL_Orgs': 1, '_id': 0 }).exec();
    },
    getWhoisOrgsPromise: function () {
        return configModel.find({}, { 'Whois_Orgs': 1, '_id': 0 }).exec();
    },
    getFullConfigPromise: function () {
        return configModel.find({}).exec();
    },
};
