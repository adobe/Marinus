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

const awsIpSchema = new Schema({
    syncToken: String,
    createDate: String,
    prefixes: [{
        region: String,
        ip_prefix: String,
        service: String,
    }],
    ipv6_prefixes: [{
        region: String,
        ipv6_prefix: String,
        service: String,
    }],
}, {
    collection: 'aws_ips',
});

const awsIpModel = mongoose.model('awsIpModel', awsIpSchema);

module.exports = {
    AwsIpModel: awsIpModel,
    getAwsIpZonesPromise: function () {
        return awsIpModel.find({}, { 'prefixes': 1, '_id': 0 }).exec();
    },
    getAwsIpv6ZonesPromise: function () {
        return awsIpModel.find({}, { 'ipv6_prefixes': 1, '_id': 0 }).exec();
    },
};
