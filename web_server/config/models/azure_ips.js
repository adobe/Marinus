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

import mongoose from 'mongoose';
import { Schema } from 'mongoose';

const azureIpSchema = new Schema({
    createDate: Date,
    prefixes: [{
        region: String,
        ip_prefix: String,
    }],
}, {
    collection: 'azure_ips',
});

const azureIpModel = mongoose.model('azureIpModel', azureIpSchema);

export const azure_ips = {
    AzureIpModel: azureIpModel,
    getAzureIpZonesPromise: function () {
        return azureIpModel.find({}, { 'prefixes': 1, '_id': 0 }).exec();
    },
};
