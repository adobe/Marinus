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
 * This is a placeholder for an upcoming feature around saved queries.
 * It is not currently implemented.
 */
const querySchema = new Schema({
    owner: String,
    name: String,
    creation_date: Date,
    users: [String],
    groups: [String],
    service: [String],
    getParams: [String],
    postParams: [String],
}, {
    collection: 'queries',
});

const queryModel = mongoose.model('queryModel', querySchema);

module.exports = {
    QueryModel: queryModel,
};
