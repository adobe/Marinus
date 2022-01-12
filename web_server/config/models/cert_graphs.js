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

// certificate graph model
const certGraphSchema = new Schema({
    zone: String,
    directed: Boolean,
    created: Date,
    nodes: [],
    links: [],
}, {
    collection: 'cert_graphs',
});

const certGraphModel = mongoose.model('certGraphModel', certGraphSchema);

module.exports = {
    CertGraphModel: certGraphModel,
    getGraphDataByZone: function (zone) {
        return certGraphModel.findOne({ 'zone': zone }).exec();
    },
};
