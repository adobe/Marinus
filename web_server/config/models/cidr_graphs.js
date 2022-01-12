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

// CIDR graph model
const cidrGraphSchema = new Schema({
    zone: String,
    directed: Boolean,
    multigraph: Boolean,
    created: Date,
    errs: [],
    data: {},
    links: [],
    config: {},
}, {
    collection: 'cidr_graphs',
});

const cidrGraphModel = mongoose.model('cidr_graphModel', cidrGraphSchema);

module.exports = {
    CIDR_graphModel: cidrGraphModel,
    getCIDRGraphDataByZone: function (zone) {
        let limitQuery = { 'data': 1, 'errs': 1 };
        return cidrGraphModel.findOne({
            'zone': zone,
        }, limitQuery).exec();
    },
    getCIDRGraphConfigByZone: function (zone) {
        let limitQuery = { 'config': 1 };
        return cidrGraphModel.findOne({
            'zone': zone,
        }, limitQuery).exec();
    },
    getCIDRGraphLinksByZone: function (zone) {
        let limitQuery = { 'links': 1 };
        return cidrGraphModel.findOne({
            'zone': zone,
        }, limitQuery).exec();
    },
};
