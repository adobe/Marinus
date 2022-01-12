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

// graph model
const tpdGraphSchema = new Schema({
    zone: String,
    directed: Boolean,
    multigraph: Boolean,
    created: Date,
    errs: [],
    data: {},
    links: [],
    config: {},
}, {
    collection: 'tpd_graphs',
});

const tpdGraphModel = mongoose.model('tpd_graphModel', tpdGraphSchema);

module.exports = {
    TPD_graphModel: tpdGraphModel,
    getTPDGraphDataByTPD: function (tpd) {
        let limitQuery = { 'data': 1, 'errs': 1 };
        return tpdGraphModel.findOne({
            'zone': tpd,
        }, limitQuery).exec();
    },
    getTPDGraphConfigByTPD: function (tpd) {
        let limitQuery = { 'config': 1 };
        return tpdGraphModel.findOne({
            'zone': tpd,
        }, limitQuery).exec();
    },
    getTPDGraphLinksByTPD: function (tpd) {
        let limitQuery = { 'links': 1 };
        return tpdGraphModel.findOne({
            'zone': tpd,
        }, limitQuery).exec();
    },
};
