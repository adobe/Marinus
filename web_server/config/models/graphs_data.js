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
const graphDataSchema = new Schema({
    zone: String,
    directed: Boolean,
    multigraph: Boolean,
    created: Date,
    data: {},
    errs: [],
}, {
    collection: 'graphs_data',
});

const graphDataModel = mongoose.model('graphDataModel', graphDataSchema);

module.exports = {
    GraphDataModel: graphDataModel,
    getGraphDataByZone: function (zone) {
        let limitQuery = { 'data': 1, 'errs': 1 };
        return graphDataModel.findOne({
            'zone': zone,
        }, limitQuery).exec();
    },
    getGraphCountByZone: function (zone) {
        return (graphDataModel.countDocuments({ 'zone': zone }).exec());
    },
};
