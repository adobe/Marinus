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


const extattrSchema = new Schema({
    zone: String,
    infoblox_zone: String,
    updated: Date,
    created: Date,
    _ref: String,
    record_type: String,
    extattrs: {},
    value: String
}, {
    collection: 'iblox_extattr_records',
});

const extattrModel = mongoose.model('extattrModel', extattrSchema);

module.exports = {
    extattrModel: extattrModel,
    /**
     * Returns the owner information for the host or cname value queried.
     * @param value: Host or Cname value to be queried
     * @returns {promise} Promise object
     */
    getIBHostExtattr: function (value) {
        return extattrModel.find({
            $and: [
                { $or: [{ 'record_type': 'cname' }, { 'record_type': 'host' }] },
                { 'value': value }]
        }, { 'extattrs': 1 }).exec();
    },
    /**
     * Returns the owner information for the zone value queried.
     * @param value: Zone value to be queried
     * @returns {promise} Promise object
     */
    getIBZoneExtattr: function (value) {
        return extattrModel.find({
            'record_type': 'zone',
            'value': value,
        }, { 'extattrs': 1 }).exec();
    },
    /**
     * Returns the owner information for the cname value queried.
     * @param value: Zone value to be queried
     * @returns {promise} Promise object
     */
    getIBCnameExtattr: function (value) {
        return extattrModel.find({
            'record_type': 'cname',
            'value': value,
        }, { 'extattrs': 1 }).exec();
    },
    /**
     * Returns the owner information for the IP value queried.
     * @param value: IP value to be queried
     * @returns {promise} Promise object
     */
    getIBIpExtattr: function (value) {
        return extattrModel.aggregate([
            {
                $match: {
                    'record_type': 'a',
                    'value': value
                }
            },
            {
                $project: {
                    'extattrs': 1,
                    'ref': '$_ref'
                }
            }]).exec();
    },
    getIBIpv6Extattr: function (value) {
        return extattrModel.aggregate([
            {
                $match: {
                    'record_type': 'aaaa',
                    'value': value
                }
            },
            {
                $project: {
                    'extattrs': 1,
                    'ref': '$_ref'
                }
            }]).exec();
    },
};
