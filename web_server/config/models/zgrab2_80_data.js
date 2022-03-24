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

const z2_80_schema = require('./zgrab2_80_data_schema.js');

// ZGrab 2.0 port 80 module
module.exports = {
    zgrab2Model: z2_80_schema.zgrab2_80_model,
    getRecordByDomainPromise: function (domain, count) {
        if (count) {
            return z2_80_schema.zgrab2_80_model.find({ 'domain': domain }).countDocuments().exec();
        } else {
            return z2_80_schema.zgrab2_80_model.find({ 'domain': domain }).exec();
        }
    },
    getRecordByIPPromise: function (ip, count) {
        if (count) {
            return z2_80_schema.zgrab2_80_model.find({ 'ip': ip }).countDocuments().exec();
        }
        return z2_80_schema.zgrab2_80_model.find({ 'ip': ip }).exec();
    },
    getRecordsByZonePromise: function (zone, count) {
        let promise;
        if (count) {
            promise = z2_80_schema.zgrab2_80_model.countDocuments({ 'zones': zone }).exec();
        } else {
            promise = z2_80_schema.zgrab2_80_model.find({ 'zones': zone }).exec();
        }
        return (promise);
    },
    getDistinctZonesPromise: function () {
        return z2_80_schema.zgrab2_80_model.aggregate([
            { "$unwind": "$zones" },
            {
                "$group": {
                    "_id": "$zones",
                    "count": { "$sum": 1 }
                }
            },
            {
                "$project": {
                    "_id": 0,
                    "zone": "$_id",
                    "count": "$count"
                }
            }
        ]).exec()
    },
    getDomainListPromise: function (count, limit, page) {
        let promise;
        if (count) {
            promise = z2_80_schema.zgrab2_80_model.countDocuments({ "domain": { "$ne": "<nil>" } }).exec();
        } else if (limit > 0 && page > 0) {
            promise = z2_80_schema.zgrab2_80_model.find({ "domain": { "$ne": "<nil>" } }, { "_id": 0, "domain": 1, "zones": 1 }).skip(limit * (page - 1)).limit(limit).exec();
        } else {
            promise = z2_80_schema.zgrab2_80_model.find({ "domain": { "$ne": "<nil>" } }, { "_id": 0, "domain": 1, "zones": 1 }).exec();
        }
        return (promise);
    },
    getIPListPromise: function (count, limit, page) {
        let promise;
        if (count) {
            promise = z2_80_schema.zgrab2_80_model.countDocuments({ "ip": { "$ne": "<nil>" } }).exec();
        } else if (limit > 0 && page > 0) {
            promise = z2_80_schema.zgrab2_80_model.find({ "ip": { "$ne": "<nil>" } }, { "_id": 0, "ip": 1 }).skip(limit * (page - 1)).limit(limit).exec();
        } else {
            promise = z2_80_schema.zgrab2_80_model.find({ "ip": { "$ne": "<nil>" } }, { "_id": 0, "ip": 1 }).exec();
        }
        return (promise);
    },
    getHttpHeaderPromise: function (header, zone, count) {
        let headerQuery = 'data.http.response.headers.' + header;
        let query = {};
        if (zone != null && zone !== '') {
            query = { 'zones': zone };
        }
        let promise;
        if (count === true) {
            promise = z2_80_schema.zgrab2_80_model.find(query).exists(headerQuery).countDocuments().exec();
        } else {
            promise = z2_80_schema.zgrab2_80_model.find(query).exists(headerQuery).select(headerQuery + ' zones ip domain').exec();
        }
        return (promise);
    },
    getUnknownHttpHeaderPromise: function (header, zone, count) {
        let query = { 'data.http.response.headers.unknown.key': header };
        if (zone != null && zone !== '') {
            query['zones'] = zone;
        }
        let promise;
        if (count === true) {
            promise = z2_80_schema.zgrab2_80_model.countDocuments(query).exec();
        } else {
            promise = z2_80_schema.zgrab2_80_model.find(query).select('data.http.result.response.headers.unknown.$.key data.http.result.response.headers.unknown.$.value ' + ' zones ip domain').exec();
        }
        return (promise);
    },
    getHttpHeaderByValuePromise: function (header, value, zone) {
        let headerQuery = 'data.http.result.response.headers.' + header;
        let query = { [headerQuery]: value };
        if (zone != null && zone !== '') {
            query['zones'] = zone;
        }
        return z2_80_schema.zgrab2_80_model.find(query).select(headerQuery + ' zones ip domain').exec();
    },
    getUnknownHttpHeaderByValuePromise: function (header, value, zone) {
        let query = { 'data.http.result.response.headers.unknown.value': value };
        if (zone != null && zone !== '') {
            query['zones'] = zone;
        }
        return z2_80_schema.zgrab2_80_model.find(query).select('data.http.result.response.headers.$.key ' + ' zones ip domain').exec();
    },
    getDistinctHttpHeaderPromise: function (header, zone) {
        let headerQuery = 'data.http.result.response.headers.' + header;
        let query;
        if (zone == null || zone === '') {
            query = { '$match': { [headerQuery]: { '$exists': true } } };
        } else {
            query = { '$match': { [headerQuery]: { '$exists': true }, 'zones': zone } };
        }
        return z2_80_schema.zgrab2_80_model.aggregate([query, { '$group': { '_id': '$' + headerQuery, 'count': { '$sum': 1 } } }]).sort({ 'count': 'descending' }).exec();
    },
    getDistinctUnknownHttpHeaderPromise: function (header, zone) {
        let query = {}
        if (zone == null || zone === '') {
            query = { 'data.http.result.response.headers.unknown.key': header };
        } else {
            query = { 'data.http.result.response.headers.unknown.key': header, 'zones': zone };
        }
        return z2_80_schema.zgrab2_80_model.aggregate([{ "$match": query },
        {
            "$project": {
                "headers": {
                    "$filter": {
                        "input": '$data.http.result.response.headers.unknown',
                        "as": "header",
                        "cond": { "$eq": ["$$header.key", header] }
                    }
                }
            }
        },
        { '$group': { "_id": "$headers.value", "count": { "$sum": 1 } } }, { "$project": { "_id": { "$arrayElemAt": ["$_id", 0] }, "count": "$count" } }])
    },
    getFullCountPromise: function () {
        return z2_80_schema.zgrab2_80_model.countDocuments({}).exec();
    }
}
