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

const z80Schema = require('./zgrab_80_data_schema.js');

// zgrab port 80 Module
module.exports = {
    zgrabModel: z80Schema.zgrab80Model,
    getRecordByDomainPromise: function (domain, count) {
        if (count) {
            return z80Schema.zgrab80Model.find({ 'domain': domain }).countDocuments().exec();
        } else {
            return z80Schema.zgrab80Model.find({ 'domain': domain }).exec();
        }
    },
    getRecordByIPPromise: function (ip, count) {
        if (count) {
            return z80Schema.zgrab80Model.find({ 'ip': ip }).countDocuments().exec();
        }
        return z80Schema.zgrab80Model.find({ 'ip': ip }).exec();
    },
    getRecordsByZonePromise: function (zone, count) {
        let promise;
        if (count) {
            promise = z80Schema.zgrab80Model.countDocuments({ 'zones': zone }).exec();
        } else {
            promise = z80Schema.zgrab80Model.find({ 'zones': zone }).exec();
        }
        return (promise);
    },
    getDomainListPromise: function (count, limit, page) {
        let promise;
        if (count) {
            promise = z80Schema.zgrab80Model.countDocuments({ "domain": { "$ne": "<nil>" } }).exec();
        } else if (limit > 0 && page > 0) {
            promise = z80Schema.zgrab80Model.find({ "domain": { "$ne": "<nil>" } }, { "_id": 0, "domain": 1, "zones": 1 }).skip(limit * (page - 1)).limit(limit).exec();
        } else {
            promise = z80Schema.zgrab80Model.find({ "domain": { "$ne": "<nil>" } }, { "_id": 0, "domain": 1, "zones": 1 }).exec();
        }
        return (promise);
    },
    getIPListPromise: function (count, limit, page) {
        let promise;
        if (count) {
            promise = z80Schema.zgrab80Model.countDocuments({ "ip": { "$ne": "<nil>" } }).exec();
        } else if (limit > 0 && page > 0) {
            promise = z80Schema.zgrab80Model.find({ "ip": { "$ne": "<nil>" } }, { "_id": 0, "ip": 1 }).skip(limit * (page - 1)).limit(limit).exec();
        } else {
            promise = z80Schema.zgrab80Model.find({ "ip": { "$ne": "<nil>" } }, { "_id": 0, "ip": 1 }).exec();
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
            promise = z80Schema.zgrab80Model.find(query).exists(headerQuery).countDocuments().exec();
        } else {
            promise = z80Schema.zgrab80Model.find(query).exists(headerQuery).select(headerQuery + ' zones ip domain').exec();
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
            promise = z80Schema.zgrab80Model.countDocuments(query).exec();
        } else {
            promise = z80Schema.zgrab80Model.find(query).select('data.http.response.headers.unknown.$.key data.http.response.headers.unknown.$.value ' + ' zones ip domain').exec();
        }
        return (promise);
    },
    getHttpHeaderByValuePromise: function (header, value, zone) {
        let headerQuery = 'data.http.response.headers.' + header;
        let query = { [headerQuery]: value };
        if (zone != null && zone !== '') {
            query['zones'] = zone;
        }
        return z80Schema.zgrab80Model.find(query).select(headerQuery + ' zones ip domain').exec();
    },
    getUnknownHttpHeaderByValuePromise: function (header, value, zone) {
        let query = { 'data.http.response.headers.unknown.value': value };
        if (zone != null && zone !== '') {
            query['zones'] = zone;
        }
        return z80Schema.zgrab80Model.find(query).select('data.http.response.headers.$.key ' + ' zones ip domain').exec();
    },
    getDistinctHttpHeaderPromise: function (header, zone) {
        let headerQuery = 'data.http.response.headers.' + header;
        let query;
        if (zone == null || zone === '') {
            query = { '$match': { [headerQuery]: { '$exists': true } } };
        } else {
            query = { '$match': { [headerQuery]: { '$exists': true }, 'zones': zone } };
        }
        return z80Schema.zgrab80Model.aggregate([query, { '$group': { '_id': '$' + headerQuery, 'count': { '$sum': 1 } } }]).sort({ 'count': 'descending' }).exec();
    },
    getDistinctUnknownHttpHeaderPromise: function (header, zone) {
        let query = {}
        if (zone == null || zone === '') {
            query = { 'data.http.response.headers.unknown.key': header };
        } else {
            query = { 'data.http.response.headers.unknown.key': header, 'zones': zone };
        }
        return z80Schema.zgrab80Model.aggregate([{ "$match": query },
        {
            "$project": {
                "headers": {
                    "$filter": {
                        "input": '$data.http.response.headers.unknown',
                        "as": "header",
                        "cond": { "$eq": ["$$header.key", header] }
                    }
                }
            }
        },
        { '$group': { "_id": "$headers.value", "count": { "$sum": 1 } } }, { "$project": { "_id": { "$arrayElemAt": ["$_id", 0] }, "count": "$count" } }])
    },
    getFullCountPromise: function () {
        return z80Schema.zgrab80Model.countDocuments({}).exec();
    }
}
