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
 * This model represents dead DNS records.
 */
const deadDnsSchema = new Schema({
    status: String,
    sources: [{ source: String, updated: Date }],
    sonar_timestamp: Number,
    fqdn: String,
    zone: String,
    created: Date,
    updated: Date, // For older records that haven't been converted
    value: String,
    type: String, // Record type: "a", "cname", etc.
}, {
    collection: 'dead_dns',
});

const deadDnsModel = mongoose.model('deadDnsModel', deadDnsSchema);

module.exports = {
    DeadDnsModel: deadDnsModel,
    getAllDeadDNSPromise: function () {
        return deadDnsModel.find({}).exec();
    },
    getDeadDNSByZonePromise: function (zone, source) {
        let query = { 'zone': zone };
        if (source != null) {
            query['sources.source'] = source;
        }
        return deadDnsModel.find(query).exec();
    },
    getDeadDNSByDomainPromise: function (domain, source) {
        let query = { 'fqdn': domain };
        if (source != null) {
            query['sources.source'] = source;
        }
        return deadDnsModel.find(query).exec();
    },
    getDeadDNSByIPPromise: function (ip, source) {
        let query = {
            'type': 'a',
            'value': ip,
        };
        if (source != null) {
            query['sources.source'] = source;
        }
        return deadDnsModel.find(query).exec();
    },
    getDeadDNSByIPRangePromise: function (ipRange, source) {
        let reZone = new RegExp('^' + ipRange + '\\..*');
        let query = {
            'type': 'a',
            'value': { '$regex': reZone },
        };
        if (source != null) {
            query['sources.source'] = source;
        }
        return deadDnsModel.find(query).exec();
    },
    getDeadDNSTypeByZoneCountPromise: function (type, source) {
        let query = { 'type': type };
        if (source != null) {
            query['sources.source'] = source;
        }
        return deadDnsModel.aggregate([{ '$match': query },
        {
            $group: {
                '_id': '$zone',
                'count': { $sum: 1 }
            },
        }]).sort({ '_id': 1 }).exec();
    },
    getDeadDNSByTypePromise: function (type, zone, source, count) {
        let search = { 'type': type };
        if (zone) {
            search['zone'] = zone;
        }
        if (source != null) {
            query['sources.source'] = source;
        }
        let promise;
        if (count) {
            promise = deadDnsModel.countDocuments(search).exec();
        } else {
            promise = deadDnsModel.find(search).exec();
        }
        return promise;
    },
    getDeadDNSAmazonEntriesPromise: function (subdomain, source) {
        if (subdomain === undefined
            || subdomain == null
            || subdomain === 'dead') {
            subdomain = '';
        }
        let reAmazon = new RegExp('^.*' + subdomain + '\.amazonaws\.com');

        let query = {
            'type': 'cname',
            'value': reAmazon,
        };

        if (source != null) {
            query['sources.source'] = source;
        }
        return deadDnsModel.find(query).exec();
    },
    getDeadDNSCount: function (zone, source) {
        let query = {};
        if (zone) {
            query['zone'] = zone;
        }
        if (source != null) {
            query['sources.source'] = source;
        }
        return deadDnsModel.countDocuments(query).exec();
    },
    getDeadDNSByCanonicalSearch: function (search, zone, source) {
        let reSearch = new RegExp('.*' + search + '$');
        let promise;
        let query;
        if (zone) {
            query = {
                'type': 'cname',
                'value': { '$regex': reSearch },
                'zone': zone,
            };
            if (source != null) {
                query['sources.source'] = source;
            }
            promise = deadDnsModel.find(query).exec();
        } else {
            query = {
                'type': 'cname',
                'value': { '$regex': reSearch },
            };
            if (source != null) {
                query['sources.source'] = source;
            }
            promise = deadDnsModel.find(query).exec();
        }
        return promise;
    },
};
