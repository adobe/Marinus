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
 * This model represents all of the DNS records.
 */
const allDnsSchema = new Schema({
    status: String,
    sources: [{ source: String, updated: Date }],
    sonar_timestamp: Number,
    fqdn: String,
    zone: String,
    created: Date,
    value: String,
    accountInfo: [{ key: String, value: String }],
    type: String, // Record type: "a", "cname", etc.
}, {
    collection: 'all_dns',
});

const allDnsModel = mongoose.model('allDnsModel', allDnsSchema);

module.exports = {
    AllDnsModel: allDnsModel,
    getAllDNSByZonePromise: function (zone, source, created_date, limit, page) {
        /**
         * Fetch all DNS records for the provided zone.
         * (Optional) Limit to the provided source.
         */
        let query = { 'zone': zone };
        if (source != null) {
            query['sources.source'] = source;
        }
        if (created_date != null) {
            query['created'] = { "$gt": new Date(created_date) };
        }
        if (limit !== undefined && limit > 0) {
            return allDnsModel.find(query).skip(limit * (page - 1)).limit(limit).exec();
        } else {
            return allDnsModel.find(query).exec();
        }
    },
    getAllDNSByDomainPromise: function (domain, source) {
        /**
         * Fetch all DNS records associated to the provided FQDN.
         * (Optional) Limit to the provided source.
         */
        let query = { 'fqdn': domain };
        if (source != null) {
            query['sources.source'] = source;
        }
        return allDnsModel.find(query).exec();
    },
    getAllDNSByIPPromise: function (ip, source) {
        /**
         * Fetch all IP records associated with the provided IP.
         * (Optional) Limit to the provided source.
         */
        let query = {
            'type': 'a',
            'value': ip,
        };
        if (source != null) {
            query['sources.source'] = source;
        }
        return allDnsModel.find(query).exec();
    },
    getAllDNSByIPv6Promise: function (ip, source) {
        /**
         * Fetch all IPv6 records for the provided IPv6
         * (Optional) Limit to the provided source.
         */
        let query = {
            'type': 'aaaa',
            'value': ip,
        };
        if (source != null) {
            query['sources.source'] = source;
        }
        return allDnsModel.find(query).exec();
    },
    getAllDNSByIPRangePromise: function (ipRange, source) {
        /**
         * Fetch all IP records that begin with the ipRange
         * This is a regex match and not a true CIDR match.
         * (Optional) Limit to the provided source.
         */
        let reZone = new RegExp('^' + ipRange + '\\..*');
        let query = {
            'type': 'a',
            'value': { '$regex': reZone },
        };
        if (source != null) {
            query['sources.source'] = source;
        }
        return allDnsModel.find(query).exec();
    },
    getAllDNSByIPv6RangePromise: function (ipRange, source) {
        /**
         * Fetech all IPv6 records that begin with the specified IP range
         * This is a regex match and not a true CIDR match.
         * (Optional) Limit to a specific source
         */
        let reZone = new RegExp('^' + ipRange + '\\:.*');
        let query = {
            'type': 'aaaa',
            'value': { '$regex': reZone },
        };
        if (source != null) {
            query['sources.source'] = source;
        }
        return allDnsModel.find(query).exec();
    },
    getAllDNSByTxtSearchPromise: function (txtRegex, zone, source, count) {
        /**
         * Fetch all TXT records that match the regex "".*{txtRegex}.*"
         * (Optional) Limit by zone and/or source
         * If count is true, return the count of the matched records.
         */
        let reZone = new RegExp('.*' + txtRegex + '.*', 'i');
        let query = {
            'type': 'txt',
            'value': { '$regex': reZone }
        };
        if (zone != null) {
            query['zone'] = zone;
        }
        if (source != null) {
            query['sources.source'] = source;
        }
        let promise;
        if (count) {
            promise = allDnsModel.countDocuments(query).exec();
        } else {
            promise = allDnsModel.find(query).exec();
        }
        return promise;
    },
    getAllDNSTypeByZoneCountPromise: function (type, source) {
        /**
         * Fetch the sum of records for the given type (grouped by zone).
         * (Optional) Limit the query to those from the given source.
         * e.g. Example.org has 12 A records, Example.net has 5 A records, etc.
         */
        let query = { 'type': type };
        if (source != null) {
            query['sources.source'] = source;
        }
        return allDnsModel.aggregate([{ '$match': query },
        {
            $group: {
                '_id': '$zone',
                'count': { $sum: 1 }
            },
        }]).sort({ '_id': 1 }).exec();

    },
    getAllDNSTxtByZoneCountPromise: function (stringType, source) {
        /**
         * Fetch all TXT records that match ".*v={stringType}.*"
         * (Optional) Limit by source.
         */
        let reSPF = new RegExp('.*v=' + stringType + '.*', 'i');

        let query = { 'type': 'txt', 'value': { '$regex': reSPF } };

        if (source != null) {
            query['sources.source'] = source;
        }

        return allDnsModel.aggregate([{ '$match': query },
        {
            $group: {
                '_id': '$zone',
                'count': { $sum: 1 }
            },
        }]).sort({ '_id': 1 }).exec();

    },
    getAllDNSByTypePromise: function (type, zone, source, count) {
        /**
         * Fetch all records for the given type.
         * (Optional) Limit the search with zone and/or source.
         * Return either the records or the count of the records.
         */
        let search = { 'type': type };
        if (zone) {
            search['zone'] = zone;
        }
        if (source != null) {
            query['sources.source'] = source;
        }
        let promise;
        if (count) {
            promise = allDnsModel.countDocuments(search).exec();
        } else {
            promise = allDnsModel.find(search).exec();
        }
        return promise;
    },
    getAllDNSAmazonEntriesPromise: function (subdomain, source) {
        /**
         * Fetch all CNAME records that match the regex "^.*+{subdomain}+\.amazonaws\.com"
         * (Optional) Limit to the provided source.
         */
        if (subdomain === undefined || subdomain === null || subdomain === 'all') {
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
        return allDnsModel.find(query).exec();
    },
    getAllDNSCount: function (zone, source) {
        /**
         * Return the count of AllDNS records.
         * (Optional) Limit by zone and/or source.
         */
        let query = {};
        if (zone) {
            query['zone'] = zone;
        }
        if (source != null) {
            query['sources.source'] = source;
        }
        return allDnsModel.countDocuments(query).exec();
    },
    getAllDNSByCNameSearch: function (cname, zone, source) {
        /**
         * Fetch all records which resolve to the provided CName value
         */
        let promise;
        let query;
        if (zone) {
            query = {
                'type': 'cname',
                'value': cname,
                'zone': zone,
            };
            if (source != null) {
                query['sources.source'] = source;
            }
            promise = allDnsModel.find(query).exec();
        } else {
            query = {
                'type': 'cname',
                'value': cname,
            };
            if (source != null) {
                query['sources.source'] = source;
            }
            promise = allDnsModel.find(query).exec();
        }
        return promise;
    },
    getAllDNSByCanonicalSearch: function (search, zone, source) {
        /**
         * Fetch all CNAME records that end in the provided search string.
         * (Optional) Limit the request by zone and/or source.
         */
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
            promise = allDnsModel.find(query).exec();
        } else {
            query = {
                'type': 'cname',
                'value': { '$regex': reSearch },
            };
            if (source != null) {
                query['sources.source'] = source;
            }
            promise = allDnsModel.find(query).exec();
        }
        return promise;
    },
    getAllDNSByCreatedPromise: function (created, limit, page) {
        /**
         * Fetch all DNS records for the provided zone.
         * (Optional) Limit to the provided source.
         */
        let query = { 'created': { "$gt": new Date(created) } };

        if (limit !== undefined && limit > 0) {
            return allDnsModel.find(query).skip(limit * (page - 1)).limit(limit).exec();
        } else {
            return allDnsModel.find(query).exec();
        }
    },
    getRegexDNSWithCreatedPromise: function (domain_ending, created, limit, page) {
        /**
         * Fetch all DNS records for the provided zone.
         * (Optional) Limit to the provided source.
         */
        let query = {};

        let reDomain = new RegExp('.*\.' + domain_ending + '$');

        query['fqdn'] = { "$regex": reDomain };

        if (created !== undefined) {
            query['created'] = { "$gt": new Date(created) };
        }

        if (limit !== undefined && limit > 0) {
            return allDnsModel.find(query).skip(limit * (page - 1)).limit(limit).exec();
        } else {
            return allDnsModel.find(query).exec();
        }
    },
    getDistinctDNSSources: function () {
        /**
         * Returns the list of distinct DNS record sources.
         */
        return allDnsModel.distinct('sources.source').exec()
    },
    getByAccountInfo: function (accountInfoValue) {
        /**
         * Returns DNS names matching an accountInfoValue
         */
        return allDnsModel.find({ 'accountInfo.value': accountInfoValue }).exec()
    }
};
