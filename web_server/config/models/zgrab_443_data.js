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

const zSchema = require('./zgrab_443_data_schema.js');
const zgrab_cert_path = 'data.http.response.request.tls_handshake.server_certificates.';

/**
 * The projections used in many of the aggregate queries are due to the fact that zgrab
 * records the final response as the primary response. In the event of redirects, this response
 * may not be closely related to the initial request (e.g. a redirect may send you to 3rd-party.)
 * In the context of these queries, it is likely that the caller only cares about the initial
 * target. Therefore, the $project is used to figure out which folder to use. Doing a $project on
 * every row is expensive and this will be simplified in a future version.
 *
 * The same philosophy is currently not followed for headers because the interesting headers are
 * set on 200 responses and not on the 30x.s
 */

// zgrab port 443 Module
module.exports = {
    zgrabModel: zSchema.zgrab443Model,
    getRecordByDomainPromise: function (domain) {
        return zSchema.zgrab443Model.find({ 'domain': domain }).exec();
    },
    getRecordByIPPromise: function (ip, count) {
        if (count) {
            return zSchema.zgrab443Model.find({ 'ip': ip }).countDocuments().exec();
        }
        return zSchema.zgrab443Model.find({ 'ip': ip }).exec();
    },
    getRecordsByZonePromise: function (zone, count, limit, page) {
        let promise;
        if (count) {
            promise = zSchema.zgrab443Model.countDocuments({ 'zones': zone }).exec();
        } else {
            if (limit > 0) {
                promise = zSchema.zgrab443Model.find({ 'zones': zone }).skip(limit * (page - 1)).limit(limit).exec();
            } else {
                promise = zSchema.zgrab443Model.find({ 'zones': zone }).exec();
            }
        }
        return (promise);
    },
    getDomainListPromise: function (count, limit, page) {
        let promise;
        if (count) {
            promise = zSchema.zgrab443Model.countDocuments({ "domain": { "$ne": "<nil>" } }).exec();
        } else if (limit > 0 && page > 0) {
            promise = zSchema.zgrab443Model.find({ "domain": { "$ne": "<nil>" } }, { "_id": 0, "domain": 1, "zones": 1 }).skip(limit * (page - 1)).limit(limit).exec();
        } else {
            promise = zSchema.zgrab443Model.find({ "domain": { "$ne": "<nil>" } }, { "_id": 0, "domain": 1, "zones": 1 }).exec();
        }
        return (promise);
    },
    getIPListPromise: function (count, limit, page,) {
        let promise;
        if (count) {
            promise = zSchema.zgrab443Model.countDocuments({ "ip": { "$ne": "<nil>" } }).exec();
        } else if (limit > 0 && page > 0) {
            promise = zSchema.zgrab443Model.find({ "ip": { "$ne": "<nil>" } }, { "_id": 0, "ip": 1, "aws": 1, "azure": 1, "tracked": 1 }).skip(limit * (page - 1)).limit(limit).exec();
        } else {
            promise = zSchema.zgrab443Model.find({ "ip": { "$ne": "<nil>" } }, { "_id": 0, "ip": 1, "aws": 1, "azure": 1, "tracked": 1 }).exec();
        }
        return (promise);
    },
    getRecordsBySSLOrgPromise: function (org, recursive, limit, page) {
        let promise;
        if (recursive === true) {
            if (limit > 0) {
                promise = zSchema.zgrab443Model.find({
                    [zgrab_cert_path + 'certificate.parsed.subject.organization']: org,
                }).skip(limit * (page - 1)).limit(limit).exec();
            } else {
                promise = zSchema.zgrab443Model.find({
                    [zgrab_cert_path + 'certificate.parsed.subject.organization']: org,
                }).exec();
            }
        } else {
            if (limit > 0) {
                promise = zSchema.zgrab443Model.aggregate([{
                    "$project":
                    {
                        'domain': 1,
                        'ip': 1,
                        'data.http':
                            { "$ifNull": ["$data.http.redirect_response_chain", ["$data.http.response"]] }
                    }
                },
                { "$match": { [zgrab_cert_path + 'certificate.parsed.subject.organization']: org } }]
                ).skip(limit * (page - 1)).limit(limit).exec();
            } else {
                promise = zSchema.zgrab443Model.aggregate([{
                    "$project":
                    {
                        'domain': 1,
                        'ip': 1,
                        'data.http':
                            { "$ifNull": ["$data.http.redirect_response_chain", ["$data.http.response"]] }
                    }
                },
                { "$match": { [zgrab_cert_path + 'certificate.parsed.subject.organization']: org } }]
                ).exec();
            }
        }
        return (promise);
    },
    getSSLByCommonNamePromise: function (commonName, recursive) {
        let promise;
        if (recursive === true) {
            promise = zSchema.zgrab443Model.find({
                '$or': [{ [zgrab_cert_path + 'certificate.parsed.subject.common_name']: commonName },
                { [zgrab_cert_path + 'certificate.parsed.extensions.subject_alt_name.dns_names']: commonName }],
            }, { 'domain': 1, 'ip': 1, 'data.http': 1 }).exec();
        } else {
            promise = zSchema.zgrab443Model.aggregate([{
                "$project":
                {
                    'domain': 1,
                    'ip': 1,
                    'data.http':
                        { "$ifNull": ["$data.http.redirect_response_chain", ["$data.http.response"]] }
                }
            },
            {
                "$match": {
                    '$or': [{ 'data.http.0.request.tls_handshake.server_certificates.certificate.parsed.subject.common_name': commonName },
                    { 'data.http.0.request.tls_handshake.server_certificates.certificate.parsed.extensions.subject_alt_name.dns_names': commonName }]
                }
            }
            ]
            ).exec();
        }
        return (promise);
    },
    getSSLByZonePromise: function (zone, count, recursive) {
        let escZone = zone.replace('.', '\\.');
        let reZone = new RegExp('^.*\.' + escZone + '$');
        let promise;
        if (recursive === true) {
            if (count) {
                promise = zSchema.zgrab443Model.countDocuments({
                    '$or': [{ [zgrab_cert_path + 'certificate.parsed.subject.common_name']: reZone },
                    { [zgrab_cert_path + 'certificate.parsed.extensions.subject_alt_name.dns_names']: reZone },
                    { [zgrab_cert_path + 'certificate.parsed.subject.common_name']: zone },
                    { [zgrab_cert_path + 'certificate.parsed.extensions.subject_alt_name.dns_names']: zone }],
                }).exec();
            } else {
                promise = zSchema.zgrab443Model.find({
                    '$or': [{ [zgrab_cert_path + 'certificate.parsed.subject.common_name']: reZone },
                    { [zgrab_cert_path + 'certificate.parsed.extensions.subject_alt_name.dns_names']: reZone },
                    { [zgrab_cert_path + 'certificate.parsed.subject.common_name']: zone },
                    { [zgrab_cert_path + 'certificate.parsed.extensions.subject_alt_name.dns_names']: zone },
                    ]
                }, { 'domain': 1, 'ip': 1, 'data.http': 1 }).exec();
            }
        } else {
            if (count) {
                promise = zSchema.zgrab443Model.aggregate([{
                    "$project":
                    {
                        'domain': 1,
                        'ip': 1,
                        'zones': 1,
                        'data.http':
                            { "$ifNull": ["$data.http.redirect_response_chain", ["$data.http.response"]] }
                    }
                },
                {
                    "$match": {
                        '$or': [{ 'zones': zone },
                        { 'data.http.0.request.tls_handshake.server_certificates.certificate.parsed.subject.common_name': reZone },
                        { 'data.http.0.request.tls_handshake.server_certificates.certificate.parsed.extensions.subject_alt_name.dns_names': reZone },
                        { 'data.http.0.request.tls_handshake.server_certificates.certificate.parsed.subject.common_name': zone },
                        { 'data.http.0.request.tls_handshake.server_certificates.certificate.parsed.extensions.subject_alt_name.dns_names': zone },
                        ]
                    }
                },
                { "$count": "count" }
                ]
                ).exec();
            } else {
                promise = zSchema.zgrab443Model.aggregate([{
                    "$project":
                    {
                        'domain': 1,
                        'ip': 1,
                        'zones': 1,
                        'data.http':
                            { "$ifNull": ["$data.http.redirect_response_chain", ["$data.http.response"]] }
                    }
                },
                {
                    "$match": {
                        '$or': [{ 'zones': zone },
                        { 'data.http.0.request.tls_handshake.server_certificates.certificate.parsed.subject.common_name': reZone },
                        { 'data.http.0.request.tls_handshake.server_certificates.certificate.parsed.extensions.subject_alt_name.dns_names': reZone },
                        { 'data.http.0.request.tls_handshake.server_certificates.certificate.parsed.subject.common_name': zone },
                        { 'data.http.0.request.tls_handshake.server_certificates.certificate.parsed.extensions.subject_alt_name.dns_names': zone },
                        ]
                    }
                }
                ]
                ).exec();
            }
        }
        return (promise);
    },
    getSSLByValidity2kPromise: function (recursive) {
        let isBefore2010 = new RegExp('^200.*');
        let promise;
        if (recursive === true) {
            promise = zSchema.zgrab443Model.find({
                [zgrab_cert_path + 'certificate.parsed.validity.end']: isBefore2010,
            }, { 'domain': 1, 'ip': 1, 'data.http': 1 }).exec();
        } else {
            promise = zSchema.zgrab443Model.aggregate([{
                "$project":
                {
                    'domain': 1,
                    'ip': 1,
                    'data.http':
                        { "$ifNull": ["$data.http.redirect_response_chain", ["$data.http.response"]] }
                }
            },
            { "$match": { 'data.http.0.request.tls_handshake.server_certificates.certificate.parsed.validity.end': isBefore2010 } }]
            ).exec();
        }
        return (promise);
    },
    getSSLByValidityYearPromise: function (year, recursive) {
        let thisDecade = new RegExp('^' + year + '.*');
        let promise;
        if (recursive === true) {
            promise = zSchema.zgrab443Model.find({
                [zgrab_cert_path + 'certificate.parsed.validity.end']: thisDecade,
            }, { 'domain': 1, 'ip': 1, 'data.http': 1 }).exec();
        } else {
            promise = zSchema.zgrab443Model.aggregate([{
                "$project":
                {
                    'domain': 1,
                    'ip': 1,
                    'data.http':
                        { "$ifNull": ["$data.http.redirect_response_chain", ["$data.http.response"]] }
                }
            },
            { "$match": { 'data.http.0.request.tls_handshake.server_certificates.certificate.parsed.validity.end': thisDecade } }]
            ).exec();
        }
        return (promise);
    },
    getSSLOrgCountPromise: function (org, recursive) {
        let promise;
        if (recursive === true) {
            promise = zSchema.zgrab443Model.countDocuments({
                [zgrab_cert_path + 'certificate.parsed.subject.organization']: org,
            }).exec();
        } else {
            promise = zSchema.zgrab443Model.aggregate([{
                "$project":
                {
                    'domain': 1,
                    'ip': 1,
                    'data.http':
                        { "$ifNull": ["$data.http.redirect_response_chain", ["$data.http.response"]] }
                }
            },
            { "$match": { 'data.http.0.request.tls_handshake.server_certificates.certificate.parsed.subject.organization': org } },
            { "$count": "count" }]
            ).exec();
        }
        return (promise);
    },
    getSSLAlgorithmPromise: function (algorithm, count, recursive, limit, page) {
        let promise;
        if (recursive === true) {
            if (count === true) {
                promise = zSchema.zgrab443Model.countDocuments({
                    [zgrab_cert_path + 'certificate.parsed.signature.signature_algorithm.name']: algorithm,
                }).exec();
            } else {
                promise = zSchema.zgrab443Model.find({
                    [zgrab_cert_path + 'certificate.parsed.signature.signature_algorithm.name']: algorithm,
                }, {
                    'ip': 1,
                    'domain': 1,
                    [zgrab_cert_path + 'certificate']: 1,
                    [zgrab_cert_path + 'validation']: 1
                }).skip(limit * (page - 1)).limit(limit).exec();
            }
        } else {
            if (count) {
                promise = zSchema.zgrab443Model.aggregate([{
                    "$project":
                    {
                        'domain': 1,
                        'ip': 1,
                        'data.http':
                            { "$ifNull": ["$data.http.redirect_response_chain", ["$data.http.response"]] }
                    }
                },
                { "$match": { 'data.http.0.request.tls_handshake.server_certificates.certificate.parsed.signature.signature_algorithm.name': algorithm } },
                { "$count": "count" }]
                ).exec();
            } else {
                promise = zSchema.zgrab443Model.aggregate([{
                    "$project":
                    {
                        'domain': 1,
                        'ip': 1,
                        'data.http':
                            { "$ifNull": ["$data.http.redirect_response_chain", ["$data.http.response"]] }
                    }
                },
                { "$match": { 'data.http.0.request.tls_handshake.server_certificates.certificate.parsed.signature.signature_algorithm.name': algorithm } },
                {
                    "$project":
                    {
                        'domain': 1,
                        'ip': 1,
                        'temp': { "$arrayElemAt": ['$data.http', 0] }
                    }
                },
                {
                    "$project":
                    {
                        'domain': 1,
                        'ip': 1,
                        'data.http.response.request.tls_handshake.server_certificates.certificate': "$temp.request.tls_handshake.server_certificates.certificate",
                        'data.http.response.request.tls_handshake.server_certificates.validation': "$temp.request.tls_handshake.server_certificates.validation"
                    }
                },
                ]).skip(limit * (page - 1)).limit(limit).exec();
            }
        }
        return (promise);
    },
    getSSLAlgorithmByZonePromise: function (algorithm, zone, count, recursive, limit, page) {
        let escZone = zone.replace('.', '\\.');
        let reZone = new RegExp('^.*\.' + escZone + '$');
        let promise;
        if (recursive === true) {
            if (count === true) {
                promise = zSchema.zgrab443Model.countDocuments({
                    [zgrab_cert_path + 'certificate.parsed.signature.signature_algorithm.name']: algorithm,
                    '$or': [{ [zgrab_cert_path + 'certificate.parsed.subject.common_name']: reZone },
                    { [zgrab_cert_path + 'certificate.parsed.extensions.subject_alt_name.dns_names']: reZone }]
                }).exec();
            } else {
                promise = zSchema.zgrab443Model.find({
                    [zgrab_cert_path + 'certificate.parsed.signature.signature_algorithm.name']: algorithm,
                    '$or': [{ [zgrab_cert_path + 'certificate.parsed.subject.common_name']: reZone },
                    { [zgrab_cert_path + 'certificate.parsed.extensions.subject_alt_name.dns_names']: reZone }]
                },
                    { 'domain': 1, 'ip': 1, [zgrab_cert_path + 'certificate']: 1 }).skip(limit * (page - 1)).limit(limit).exec();
            }
        } else {
            if (count === true) {
                promise = zSchema.zgrab443Model.aggregate([{
                    "$project":
                    {
                        'domain': 1,
                        'ip': 1,
                        'zones': 1,
                        'data.http':
                            { "$ifNull": ["$data.http.redirect_response_chain", ["$data.http.response"]] }
                    }
                },
                {
                    "$match": {
                        'data.http.0.request.tls_handshake.server_certificates.certificate.parsed.signature.signature_algorithm.name': algorithm,
                        "$or": [{ 'data.http.0.request.tls_handshake.server_certificates.certificate.parsed.subject.common_name': reZone },
                        { 'data.http.0.request.tls_handshake.server_certificates.certificate.parsed.extensions.subject_alt_name.dns_names': reZone },
                        { 'zones': zone }]
                    }
                },
                {
                    "$project":
                    {
                        'domain': 1,
                        'ip': 1,
                        'zones': 1,
                        'data.http.0.request.tls_handshake.server_certificates.certificate': 1,
                    }
                },
                { "$count": "count" }]
                ).exec();
            } else {
                promise = zSchema.zgrab443Model.aggregate([{
                    "$project":
                    {
                        'domain': 1,
                        'ip': 1,
                        'zones': 1,
                        'data.http':
                            { "$ifNull": ["$data.http.redirect_response_chain", ["$data.http.response"]] }
                    }
                },
                {
                    "$match": {
                        'data.http.0.request.tls_handshake.server_certificates.certificate.parsed.signature.signature_algorithm.name': algorithm,
                        "$or": [{ 'data.http.0.request.tls_handshake.server_certificates.certificate.parsed.subject.common_name': reZone },
                        { 'data.http.0.request.tls_handshake.server_certificates.certificate.parsed.extensions.subject_alt_name.dns_names': reZone },
                        { 'zones': zone }]
                    }
                },
                {
                    "$project":
                    {
                        'domain': 1,
                        'ip': 1,
                        'data.http.request.tls_handshake.server_certificates.certificate': 1,
                    }
                }]
                ).skip(limit * (page - 1)).limit(limit).exec();
            }

        }
        return (promise);
    },
    getFullCountPromise: function () {
        return zSchema.zgrab443Model.countDocuments({}).exec();
    },
    getRecordsBySSLFingerprintPromise: function (fingerprint, count, recursive) {
        let promise;
        if (recursive === true) {
            if (count) {
                promise = zSchema.zgrab443Model.countDocuments({
                    [zgrab_cert_path + 'certificate.parsed.fingerprint_sha1']: fingerprint,
                }).exec();
            } else {
                promise = zSchema.zgrab443Model.find({
                    [zgrab_cert_path + 'certificate.parsed.fingerprint_sha1']: fingerprint,
                }).exec();
            }
        } else {
            if (count) {
                promise = zSchema.zgrab443Model.aggregate([{
                    "$project":
                    {
                        'domain': 1,
                        'ip': 1,
                        'data.http':
                            { "$ifNull": ["$data.http.redirect_response_chain", ["$data.http.response"]] }
                    }
                },
                { "$match": { 'data.http.0.request.tls_handshake.server_certificates.certificate.parsed.fingerprint_sha1': fingerprint } },
                { "$count": "count" }]
                ).exec();
            } else {
                promise = zSchema.zgrab443Model.aggregate([{
                    "$project":
                    {
                        'domain': 1,
                        'ip': 1,
                        'data.http':
                            { "$ifNull": ["$data.http.redirect_response_chain", ["$data.http.response"]] }
                    }
                },
                { "$match": { 'data.http.0.request.tls_handshake.server_certificates.certificate.parsed.fingerprint_sha1': fingerprint } }]
                ).exec();
            }
        }
        return (promise);
    },
    getRecordsBySSL256FingerprintPromise: function (fingerprint, count, recursive) {
        let promise;
        if (recursive === true) {
            if (count) {
                promise = zSchema.zgrab443Model.countDocuments({
                    [zgrab_cert_path + 'certificate.parsed.fingerprint_sha256']: fingerprint,
                }).exec();
            } else {
                promise = zSchema.zgrab443Model.find({
                    [zgrab_cert_path + 'certificate.parsed.fingerprint_sha256']: fingerprint,
                }).exec();
            }
        } else {
            if (count) {
                promise = zSchema.zgrab443Model.aggregate([{
                    "$project":
                    {
                        'domain': 1,
                        'ip': 1,
                        'data.http':
                            { "$ifNull": ["$data.http.redirect_response_chain", ["$data.http.response"]] }
                    }
                },
                { "$match": { 'data.http.0.request.tls_handshake.server_certificates.certificate.parsed.fingerprint_sha256': fingerprint } },
                { "$count": "count" }]
                ).exec();
            } else {
                promise = zSchema.zgrab443Model.aggregate([{
                    "$project":
                    {
                        'domain': 1,
                        'ip': 1,
                        'data.http':
                            { "$ifNull": ["$data.http.redirect_response_chain", ["$data.http.response"]] }
                    }
                },
                { "$match": { 'data.http.0.request.tls_handshake.server_certificates.certificate.parsed.fingerprint_sha256': fingerprint } }]
                ).exec();
            }
        }
        return (promise);
    },
    getCAIssuersListPromise(recursive) {
        let promise;
        if (recursive === true) {
            promise = zSchema.zgrab443Model.aggregate([
                {
                    "$project":
                        { 'chain': { "$arrayElemAt": ['$data.http.response.request.tls_handshake.server_certificates.chain', 0] } }
                },
                {
                    "$project":
                        { 'common_name': { "$arrayElemAt": ['$chain.parsed.issuer.common_name', 0] } }
                },
                { "$group": { "_id": { 'ca': '$common_name' }, "result": { '$push': '$common_name' } } },
                { "$unwind": "$result" },
                { "$group": { "_id": "$_id.ca", "count": { "$sum": 1 } } }
            ]).exec();
        } else {
            promise = zSchema.zgrab443Model.aggregate([{
                "$project":
                    { 'data.http': { "$ifNull": ["$data.http.redirect_response_chain", ["$data.http.response"]] } }
            },
            {
                "$project":
                    { 'response': { "$arrayElemAt": ['$data.http', 0] } }
            },
            {
                "$project":
                    { 'chain': { "$arrayElemAt": ['$response.request.tls_handshake.server_certificates.chain', 0] } }
            },
            {
                "$project":
                    { 'common_name': { "$arrayElemAt": ['$chain.parsed.issuer.common_name', 0] } }
            },
            { "$group": { "_id": { 'ca': '$common_name' }, "result": { '$push': '$common_name' } } },
            { "$unwind": "$result" },
            { "$group": { "_id": "$_id.ca", "count": { "$sum": 1 } } }
            ]).exec();
        }
        //             {"$group": {"_id": null, "result": {'$addToSet': '$common_name'}}}
        return promise;
    },
    getRecordsBySSLCAPromise(caIssuer, count, page, limit, recursive) {
        let promise;
        if (recursive === true) {
            if (count === true) {
                promise = zSchema.zgrab443Model.countDocuments({
                    [zgrab_cert_path + 'chain.0.parsed.issuer.common_name']: caIssuer,
                }).exec();
            } else {
                if (limit > 0 && page > 0) {
                    promise = zSchema.zgrab443Model.find({
                        [zgrab_cert_path + 'chain.0.parsed.issuer.common_name']: caIssuer,
                    }).skip(limit * (page - 1)).limit(limit).exec();
                } else {
                    promise = zSchema.zgrab443Model.find({
                        [zgrab_cert_path + 'chain.0.parsed.issuer.common_name']: caIssuer,
                    }).exec();
                }
            }
        } else {
            if (count === true) {
                promise = zSchema.zgrab443Model.aggregate([{
                    "$project":
                    {
                        'data.http':
                            { "$ifNull": ["$data.http.redirect_response_chain", ["$data.http.response"]] }
                    }
                },
                { "$match": { 'data.http.0.request.tls_handshake.server_certificates.chain.0.parsed.issuer.common_name': caIssuer } },
                { "$count": "count" }]
                ).exec();
            } else {
                if (limit > 0) {
                    promise = zSchema.zgrab443Model.aggregate([
                        {
                            "$project":
                            {
                                'domain': 1,
                                'ip': 1,
                                'data.http':
                                    { "$ifNull": ["$data.http.redirect_response_chain", ["$data.http.response"]] }
                            }
                        },
                        { "$match": { 'data.http.0.request.tls_handshake.server_certificates.chain.0.parsed.issuer.common_name': caIssuer } },
                        { "$skip": (limit * (page - 1)) },
                        { "$limit": limit }]
                    ).exec();
                } else {
                    promise = zSchema.zgrab443Model.aggregate([{
                        "$project":
                        {
                            'domain': 1,
                            'ip': 1,
                            'data.http':
                                { "$ifNull": ["$data.http.redirect_response_chain", ["$data.http.response"]] }
                        }
                    },
                    { "$match": { 'data.http.0.request.tls_handshake.server_certificates.chain.0.parsed.issuer.common_name': caIssuer } }]
                    ).exec();
                }
            }
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
            promise = zSchema.zgrab443Model.find(query).exists(headerQuery).countDocuments().exec();
        } else {
            promise = zSchema.zgrab443Model.find(query).exists(headerQuery).select(headerQuery + ' zones domain ip').exec();
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
            promise = zSchema.zgrab443Model.countDocuments(query).exec();
        } else {
            promise = zSchema.zgrab443Model.find(query).select('data.http.response.headers.unknown.$.key data.http.response.headers.unknown.$.value ' + ' zones ip domain').exec();
        }
        return (promise);
    },
    getHttpHeaderByValuePromise: function (header, value, zone) {
        let headerQuery = 'data.http.response.headers.' + header;
        let query = { [headerQuery]: value };
        if (zone != null && zone !== '') {
            query['zones'] = zone;
        }
        return zSchema.zgrab443Model.find(query).select(headerQuery + ' zones domain ip').exec();
    },
    getUnknownHttpHeaderByValuePromise: function (value, zone) {
        let query = { 'data.http.response.headers.unknown.value': value };
        if (zone != null && zone !== '') {
            query['zones'] = zone;
        }
        return zSchema.zgrab443Model.find(query).select('data.http.response.headers.$.key ' + ' zones ip domain').exec();
    },
    getDistinctHttpHeaderPromise: function (header, zone) {
        let headerQuery = 'data.http.response.headers.' + header;
        let query;
        if (zone == null || zone === '') {
            query = { '$match': { [headerQuery]: { '$exists': true } } };
        } else {
            query = { '$match': { [headerQuery]: { '$exists': true }, 'zones': zone } };
        }
        return zSchema.zgrab443Model.aggregate([query, { '$group': { '_id': '$' + headerQuery, 'count': { '$sum': 1 } } }]).sort({ 'count': 'descending' }).exec();
    },
    getDistinctUnknownHttpHeaderPromise: function (header, zone) {
        let query = {}
        if (zone == null || zone === '') {
            query = { 'data.http.response.headers.unknown.key': header };
        } else {
            query = { 'data.http.response.headers.unknown.key': header, 'zones': zone };
        }
        return zSchema.zgrab443Model.aggregate([{ "$match": query },
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
};
