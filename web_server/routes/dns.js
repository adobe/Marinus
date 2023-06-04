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

const express = require('express');
const router = express.Router();
const htmlEscape = require('secure-filters').html;

const allDNS = require('../config/models/all_dns');
const deadDNS = require('../config/models/dead_dns');

const CIDRMatcher = require('cidr-matcher');
const rangeCheck = require('range_check');

/**
 * Converts a CIDR range into a string for text searches.
 * Supports Class B and Class C ranges.
 * @param {string} range The CIDR range to be converted.
 * @return {string}
 */
function createRange(range) {
    let parts = range.split('/');
    let ip = parts[0];
    let ipParts = ip.split('.');
    let cidr = parts[1];
    if (cidr < 8 || cidr > 32) {
        return ('Error: Invalid CIDR');
    }
    if (ipParts.length !== 4) {
        return ('Error: Invalid IP');
    }
    let searchRange = ipParts[0] + '\\.' + ipParts[1] + '\\.';
    if (cidr >= 24) {
        searchRange += ipParts[2];
    }
    return (searchRange);
}

function isValidDate(d) {
    return d instanceof Date && !isNaN(d);
}

/**
 * Confirm that all parameters are a string and not an array.
 * This helps prevent NoSQL injection since NoSQL will honor arrays as parameters.
 * @param {*} req The Express request.query object representing the GET parameters.
 */
function is_valid_strings(params) {
    for (var prop in params) {
        if (Object.prototype.hasOwnProperty.call(params, prop)) {
            if (typeof params[prop] != "string") {
                return false;
            }
            if (params[prop].includes("[") || params[prop].includes["$"] || params[prop].includes["{"]) {
                return false;
            }
        }
    }
    return true;
}

/**
 * @swagger
 *
 * definitions:
 *   DNSModel:
 *     type: object
 *     description: An tracked DNS record
 *     properties:
 *       zone:
 *         type: string
 *         example: "example.org"
 *       status:
 *         type: string
 *         example: "unconfirmed"
 *       created:
 *         type: string
 *         example: 2016-06-22T02:08:46.893Z
 *       updated:
 *         type: string
 *         example: 2016-06-22T02:08:46.893Z
 *       type:
 *         type: string
 *         example: "a"
 *       fqdn:
 *         type: string
 *         example: stage.example.org
 *       value:
 *         type: string
 *         example: 11.22.33.44
 *       sources:
 *         type: array
 *         items:
 *           type: object
 *           properties:
 *             source:
 *               type: string
 *               example: "infoblox"
 *             updated:
 *               type: string
 *               example: 2016-06-22T02:08:46.893Z
 *       accountInfo:
 *         type: array
 *         items:
 *           type: object
 *           properties:
 *             key:
 *               type: string
 *               example: "accountType"
 *             value:
 *               type: string
 *               example: "aws"
 *       sonar_timestamp:
 *         type: integer
 *         example: 1489274775
 *
 *   DNSTypeCount:
 *     type: object
 *     properties:
 *       zone:
 *         type: string
 *         example: example.org
 *       count:
 *         type: integer
 *         example: 2
 *
 */

module.exports = function (envConfig) {

    /**
     * @swagger
     *
     * security:
     *   - APIKeyHeader: []
     *
     * tags:
     *   - name: DNS - DNS Search
     *     description: An all purpose DNS record search API.
     *   - name: DNS - DNS List
     *     description: Get a zone by zone break down of records.
     *   - name: DNS - DNS Count
     *     description: Get a count of matching DNS records
     *
     * /api/v1.0/dns:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Retrieves information regarding DNS records based on the provided parameters. The parameters range,
     *                  ipv6_range, domain, ip, ipv6, amazonSearch, txtSearch, dnsType, created, and cnameTLD are mutually exclusive.
     *     tags: [DNS - DNS Search]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: source
     *         type: string
     *         required: false
     *         description: Limit results to a specific source. Works with most types of searches.
     *         in: query
     *       - name: range
     *         type: string
     *         required: false
     *         description: Fetch DNS records associated with the provided CIDR.
     *         in: query
     *       - name: ipv6_range
     *         type: string
     *         required: false
     *         description: Fetch DNS records associated with the provided IPv6 CIDR.
     *         in: query
     *       - name: domain
     *         type: string
     *         required: false
     *         description: Fetch DNS records associated with the provided FQDN.
     *         in: query
     *       - name: ip
     *         type: string
     *         required: false
     *         description: Fetch DNS records associated with the provided IPv4 address.
     *         in: query
     *       - name: ipv6
     *         type: string
     *         required: false
     *         description: Fetch DNS records associated with the provided IPv6 address.
     *         in: query
     *       - name: amazonSearch
     *         type: string
     *         required: false
     *         description: Fetch DNS records that regex match the value + ".amazonaws.com". Set to "all" to fetch any record
     *                      that ends in ".amazonaws.com".
     *         in: query
     *       - name: txtSearch
     *         type: string
     *         required: false
     *         description: Fetch DNS TXT records associated with either SPF or DKIM records. Optionally works with the zone value.
     *         enum: [spf, dkim]
     *         in: query
     *       - name: dnsType
     *         type: string
     *         required: false
     *         description: Fetch DNS records associated with the provided type (e.g. "a", "mx", "txt", etc). Works with list,
     *                      source, and zone parameters.
     *         enum: [a, cname, ns, soa, aaaa, txt, ptr, mx, ds, naptr, rrsig, srv]
     *         in: query
     *       - name: cname
     *         type: string
     *         required: false
     *         description: Fetch DNS records whose fqdn resolves to the provided CNAME value
     *         in: query
     *       - name: cnameTLD
     *         type: string
     *         required: false
     *         description: Fetch DNS CName records whose value ends with the provided string. This search is not strictly
     *                      limited to TLDs (e.g. .edu). The search is a regex that just checks whether the CName ends with
     *                      whatever value is provided.
     *         in: query
     *       - name: accountInfoValue
     *         type: string
     *         required: false
     *         description: Fetch DNS records based on the value of an accountInfo entry. If AccountInfo is specified in the
     *                      all_dns table, this will search for any records with the provided value.
     *         in: query
     *       - name: zone
     *         type: string
     *         required: false
     *         description: Fetch all DNS parameters associated with this zone. Also works in conjunction with txtSearch, dnsType,
     *                      and cnameTLD queries.
     *         in: query
     *       - name: subdomain
     *         type: string
     *         required: false
     *         description: Fetch all DNS parameters associated with this subdomain. This will search for all FQDNs that end with
     *                      the provided subdomain. For instance, if "foo.example.org" is provided, then it will search for
     *                      .*\.foo.example.org. There is no need to add the wildcards or leading dots. You only need to
     *                      provide "foo.example.org".
     *         in: query
     *       - name: created
     *         type: string
     *         required: false
     *         description: Fetch all DNS entries whose created value is greater than the provided value. The value must have the
     *                      format YYYY-MM-DD (or any valid field for the new Date() JavaScript function). Limit and page
     *                      are supported. A created field can be used in conjunction with the zone parameter.
     *         in: query
     *       - name: limit
     *         type: number
     *         required: false
     *         description: Limit the number of records per page when requesting information by zone. Does not apply to other queries. Default 1,000.
     *         in: query
     *       - name: page
     *         type: number
     *         required: false
     *         description: The page to request. This must be set in conjunction with the limit parameter. This only applies to zone queries. The default is 1.
     *         in: query
     *     responses:
     *       200:
     *         description: Returns the array of DNS results.
     *         type: array
     *         items:
     *           $ref: '#/definitions/DNSModel'
     *       400:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       404:
     *         description: Results not found.
     *         schema:
     *           $ref: '#/definitions/ResultsNotFound'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     *
     * /api/v1.0/dns?list=1:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Retrieves information regarding DNS records based on the provided parameters in a zone-by-zone break down.
     *                  The parameters dnsType and txtSearch are mutually exclusive.
     *     tags: [DNS - DNS List]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: list
     *         type: string
     *         required: true
     *         description: Set to 1 to get a zone-by-zone list of matched records.
     *         in: query
     *       - name: source
     *         type: string
     *         required: false
     *         description: Limit results to a specific source. Works with most types of searches.
     *         in: query
     *       - name: txtSearch
     *         type: string
     *         required: false
     *         description: Fetch DNS TXT records associated with either SPF or DKIM records. Optionally works with the zone value.
     *         enum: [spf, dkim]
     *         in: query
     *       - name: dnsType
     *         type: string
     *         required: false
     *         description: Fetch DNS records associated with the provided type (e.g. "a", "mx", "txt", etc). Works with list,
     *                      source, and zone parameters.
     *         enum: [a, cname, ns, soa, aaaa, txt, ptr, mx, ds, naptr, rrsig, srv]
     *         in: query
     *     responses:
     *       200:
     *         description: A zone-by-zone break down of matched records.
     *         type: object
     *         schema:
     *           $ref: '#/definitions/DNSTypeCount'
     *       400:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       404:
     *         description: Results not found.
     *         schema:
     *           $ref: '#/definitions/ResultsNotFound'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     *
     * /api/v1.0/dns?count=1:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Returns a count of all matching records based on the parameters provided. The parameters range, ipv6_range,
     *                  txtSearch, and dnsType are mutually exclusive.
     *     tags: [DNS - DNS Count]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: count
     *         type: string
     *         required: true
     *         description: Set to 1 to get a zone-by-zone list of matched records.
     *         in: query
     *       - name: source
     *         type: string
     *         required: false
     *         description: Limit results to a specific source. Works with most types of searches.
     *         in: query
     *       - name: range
     *         type: string
     *         required: false
     *         description: Fetch DNS records associated with the provided CIDR.
     *         in: query
     *       - name: ipv6_range
     *         type: string
     *         required: false
     *         description: Fetch DNS records associated with the provided IPv6 CIDR.
     *         in: query
     *       - name: txtSearch
     *         type: string
     *         required: false
     *         description: Fetch DNS TXT records associated with either SPF or DKIM records. Optionally works with the zone value.
     *         enum: [spf, dkim]
     *         in: query
     *       - name: dnsType
     *         type: string
     *         required: false
     *         description: Fetch DNS records associated with the provided type (e.g. "a", "mx", "txt", etc). Works with list,
     *                      source, and zone parameters.
     *         enum: [a, cname, ns, soa, aaaa, txt, ptr, mx, ds, naptr, rrsig, srv]
     *         in: query
     *     responses:
     *       200:
     *         description: A count of all matching DNS records.
     *         schema:
     *           $ref: '#/definitions/CountResponse'
     *       400:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       404:
     *         description: Results not found.
     *         schema:
     *           $ref: '#/definitions/ResultsNotFound'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     */
    router.route('/dns')
        .get(function (req, res) {
            let promise;
            let source = null;

            if (!is_valid_strings(req.query)) {
                res.status(400).json({ 'message': 'Multiple query parameters are not allowed.' });
                return;
            }

            if (req.query.hasOwnProperty('source')) {
                source = req.query.source;
            }

            let limit = 1000;
            if (req.query.hasOwnProperty('limit')) {
                limit = parseInt(req.query.limit);
                if (isNaN(limit)) {
                    res.status(400).json({ 'message': 'A valid limit value must be provided.' });
                    return;
                }
                if (limit < 0) {
                    limit = 0;
                }
            }

            let page = 1;
            if (req.query.hasOwnProperty('page')) {
                page = parseInt(req.query.page);
                if (isNaN(page)) {
                    res.status(400).json({ 'message': 'A valid page value must be provided.' });
                    return;
                }
                if (page < 1) {
                    page = 1;
                }
            }

            let created_date = null;
            if (req.query.hasOwnProperty('created')) {
                created_date = new Date(req.query.created);
                if (!isValidDate(created_date)) {
                    res.status(400).json({
                        'message': 'A valid date must be provided',
                    });
                    return;
                }
            }

            if (req.query.hasOwnProperty('range')) {
                let searchRange = createRange(req.query.range);
                if (searchRange.startsWith('Error')) {
                    res.status(400).json({ 'message': htmlEscape(searchRange) });
                    return;
                }
                promise = allDNS.getAllDNSByIPRangePromise(searchRange, source);
                promise.then(function (data) {
                    if (!data) {
                        res.status(404).json({ 'message': 'Info not found' });
                        return;
                    }
                    let matcher = new CIDRMatcher();
                    matcher.addNetworkClass(req.query.range);
                    let returnData = [];
                    for (let i = 0; i < data.length; i++) {
                        if (matcher.contains(data[i]['value'])) {
                            returnData.push(data[i]);
                        }
                    }
                    if (req.query.hasOwnProperty('count')) {
                        res.status(200).json({ 'count': returnData.length });
                    } else {
                        res.status(200).json(returnData);
                    }
                    return;
                });
                return;
            } else if (req.query.hasOwnProperty('ipv6_range')) {
                if (!rangeCheck.isRange(req.query.ipv6_range)) {
                    res.status(400).json({ 'message': 'A valid IPv6 range must be provided' });
                    return;
                }
                let searchRange = req.query.ipv6_range.split(":")[0];
                promise = allDNS.getAllDNSByIPv6RangePromise(searchRange, source);
                promise.then(function (data) {
                    if (!data) {
                        res.status(404).json({ 'message': 'Info not found' });
                        return;
                    }
                    let returnData = [];
                    for (let i = 0; i < data.length; i++) {
                        if (rangeCheck.inRange(data[i]['value'], req.query.ipv6_range)) {
                            returnData.push(data[i]);
                        }
                    }
                    if (req.query.hasOwnProperty('count')) {
                        res.status(200).json({ 'count': returnData.length });
                    } else {
                        res.status(200).json(returnData);
                    }
                    return;
                });
                return;
            } else if (req.query.hasOwnProperty('domain')) {
                promise = allDNS.getAllDNSByDomainPromise(req.query.domain, source);
            } else if (req.query.hasOwnProperty('ip')) {
                promise = allDNS.getAllDNSByIPPromise(req.query.ip, source);
            } else if (req.query.hasOwnProperty('ipv6')) {
                promise = allDNS.getAllDNSByIPv6Promise(req.query.ipv6, source);
            } else if (req.query.hasOwnProperty('amazonSearch')) {
                promise = allDNS.getAllDNSAmazonEntriesPromise(req.query.amazonSearch, source);
            } else if (req.query.hasOwnProperty('txtSearch')) {
                let zone = null;
                let count = false;
                if (req.query.hasOwnProperty('zone')) {
                    zone = req.query.zone;
                }
                if (req.query.hasOwnProperty('count') && req.query.count === '1') {
                    count = true;
                }
                if (req.query.txtSearch === 'spf') {
                    if (req.query.hasOwnProperty('list') && req.query.list === '1') {
                        promise = allDNS.getAllDNSTxtByZoneCountPromise('spf', source);
                    } else {
                        promise = allDNS.getAllDNSByTxtSearchPromise('spf', zone, source, count);
                    }
                } else if (req.query.txtSearch === 'dkim') {
                    if (req.query.hasOwnProperty('list') && req.query.list === '1') {
                        promise = allDNS.getAllDNSTxtByZoneCountPromise('dkim', source);
                    } else {
                        promise = allDNS.getAllDNSByTxtSearchPromise('dkim', zone, source, count);
                    }
                } else {
                    res.status(400).json({ 'message': 'Unknown text search type.' });
                    return;
                }
            } else if (req.query.hasOwnProperty('dnsType')) {
                let zone = null;
                let count = false;
                if (req.query.hasOwnProperty('zone')) {
                    zone = req.query.zone;
                }
                if (req.query.hasOwnProperty('count') && req.query.count === '1') {
                    count = true;
                }
                if (req.query.hasOwnProperty('list') && req.query.list === '1') {
                    promise = allDNS.getAllDNSTypeByZoneCountPromise(req.query.dnsType, source);
                } else {
                    promise = allDNS.getAllDNSByTypePromise(req.query.dnsType, zone, source, count);
                }
            } else if (req.query.hasOwnProperty('cnameTLD')) {
                if (req.query.hasOwnProperty('zone') && req.query.zone.length > 0) {
                    promise = allDNS.getAllDNSByCanonicalSearch(req.query.cnameTLD, req.query.zone, source);
                } else {
                    promise = allDNS.getAllDNSByCanonicalSearch(req.query.cnameTLD, null, source);
                }
            } else if (req.query.hasOwnProperty('cname')) {
                if (req.query.hasOwnProperty('zone') && req.query.zone.length > 0) {
                    promise = allDNS.getAllDNSByCNameSearch(req.query.cname, req.query.zone, source);
                } else {
                    promise = allDNS.getAllDNSByCNameSearch(req.query.cname, null, source);
                }
            } else if ((req.query.hasOwnProperty('count')) &&
                (req.query.count === '1')) {
                if (req.query.hasOwnProperty('zone')) {
                    promise = allDNS.getAllDNSCount(req.query.zone, source);
                } else {
                    promise = allDNS.getAllDNSCount(null, source);
                }
            } else if (req.query.hasOwnProperty('zone')) {
                promise = allDNS.getAllDNSByZonePromise(req.query.zone, source, created_date, limit, page);
            } else if (req.query.hasOwnProperty('accountInfoValue')) {
                promise = allDNS.getByAccountInfo(req.query.accountInfoValue);
            } else if (req.query.hasOwnProperty('subdomain')) {
                let escaped_domain = req.query.subdomain.replace(/\./g, "\\.");
                promise = allDNS.getRegexDNSWithCreatedPromise(escaped_domain, created_date, limit, page);
            } else if (created_date != null) {
                promise = allDNS.getAllDNSByCreatedPromise(req.query.created, limit, page);
            } else {
                res.status(400).json({
                    'message': 'A domain, ip, or zone must be provided',
                });
                return;
            }
            promise.then(function (data) {
                if (!data) {
                    res.status(404).json({ 'message': 'Info not found' });
                    return;
                }
                if (req.query.hasOwnProperty('count') && req.query.count === '1') {
                    res.status(200).json({ 'count': data });
                } else {
                    res.status(200).json(data);
                }
                return;
            });
        });


    /**
     * @swagger
     *
     * security:
     *   - APIKeyHeader: []
     *
     *   - name: Dead DNS - Dead DNS Search
     *     description: An all purpose dead DNS record search API.
     *   - name: Dead DNS - Dead DNS List
     *     description: Get a zone by zone break down of dead DNS records.
     *   - name: Dead DNS - Dead DNS Count
     *     description: Get a count of matching dead DNS records
     *
     * /api/v1.0/dead_dns:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Retrieves information regarding dead DNS records based on the provided parameters. The parameters range,
     *                  domain, ip, amazonSearch, dnsType, and cnameTLD are mutually exclusive.
     *     tags: [Dead DNS - Dead DNS Search]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: source
     *         type: string
     *         required: false
     *         description: Limit results to a specific source. Works with most types of searches.
     *         in: query
     *       - name: range
     *         type: string
     *         required: false
     *         description: Fetch DNS records associated with the provided CIDR.
     *         in: query
     *       - name: domain
     *         type: string
     *         required: false
     *         description: Fetch DNS records associated with the provided FQDN.
     *         in: query
     *       - name: ip
     *         type: string
     *         required: false
     *         description: Fetch DNS records associated with the provided IPv4 address.
     *         in: query
     *       - name: amazonSearch
     *         type: string
     *         required: false
     *         description: Fetch DNS records that regex match the value + ".amazonaws.com". Set to "all" to fetch any record
     *                      that ends in ".amazonaws.com".
     *         in: query
     *       - name: dnsType
     *         type: string
     *         required: false
     *         description: Fetch DNS records associated with the provided type (e.g. "a", "mx", "txt", etc). Works with list,
     *                      source, and zone parameters.
     *         enum: [a, cname, ns, soa, aaaa, txt, ptr, mx, ds, naptr, rrsig, srv]
     *         in: query
     *       - name: cnameTLD
     *         type: string
     *         required: false
     *         description: Fetch DNS CName records whose value ends with the provided string. This search is not strictly
     *                      limited to TLDs (e.g. .edu). The search is a regex that just checks whether the CName ends with
     *                      whatever value is provided.
     *         in: query
     *       - name: zone
     *         type: string
     *         required: false
     *         description: Fetch all DNS parameters associated with this zone. Also works in conjunction with txtSearch, dnsType,
     *                      and cnameTLD queries.
     *     responses:
     *       200:
     *         description: Returns the array of dead DNS records.
     *         type: array
     *         items:
     *           $ref: '#/definitions/DNSModel'
     *       400:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       404:
     *         description: Results not found.
     *         schema:
     *           $ref: '#/definitions/ResultsNotFound'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     *
     * /api/v1.0/dead_dns?list=1:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Retrieves information regarding dead DNS records based on the provided parameters in a zone-by-zone break down.
     *     tags: [Dead DNS - Dead DNS List]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: list
     *         type: string
     *         required: true
     *         description: Set to 1 to get a zone-by-zone list of matched records.
     *         in: query
     *       - name: source
     *         type: string
     *         required: false
     *         description: Limit results to a specific source. Works with most types of searches.
     *         in: query
     *       - name: dnsType
     *         type: string
     *         required: false
     *         description: Fetch DNS records associated with the provided type (e.g. "a", "mx", "txt", etc). Works with list,
     *                      source, and zone parameters.
     *         enum: [a, cname, ns, soa, aaaa, txt, ptr, mx, ds, naptr, rrsig, srv]
     *         in: query
     *     responses:
     *       200:
     *         description: A zone-by-zone break down of matched records.
     *         type: object
     *         schema:
     *           $ref: '#/definitions/DNSTypeCount'
     *       400:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       404:
     *         description: Results not found.
     *         schema:
     *           $ref: '#/definitions/ResultsNotFound'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     *
     * /api/v1.0/dead_dns?count=1:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Returns a count of all matching records based on the parameters provided. The parameters range,
     *                  and dnsType are mutually exclusive.
     *     tags: [Dead DNS - Dead DNS Count]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: count
     *         type: string
     *         required: true
     *         description: Set to 1 to get a zone-by-zone list of matched records.
     *         in: query
     *       - name: source
     *         type: string
     *         required: false
     *         description: Limit results to a specific source. Works with most types of searches.
     *         in: query
     *       - name: range
     *         type: string
     *         required: false
     *         description: Fetch DNS records associated with the provided CIDR.
     *         in: query
     *       - name: dnsType
     *         type: string
     *         required: false
     *         description: Fetch DNS records associated with the provided type (e.g. "a", "mx", "txt", etc). Works with list,
     *                      source, and zone parameters.
     *         enum: [a, cname, ns, soa, aaaa, txt, ptr, mx, ds, naptr, rrsig, srv]
     *         in: query
     *     responses:
     *       200:
     *         description: A count of all matching dead DNS records.
     *         schema:
     *           $ref: '#/definitions/CountResponse'
     *       400:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       404:
     *         description: Results not found.
     *         schema:
     *           $ref: '#/definitions/ResultsNotFound'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     */
    router.route('/dead_dns')
        .get(function (req, res) {
            let promise;
            let source = null;

            if (!is_valid_strings(req.query)) {
                res.status(400).json({ 'message': 'Multiple query parameters are not allowed.' });
                return;
            }

            if (req.query.hasOwnProperty('source')) {
                source = req.query.source;
            }
            if (req.query.hasOwnProperty('range')) {
                let searchRange = createRange(req.query.range);
                if (searchRange.startsWith('Error')) {
                    res.status(500).json({ 'message': htmlEscape(searchRange) });
                    return;
                }
                promise = deadDNS.getDeadDNSByIPRangePromise(searchRange, source);
                promise.then(function (data) {
                    if (!data) {
                        res.status(404).json({ 'message': 'Info not found' });
                        return;
                    }
                    let matcher = new CIDRMatcher();
                    matcher.addNetworkClass(req.query.range);
                    let returnData = [];
                    for (let i = 0; i < data.length; i++) {
                        if (matcher.contains(data[i]['value'])) {
                            returnData.push(data[i]);
                        }
                    }
                    if (req.query.hasOwnProperty('count')) {
                        res.status(200).json({ 'count': returnData.length });
                    } else {
                        res.status(200).json(returnData);
                    }
                    return;
                });
                return;
            } else if (req.query.hasOwnProperty('domain')) {
                promise = deadDNS.getDeadDNSByDomainPromise(req.query.domain, source);
            } else if (req.query.hasOwnProperty('ip')) {
                promise = deadDNS.getDeadDNSByIPPromise(req.query.ip, source);
            } else if (req.query.hasOwnProperty('amazonSearch')) {
                promise = deadDNS.getDeadDNSAmazonEntriesPromise(req.query.amazonSearch, source);
            } else if (req.query.hasOwnProperty('dnsType')) {
                let zone = null;
                let count = false;
                if (req.query.hasOwnProperty('zone')) {
                    zone = req.query.zone;
                }
                if (req.query.hasOwnProperty('count') && req.query.count === '1') {
                    count = true;
                }
                if (req.query.hasOwnProperty('list') && req.query.list === '1') {
                    promise = deadDNS.getDeadDNSTypeByZoneCountPromise(req.query.dnsType, source);
                } else {
                    promise = deadDNS.getDeadDNSByTypePromise(req.query.dnsType, zone, source, count);
                }
            } else if (req.query.hasOwnProperty('cnameTLD')) {
                if (req.query.hasOwnProperty('zone') && req.query.zone.length > 0) {
                    promise = deadDNS.getDeadDNSByCanonicalSearch(req.query.cnameTLD, req.query.zone, source);
                } else {
                    promise = deadDNS.getDeadDNSByCanonicalSearch(req.query.cnameTLD, null, source);
                }
            } else if ((req.query.hasOwnProperty('count')) &&
                (req.query.count === '1')) {
                if (req.query.hasOwnProperty('zone')) {
                    promise = deadDNS.getDeadDNSCount(req.query.zone, source);
                } else {
                    promise = deadDNS.getDeadDNSCount(null, source);
                }
            } else if (req.query.hasOwnProperty('zone')) {
                promise = deadDNS.getDeadDNSByZonePromise(req.query.zone, source);
            } else {
                promise = deadDNS.getAllDeadDNSPromise();
            }
            promise.then(function (data) {
                if (!data) {
                    res.status(404).json({ 'message': 'Info not found' });
                    return;
                }
                if (req.query.hasOwnProperty('count') && req.query.count === '1') {
                    res.status(200).json({ 'count': data });
                } else {
                    res.status(200).json(data);
                }
                return;
            });
        });

    /**
     * @swagger
     *
     * security:
     *   - APIKeyHeader: []
     *
     * tags:
     *   - name: DNS - DNS sources list
     *     description: Returns all known sources of DNS information.
     *
     * /api/v1.0/dns/sources:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Retrieves all known sources of DNS information for domains.
     *     tags: [DNS - DNS sources list]
     *     produces:
     *       - application/json
     *     responses:
     *       200:
     *         description: Returns the array of DNS sources.
     *         type: array
     *         items:
     *           string
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     */
    router.route('/dns/sources')
        .get(function (req, res) {
            let sourcePromise = allDNS.getDistinctDNSSources();
            sourcePromise.then(function (sources) {
                if (!sources) {
                    res.status(500).json({ 'message': 'Error retrieving sources' });
                    return;
                }
                let jsonRes = { 'sources': sources };
                res.status(200).json(jsonRes);
                return;
            });
        });

    return (router);
};
