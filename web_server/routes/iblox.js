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
const { celebrate, Joi } = require('celebrate');

const ibloxARecs = require('../config/models/iblox_a_records');
const ibloxAAAARecs = require('../config/models/iblox_aaaa_records');
const ibloxHostRecs = require('../config/models/iblox_host_records');
const ibloxCnameRecs = require('../config/models/iblox_cname_records');
const ibloxMXRecs = require('../config/models/iblox_mx_records');
const ibloxTXTRecs = require('../config/models/iblox_txt_records');
const ibloxExtattrRecs = require('../config/models/iblox_extattr_records');

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
 *   IB-BadInputValidation:
 *     properties:
 *       keys:
 *        type: array
 *        items:
 *           type: string
 *        example: ["type"]
 *        description: The keys which were specified incorrectly
 *       source:
 *         type: string
 *         enum: [body, header, params, query]
 *         example: query
 *         description: The location where this attribute was located
 *
 *   IB-BadInputError:
 *     properties:
 *       error:
 *         type: string
 *         example: Bad Request
 *         description: Error type
 *       message:
 *         type: string
 *         example: child "type" fails because ["type" must be one of [ip, host, zone]]
 *         description: Details description indicating why the request failed
 *       statusCode:
 *         type: number
 *         example: 400
 *         description: HTTP error code
 *       validation:
 *         type: object
 *         $ref: '#/definitions/IB-BadInputValidation'
 *         description: The object indicating the reason for failure
 *
 */


module.exports = function (envConfig) {

    /**
     * Swagger is commented out because these APIs are being deprecated.
     * The comment documentation is being kept as a reference until it is officially removed.
     *
     * //@swagger
     *
     * security:
     *   - APIKeyHeader: []
     *
     * tags:
     *   - name: Infoblox - A records
     *     description: Retrieve information regarding Infoblox DNS "A" records
     *
     * definitions:
     *   InfobloxARecord:
     *     type: object
     *     properties:
     *       _zone:
     *         type: string
     *         example: "example.org"
     *       zone:
     *         type: string
     *         example: "example.org"
     *       ipv4addr:
     *         type: string
     *         example: "19.14.25.58"
     *       _ref:
     *         type: string
     *         example: "record:a/ZG5zLmJp12RfYSQuMS5iZS5hZG9iZ34sMTkzLjEwNC4yMTAbCNTg:example.org/External"
     *       view:
     *         type: string
     *         example: "External"
     *       name:
     *         type: string
     *         example: www.example.org
     *       updated:
     *         type: string
     *         example: 2018-07-22T11:00:32.821Z
     *
     * /api/v1.0/iblox/addresses:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Retrieve the Infoblox DNS "A" records for the specified query. The parameters range, zone, ip, and
     *                  domain mutually exclusive.
     *                  All Infoblox DNS records are included as part of the DNS API. This API is only useful if you need the
     *                  original records.
     *     tags: [Infoblox - A records]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: range
     *         type: string
     *         required: false
     *         description: A CIDR range to match.
     *         in: query
     *       - name: zone
     *         type: string
     *         required: false
     *         description: The domain (e.g. "example.org", "example.com", etc.) that you want to search.
     *         in: query
     *       - name: ip
     *         type: string
     *         required: false
     *         description: The IP of the specific record you want to retrieve (e.g. 8.8.8.8).
     *         in: query
     *       - name: domain
     *         type: string
     *         required: false
     *         description: The records for a specific domain name (e.g. www.example.org).
     *         in: query
     *     responses:
     *       200:
     *         description: Returns an array of Infoblox A records.
     *         type: array
     *         items:
     *           $ref: '#/definitions/InfobloxARecord'
     *       400:
     *         description: Bad input was specified
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       404:
     *         description: Results Not Found
     *         schema:
     *           $ref: '#/definitions/ResultsNotFound'
     *       500:
     *         description: Internal server error
     *         schema:
     *           $ref: '#/definitions/ServerError'
     *
     * /api/v1.0/iblox/addresses?count=1:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Count the Infoblox DNS "A" records for the specified query. The parameters range and zone are mutually
     *                  exclusive.
     *                  All Infoblox DNS records are included as part of the DNS API. This API is only useful if you need the
     *                  original records.
     *     tags: [Infoblox - A records]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: count
     *         type: string
     *         required: true
     *         description: Set to 1 for this type of query.
     *         in: query
     *       - name: range
     *         type: string
     *         required: false
     *         description: A IPv4 CIDR to search.
     *         in: query
     *       - name: zone
     *         type: string
     *         required: false
     *         description: The domain (e.g. "example.org", "example.com", etc.) that you want to search.
     *         in: query
     *     responses:
     *       200:
     *         description: Returns the count of Infoblox A records.
     *         schema:
     *           $ref: '#/definitions/CountResponse'
     *       400:
     *         description: Bad input was specified
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       404:
     *         description: Results Not Found
     *         schema:
     *           $ref: '#/definitions/ResultsNotFound'
     *       500:
     *         description: Internal server error
     *         schema:
     *           $ref: '#/definitions/ServerError'
     *
     */
    router.route('/iblox/addresses')
        .get(function (req, res) {
            let promise;

            if (!is_valid_strings(req.query)) {
                res.status(400).json({ 'message': 'Multiple query parameters are not allowed.' });
                return;
            }

            if (req.query.hasOwnProperty('range')) {
                let searchRange = createRange(req.query.range);
                if (searchRange.startsWith('Error')) {
                    res.status(500).json({ 'message': searchRange });
                    return;
                }
                promise = ibloxARecs.getIBAddrByIPRangePromise(searchRange);
                promise.then(function (data) {
                    if (!data) {
                        res.status(404).json({ 'message': 'Info not found' });
                        return;
                    }
                    let matcher = new CIDRMatcher();
                    matcher.addNetworkClass(req.query.range);
                    let returnData = [];
                    for (let i = 0; i < data.length; i++) {
                        if (matcher.contains(data[i]['ipv4addr'])) {
                            returnData.push(data[i]);
                        }
                    }
                    if (req.query.hasOwnProperty('count') &&
                        req.query.count === '1') {
                        res.status(200).json({ 'count': returnData.length });
                    } else {
                        res.status(200).json(returnData);
                    }
                    return;
                });
                return;
            } else if (req.query.hasOwnProperty('zone')) {
                if (req.query.hasOwnProperty('count') && req.query.count === '1') {
                    promise = ibloxARecs.getIBAddrCountPromise(req.query.zone);
                } else {
                    promise = ibloxARecs.getIBAddrByZonePromise(req.query.zone);
                }
            } else if (req.query.hasOwnProperty('domain')) {
                promise = ibloxARecs.getIBAddrByNamePromise(req.query.domain);
            } else if (req.query.hasOwnProperty('ip')) {
                promise = ibloxARecs.getIBAddrByIPPromise(req.query.ip);
            } else if (req.query.hasOwnProperty('count') &&
                req.query.count === '1') {
                promise = ibloxARecs.getIBAddrCountPromise();
            } else {
                res.status(400).json({
                    'message': 'An IP, domain, range, or zone must be provided',
                });
                return;
            }

            promise.then(function (data) {
                if (!data) {
                    res.status(404).json({ 'message': 'Data not found' });
                    return;
                }
                if (req.query.count) {
                    res.status(200).json({ 'count': data });
                } else {
                    res.status(200).json(data);
                }
                return;
            });
        });

    /**
     * Swagger is commented out because these APIs are being deprecated.
     * The comment documentation is being kept as a reference until it is officially removed.
     *
     * //@swagger
     *
     * security:
     *   - APIKeyHeader: []
     *
     * tags:
     *   - name: Infoblox - AAAA records
     *     description: Retrieve information regarding Infoblox DNS "AAAA" IPv6 records
     *
     * definitions:
     *   InfobloxAAAARecord:
     *     type: object
     *     properties:
     *       _zone:
     *         type: string
     *         example: "example.org"
     *       zone:
     *         type: string
     *         example: "example.org"
     *       ipv6addr:
     *         type: string
     *         example: "2001:67c:3b8::1"
     *       _ref:
     *         type: string
     *         example: "record:aaaa/ZG5zLmJp12RfYSQuMS5iZS5hZG9iZ34sMTkzLjEwNC4yMTAbCNTg:foo.example.org/External"
     *       view:
     *         type: string
     *         example: "External"
     *       name:
     *         type: string
     *         example: foo.example.org
     *       updated:
     *         type: string
     *         example: 2018-07-22T11:00:32.821Z
     *
     * /api/v1.0/iblox/aaaa:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Retrieve the Infoblox DNS "AAAA" IPv6 records for the specified query. The parameters range, zone, ip, and
     *                  domain are mutually exclusive.
     *                  All Infoblox DNS records are included as part of the DNS API. This API is only useful if you need the
     *                  original records.
     *     tags: [Infoblox - AAAA records]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: range
     *         type: string
     *         required: false
     *         description: A CIDR for IPv6 range.
     *         in: query
     *       - name: zone
     *         type: string
     *         required: false
     *         description: The domain (e.g. "example.org", "example.com", etc.) that you want to search.
     *         in: query
     *       - name: ip
     *         type: string
     *         required: false
     *         description: The IP of the specific record you want to retrieve (e.g. 8.8.8.8)
     *         in: query
     *       - name: domain
     *         type: string
     *         required: false
     *         description: The records for a specific domain name (e.g. www.example.org)
     *         in: query
     *     responses:
     *       200:
     *         description: Returns an array of Infoblox AAAA records.
     *         type: array
     *         items:
     *           $ref: '#/definitions/InfobloxAAAARecord'
     *       400:
     *         description: Bad input was specified
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       404:
     *         description: Results Not Found
     *         schema:
     *           $ref: '#/definitions/ResultsNotFound'
     *       500:
     *         description: Internal server error
     *         schema:
     *           $ref: '#/definitions/ServerError'
     *
     * /api/v1.0/iblox/aaaa?count=1:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Count the Infoblox DNS "AAAA" IPv6 records for the specified query. The parameters range and zone are
     *                  mutually exclusive.
     *                  All Infoblox DNS records are included as part of the DNS API. This API is only useful if you need the
     *                  original records.
     *     tags: [Infoblox - AAAA records]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: count
     *         type: string
     *         required: true
     *         description: Set to 1 for this type of query.
     *         in: query
     *       - name: range
     *         type: string
     *         required: false
     *         description: A CIDR for an IPv6 range.
     *         in: query
     *       - name: zone
     *         type: string
     *         required: false
     *         description: The domain (e.g. "example.org", "example.com", etc.) that you want to search.
     *         in: query
     *     responses:
     *       200:
     *         description: Returns the count of Infoblox AAAA records.
     *         schema:
     *           $ref: '#/definitions/CountResponse'
     *       400:
     *         description: Bad input was specified
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       404:
     *         description: Results Not Found
     *         schema:
     *           $ref: '#/definitions/ResultsNotFound'
     *       500:
     *         description: Internal server error
     *         schema:
     *           $ref: '#/definitions/ServerError'
     */
    router.route('/iblox/aaaa')
        .get(function (req, res) {
            let promise;

            if (!is_valid_strings(req.query)) {
                res.status(400).json({ 'message': 'Multiple query parameters are not allowed.' });
                return;
            }

            if (req.query.hasOwnProperty('range')) {
                let searchRange = rangeCheck.isRange(req.query.range);
                if (searchRange === false) {
                    res.status(400).json({ 'message': "Invalid IPv6 range" });
                    return;
                }
                //The database is searched via regex.
                //Therefore, we search the database for the first block.
                //That list is then range checked against the specific range.
                let regex_range = req.query.range.split(":")[0]
                promise = ibloxAAAARecs.getIBIPv6AddrByIPRangePromise(regex_range);
                promise.then(function (data) {
                    if (!data) {
                        res.status(404).json({ 'message': 'Info not found' });
                        return;
                    }
                    let returnData = [];
                    for (let i = 0; i < data.length; i++) {
                        if (rangeCheck.inRange(data[i]['ipv6addr'], req.query.range)) {
                            returnData.push(data[i]);
                        }
                    }
                    if (req.query.hasOwnProperty('count') &&
                        req.query.count === '1') {
                        res.status(200).json({ 'count': returnData.length });
                    } else {
                        res.status(200).json(returnData);
                    }
                    return;
                });
                return;
            } else if (req.query.hasOwnProperty('zone')) {
                if (req.query.hasOwnProperty('count') && req.query.count === '1') {
                    promise = ibloxAAAARecs.getIBIPv6AddrCountPromise(req.query.zone);
                } else {
                    promise = ibloxAAAARecs.getIBIPv6AddrByZonePromise(req.query.zone);
                }
            } else if (req.query.hasOwnProperty('domain')) {
                promise = ibloxAAAARecs.getIBIPv6AddrByNamePromise(req.query.domain);
            } else if (req.query.hasOwnProperty('ip')) {
                promise = ibloxAAAARecs.getIBIPv6AddrByIPPromise(req.query.ip);
            } else if (req.query.hasOwnProperty('count') &&
                req.query.count === '1') {
                promise = ibloxAAAARecs.getIBIPv6AddrCountPromise();
            } else {
                res.status(400).json({
                    'message': 'An IP, domain, range, or zone must be provided',
                });
                return;
            }

            promise.then(function (data) {
                if (!data) {
                    res.status(404).json({ 'message': 'Data not found' });
                    return;
                }
                if (req.query.count) {
                    res.status(200).json({ 'count': data });
                } else {
                    res.status(200).json(data);
                }
                return;
            });
        });

    /**
     * Swagger is commented out because these APIs are being deprecated.
     * The comment documentation is being kept as a reference until it is officially removed.
     *
     * //@swagger
     *
     * security:
     *   - APIKeyHeader: []
     *
     * tags:
     *   - name: Infoblox - Host records
     *     description: Retrieve information regarding Infoblox DNS Host records
     *
     * definitions:
     *   InfobloxHostRecord:
     *     type: object
     *     properties:
     *       _zone:
     *         type: string
     *         example: "example.org"
     *       zone:
     *         type: string
     *         example: "example.org"
     *       _ref:
     *         type: string
     *         example: "record:host/ZG5zLmhvc3QkLjEuY29tLmFkb2JlCWUuABNhLXRlc2QtMw:test-3.example.org/External"
     *       view:
     *         type: string
     *         example: "External"
     *       name:
     *         type: string
     *         example: www.example.org
     *       updated:
     *         type: string
     *         example: 2018-07-22T11:00:32.821Z
     *       ipv4addrs:
     *         type: array
     *         items:
     *           type: object
     *           properties:
     *             host:
     *               type: string
     *               example: "www.example.org"
     *             configure_for_dhcp:
     *               type: boolean
     *               example: false
     *             ipv4addr:
     *               type: string
     *               example: "154.34.5.114"
     *             _ref:
     *               type: string
     *               example: "record:host_ipv4addr/Z23zLmhvc3RfYWRkcmVzcyQuMS5jb48uYWRvYmUtABC1Y2F0aW9uLnd3dy4xNTQuMzQuNS4xMTQu:154.34.5.114/www.example.org/External"
     *
     *
     * /api/v1.0/iblox/hosts:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Retrieve the Infoblox DNS Host records for the specified query. The parameters range, zone, ip,
     *                  and domain are mutually exclusive.
     *                  All Infoblox DNS records are included as part of the DNS API. This API is only useful if you need the
     *                  original records.
     *     tags: [Infoblox - Host records]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: range
     *         type: string
     *         required: false
     *         description: A CIDR for IPv6 range.
     *         in: query
     *       - name: zone
     *         type: string
     *         required: false
     *         description: The domain (e.g. "example.org", "example.com", etc.) that you want to search.
     *         in: query
     *       - name: ip
     *         type: string
     *         required: false
     *         description: The IP of the specific record you want to retrieve (e.g. 8.8.8.8)
     *         in: query
     *       - name: domain
     *         type: string
     *         required: false
     *         description: The records for a specific domain name (e.g. www.example.org)
     *         in: query
     *     responses:
     *       200:
     *         description: Returns an array of Infoblox Host records.
     *         type: array
     *         items:
     *           $ref: '#/definitions/InfobloxHostRecord'
     *       400:
     *         description: Bad input was specified
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       404:
     *         description: Results Not Found
     *         schema:
     *           $ref: '#/definitions/ResultsNotFound'
     *       500:
     *         description: Internal server error
     *         schema:
     *           $ref: '#/definitions/ServerError'
     *
     * /api/v1.0/iblox/hosts?count=1:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Count the Infoblox DNS Hosts records for the specified query. The parameters range and zone are mutually
     *                  exclusive.
     *                  All Infoblox DNS records are included as part of the DNS API. This API is only useful if you need the
     *                  original records.
     *     tags: [Infoblox - Host records]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: count
     *         type: string
     *         required: true
     *         description: Set to 1 for this type of query.
     *         in: query
     *       - name: range
     *         type: string
     *         required: false
     *         description: A CIDR for an IPv4 range.
     *         in: query
     *       - name: zone
     *         type: string
     *         required: false
     *         description: The domain (e.g. "example.org", "example.com", etc.) that you want to search.
     *         in: query
     *     responses:
     *       200:
     *         description: Returns the count of Infoblox Host records.
     *         schema:
     *           $ref: '#/definitions/CountResponse'
     *       400:
     *         description: Bad input was specified
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       404:
     *         description: Results Not Found
     *         schema:
     *           $ref: '#/definitions/ResultsNotFound'
     *       500:
     *         description: Internal server error
     *         schema:
     *           $ref: '#/definitions/ServerError'
     */
    router.route('/iblox/hosts')
        .get(function (req, res) {
            let promise;

            if (!is_valid_strings(req.query)) {
                res.status(400).json({ 'message': 'Multiple query parameters are not allowed.' });
                return;
            }

            if (req.query.hasOwnProperty('range')) {
                let searchRange = createRange(req.query.range);
                if (searchRange.startsWith('Error')) {
                    res.status(500).json({ 'message': searchRange });
                    return;
                }
                promise = ibloxHostRecs.getIBHostByIPRangePromise(searchRange);
                promise.then(function (data) {
                    if (!data) {
                        res.status(404).json({ 'message': 'Info not found' });
                        return;
                    }
                    let matcher = new CIDRMatcher();
                    matcher.addNetworkClass(req.query.range);
                    let returnData = [];
                    for (let i = 0; i < data.length; i++) {
                        let ipMatch = false;
                        for (let j = 0; j < data[i]['ipv4addrs'].length; j++) {
                            if (matcher.contains(data[i]['ipv4addrs'][j]['ipv4addr'])) {
                                ipMatch = true;
                            }
                        }
                        if (ipMatch) {
                            returnData.push(data[i]);
                        }
                    }
                    if (req.query.hasOwnProperty('count') &&
                        req.query.count === '1') {
                        let cnt = returnData.length;
                        res.status(200).json({ 'count': cnt });
                    } else {
                        res.status(200).json(returnData);
                    }
                    return;
                });
                return;
            } else if (req.query.hasOwnProperty('zone')) {
                if (req.query.hasOwnProperty('count') && req.query.count === '1') {
                    promise = ibloxHostRecs.getIBHostCountPromise(req.query.zone);
                } else {
                    promise = ibloxHostRecs.getIBHostByZonePromise(req.query.zone);
                }
            } else if (req.query.hasOwnProperty('domain')) {
                promise = ibloxHostRecs.getIBHostByNamePromise(req.query.domain);
            } else if (req.query.hasOwnProperty('ip')) {
                promise =
                    ibloxHostRecs.getIBHostByIPPromise(req.query.ip);
            } else if (req.query.hasOwnProperty('count') &&
                req.query.count === '1') {
                promise = ibloxHostRecs.getIBHostCountPromise();
            } else {
                res.status(400).json({
                    'message': ' A domain, ip, range, or zone must be provided.',
                });
                return;
            }
            promise.then(function (data) {
                if (!data) {
                    res.status(404).json({ 'message': 'Data not found' });
                    return;
                }
                if (req.query.hasOwnProperty('count') && req.query.count === '1') {
                    res.status(200).json({ 'count': data })
                } else {
                    res.status(200).json(data);
                }
                return;
            });
        });

    /**
     * Swagger is commented out because these APIs are being deprecated.
     * The comment documentation is being kept as a reference until it is officially removed.
     *
     * //@swagger
     *
     * security:
     *   - APIKeyHeader: []
     *
     * tags:
     *   - name: Infoblox - CName records
     *     description: Retrieve information regarding Infoblox CName records
     *
     * definitions:
     *   InfobloxCNameRecord:
     *     type: object
     *     properties:
     *       _zone:
     *         type: string
     *         example: "example.org"
     *       zone:
     *         type: string
     *         example: "example.org"
     *       _ref:
     *         type: string
     *         example: "record:cname/ZG5zLmJpbmRfY25hbWUkLjEuY2EuYWRvYmUud3d3:www.example.ca/External"
     *       view:
     *         type: string
     *         example: "External"
     *       name:
     *         type: string
     *         example: www.example.org
     *       updated:
     *         type: string
     *         example: 2018-07-22T11:00:32.821Z
     *       canonical:
     *         type: string
     *         example: redirect.example.org
     *
     * /api/v1.0/iblox/cnames:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Retrieve the Infoblox DNS CName records for the specified query. The parameters zone, domain,
     *                  and cnameTLD are mutually exclusive.
     *                  All Infoblox DNS records are included as part of the DNS API. This API is only useful if you need the
     *                  original records.
     *     tags: [Infoblox - CName records]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: cnameTLD
     *         type: string
     *         required: false
     *         description: Search canonical values based on how they end (e.g. /'.*' + tld + '$'/). This is useful for searching
     *                      non-tracked zones. This search can be limited with the addition of the zone parameter.
     *         in: query
     *       - name: zone
     *         type: string
     *         required: false
     *         description: The domain (e.g. "example.org", "example.com", etc.) that you want to search.
     *         in: query
     *       - name: domain
     *         type: string
     *         required: false
     *         description: The records for a specific domain name (e.g. www.example.org). Both the CName and value are checked.
     *         in: query
     *     responses:
     *       200:
     *         description: Returns an array of Infoblox CName records.
     *         type: array
     *         items:
     *           $ref: '#/definitions/InfobloxCNameRecord'
     *       400:
     *         description: Bad input was specified
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       404:
     *         description: Results Not Found
     *         schema:
     *           $ref: '#/definitions/ResultsNotFound'
     *       500:
     *         description: Internal server error
     *         schema:
     *           $ref: '#/definitions/ServerError'
     *
     * /api/v1.0/iblox/cnames?count=1:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Count the Infoblox DNS CName records for the specified query. If a zone is not provided, this will return
     *                  a count of all cname records.
     *                  All Infoblox DNS records are included as part of the DNS API. This API is only useful if you need the
     *                  original records.
     *     tags: [Infoblox - CName records]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: count
     *         type: string
     *         required: true
     *         description: Set to 1 for this type of query.
     *         in: query
     *       - name: zone
     *         type: string
     *         required: false
     *         description: The domain (e.g. "example.org", "example.com", etc.) that you want to search.
     *         in: query
     *     responses:
     *       200:
     *         description: Returns the count of Infoblox CName records.
     *         schema:
     *           $ref: '#/definitions/CountResponse'
     *       400:
     *         description: Bad input was specified
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       404:
     *         description: Results Not Found
     *         schema:
     *           $ref: '#/definitions/ResultsNotFound'
     *       500:
     *         description: Internal server error
     *         schema:
     *           $ref: '#/definitions/ServerError'
     */
    router.route('/iblox/cnames')
        .get(function (req, res) {
            let promise;

            if (!is_valid_strings(req.query)) {
                res.status(400).json({ 'message': 'Multiple query parameters are not allowed.' });
                return;
            }

            if (req.query.hasOwnProperty('zone')) {
                if (req.query.hasOwnProperty('count') && req.query.count === '1') {
                    promise = ibloxCnameRecs.getIBCNameCountPromise(req.query.zone);
                } else {
                    promise = ibloxCnameRecs.getIBCNameByZonePromise(req.query.zone);
                }
            } else if (req.query.hasOwnProperty('domain')) {
                promise = ibloxCnameRecs.getIBCNameByNamePromise(req.query.domain);
            } else if (req.query.hasOwnProperty('cnameTLD')) {
                if (req.query.hasOwnProperty('zone') && req.query.zone.length > 0) {
                    promise = ibloxCnameRecs.getIBCNameByCanonicalSearch(req.query.cnameTLD, req.query.zone);
                } else {
                    promise = ibloxCnameRecs.getIBCNameByCanonicalSearch(req.query.cnameTLD, null);
                }
            } else if (req.query.hasOwnProperty('count') &&
                req.query.count === '1') {
                promise = ibloxCnameRecs.getIBCNameCountPromise();
            } else {
                res.status(400).json({
                    'message': ' A domain, cnameTLD, or zone must be provided.',
                });
                return;
            }
            promise.then(function (data) {
                if (!data) {
                    res.status(404).json({ 'message': 'Data not found' });
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
     * Swagger is commented out because these APIs are being deprecated.
     * The comment documentation is being kept as a reference until it is officially removed.
     *
     * //@swagger
     *
     * security:
     *   - APIKeyHeader: []
     *
     * tags:
     *   - name: Infoblox - MX records
     *     description: Retrieve information regarding Infoblox MX records
     *
     * definitions:
     *   InfobloxMXRecord:
     *     type: object
     *     properties:
     *       _zone:
     *         type: string
     *         example: "example.ua"
     *       zone:
     *         type: string
     *         example: "example.ua"
     *       _ref:
     *         type: string
     *         example: "record:mx/ZG5zLmJpbmRfbXgkLjEudWEuYWRvYmUuLmFkb2JlLXVhLm1haWwucHJvdGVjdGlvbi5vdXRsb29rLmNvbS4x:example.ua/External"
     *       view:
     *         type: string
     *         example: "External"
     *       name:
     *         type: string
     *         example: example.ua
     *       created:
     *         type: string
     *         example: 2018-07-22T11:00:32.821Z
     *       updated:
     *         type: string
     *         example: 2018-07-22T11:00:32.821Z
     *       mail_exchanger:
     *         type: string
     *         example: foo-ua.mail.protection.outlook.com
     *
     * /api/v1.0/iblox/mx:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Retrieve the Infoblox MX records for the specified query. The zone, domain, and mail_exchanger parameters
     *                  are mutually exclusive.
     *                  All Infoblox DNS records are included as part of the DNS API. This API is only useful if you need the
     *                  original records.
     *     tags: [Infoblox - MX records]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: mail_exchanger
     *         type: string
     *         required: false
     *         description: Search for records associated with a specific mail exchanger. This query can be limited by adding
     *                      the zone parameter.
     *         in: query
     *       - name: zone
     *         type: string
     *         required: false
     *         description: The domain (e.g. "example.org", "example.com", etc.) that you want to search.
     *         in: query
     *       - name: domain
     *         type: string
     *         required: false
     *         description: The records for a specific domain name (e.g. www.example.org).
     *         in: query
     *     responses:
     *       200:
     *         description: Returns an array of Infoblox MX records.
     *         type: array
     *         items:
     *           $ref: '#/definitions/InfobloxMXRecord'
     *       400:
     *         description: Bad input was specified
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       404:
     *         description: Results Not Found
     *         schema:
     *           $ref: '#/definitions/ResultsNotFound'
     *       500:
     *         description: Internal server error
     *         schema:
     *           $ref: '#/definitions/ServerError'
     *
     * /api/v1.0/iblox/mx?count=1:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Count the Infoblox MX records for the specified query. If a zone is not provided, this will return a count
     *                  of all records.
     *                  All Infoblox DNS records are included as part of the DNS API. This API is only useful if you need the
     *                  original records.
     *     tags: [Infoblox - MX records]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: count
     *         type: string
     *         required: true
     *         description: Set to 1 for this type of query.
     *         in: query
     *       - name: zone
     *         type: string
     *         required: false
     *         description: The domain (e.g. "example.org", "example.com", etc.) that you want to search.
     *         in: query
     *     responses:
     *       200:
     *         description: Returns the count of Infoblox MX records.
     *         schema:
     *           $ref: '#/definitions/CountResponse'
     *       400:
     *         description: Bad input was specified
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       404:
     *         description: Results Not Found
     *         schema:
     *           $ref: '#/definitions/ResultsNotFound'
     *       500:
     *         description: Internal server error
     *         schema:
     *           $ref: '#/definitions/ServerError'
     */
    router.route('/iblox/mx')
        .get(function (req, res) {
            let promise;

            if (!is_valid_strings(req.query)) {
                res.status(400).json({ 'message': 'Multiple query parameters are not allowed.' });
                return;
            }

            if (req.query.hasOwnProperty('zone')) {
                if (req.query.hasOwnProperty('count') && req.query.count === '1') {
                    promise = ibloxMXRecs.getIBMXCountPromise(req.query.zone);
                } else {
                    promise = ibloxMXRecs.getIBMXByZonePromise(req.query.zone);
                }
            } else if (req.query.hasOwnProperty('domain')) {
                promise = ibloxMXRecs.getIBMXByNamePromise(req.query.domain);
            } else if (req.query.hasOwnProperty('mail_exchanger')) {
                if (req.query.hasOwnProperty('zone') && req.query.zone.length > 0) {
                    promise = ibloxMXRecs.getIBMXByMailExchanger(req.query.mail_exchanger, req.query.zone);
                } else {
                    promise = ibloxMXRecs.getIBMXByMailExchanger(req.query.mail_exchanger, null);
                }
            } else if (req.query.hasOwnProperty('count') &&
                req.query.count === '1') {
                promise = ibloxMXRecs.getIBMXCountPromise();
            } else {
                res.status(400).json({
                    'message': ' A domain, mail_exchanger, or zone must be provided.',
                });
                return;
            }
            promise.then(function (data) {
                if (!data) {
                    res.status(404).json({ 'message': 'Data not found' });
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
     * Swagger is commented out because these APIs are being deprecated.
     * The comment documentation is being kept as a reference until it is officially removed.
     *
     * //@swagger
     *
     * security:
     *   - APIKeyHeader: []
     *
     * tags:
     *   - name: Infoblox - TXT records
     *     description: Retrieve information regarding Infoblox TXT records
     *
     * definitions:
     *   InfobloxTXTRecord:
     *     type: object
     *     properties:
     *       _zone:
     *         type: string
     *         example: "example.ua"
     *       zone:
     *         type: string
     *         example: "example.ua"
     *       _ref:
     *         type: string
     *         example: "record:mx/ZG5zLmJpbmRfbXgkLjEudWEuYWRvYmUuLmFkb2JlLXVhLm1haWwucHJvdGVjdGlvbi5vdXRsb29rLmNvbS4x:example.ua/External"
     *       view:
     *         type: string
     *         example: "External"
     *       name:
     *         type: string
     *         example: example.ua
     *       updated:
     *         type: string
     *         example: 2018-07-22T11:00:32.821Z
     *       created:
     *         type: string
     *         example: 2018-07-22T11:00:32.821Z
     *       mail_exchanger:
     *         type: string
     *         example: foo-ua.mail.protection.outlook.com
     *
     * /api/v1.0/iblox/txt:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Retrieve the Infoblox TXT records for the specified query. The zone, domain, and txt parameters are
     *                  mutually exclusive.
     *                  All Infoblox DNS records are included as part of the DNS API. This API is only useful if you need the
     *                  original records.
     *     tags: [Infoblox - TXT records]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: txt
     *         type: string
     *         required: false
     *         description: A substring of the text you want to search for in the records.
     *         in: query
     *       - name: zone
     *         type: string
     *         required: false
     *         description: The domain (e.g. "example.org", "example.com", etc.) that you want to search.
     *         in: query
     *       - name: domain
     *         type: string
     *         required: false
     *         description: The records for a specific domain name (e.g. www.example.org).
     *         in: query
     *     responses:
     *       200:
     *         description: Returns an array of Infoblox TXT records.
     *         type: array
     *         items:
     *           $ref: '#/definitions/InfobloxTXTRecord'
     *       400:
     *         description: Bad input was specified
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       404:
     *         description: Results Not Found
     *         schema:
     *           $ref: '#/definitions/ResultsNotFound'
     *       500:
     *         description: Internal server error
     *         schema:
     *           $ref: '#/definitions/ServerError'
     *
     * /api/v1.0/iblox/txt?count=1:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Count the Infoblox TXT records for the specified query.
     *                  All Infoblox DNS records are included as part of the DNS API. This API is only useful if you need the
     *                  original records.
     *     tags: [Infoblox - TXT records]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: count
     *         type: string
     *         required: true
     *         description: Set to 1 for this type of query.
     *         in: query
     *       - name: zone
     *         type: string
     *         required: false
     *         description: The domain (e.g. "example.org", "example.com", etc.) that you want to search.
     *         in: query
     *     responses:
     *       200:
     *         description: Returns the count of Infoblox TXT records.
     *         schema:
     *           $ref: '#/definitions/CountResponse'
     *       400:
     *         description: Bad input was specified
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       404:
     *         description: Results Not Found
     *         schema:
     *           $ref: '#/definitions/ResultsNotFound'
     *       500:
     *         description: Internal server error
     *         schema:
     *           $ref: '#/definitions/ServerError'
     */
    router.route('/iblox/txt')
        .get(function (req, res) {
            let promise;

            if (!is_valid_strings(req.query)) {
                res.status(400).json({ 'message': 'Multiple query parameters are not allowed.' });
                return;
            }

            if (req.query.hasOwnProperty('zone')) {
                if (req.query.hasOwnProperty('count') && req.query.count === '1') {
                    promise = ibloxTXTRecs.getIBTXTCountPromise(req.query.zone);
                } else {
                    promise = ibloxTXTRecs.getIBTXTByZonePromise(req.query.zone);
                }
            } else if (req.query.hasOwnProperty('domain')) {
                promise = ibloxTXTRecs.getIBTXTByNamePromise(req.query.domain);
            } else if (req.query.hasOwnProperty('txt')) {
                promise = ibloxTXTRecs.getIBTXTByRegex(req.query.txt);
            } else if (req.query.hasOwnProperty('count') &&
                req.query.count === '1') {
                promise = ibloxTXTRecs.getIBTXTCountPromise();
            } else {
                res.status(400).json({
                    'message': ' A domain, TXT substring, or zone must be provided.',
                });
                return;
            }
            promise.then(function (data) {
                if (!data) {
                    res.status(404).json({ 'message': 'Data not found' });
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
     * Retrieves the owner values from 'extattrs'
     * @param data: Raw owner information.
     * @returns {Array} Array of objects containing owner information.
     */
    function extract_owners(data) {
        let owners = [];
        for (let i = 0; i < data.length; i++) {
            let owner_info = {};
            let owners_list = [];
            for (let extattr_key of Object.keys(data[i]['extattrs'])) {
                if (extattr_key.toLowerCase().split(' ').indexOf('owner') > -1) {
                    owners_list.push(data[i]['extattrs'][extattr_key]['value']);
                }
            }
            if (owners_list.length) {
                owner_info = { 'owners': owners_list.join(',') };
                if ('ref' in data[i]) {
                    owner_info['meta'] = data[i]['ref'].split('/')[1].split(':')[1];
                }
                owners.push(owner_info);
            }
        }
        return owners;
    }

    /**
     * @swagger
     *
     * security:
     *   - APIKeyHeader: []
     *
     * tags:
     *   - name: Infoblox - Owners
     *     description: Retrieve the Infoblox owner information for zone, ip, cname and host.
     *
     * definitions:
     *   OwnerDetails:
     *     type: object
     *     properties:
     *       owners:
     *         type: string
     *         example: Owner 1, Owner 2
     *         description: Comma separated values of the owners.
     *       meta:
     *         type: string
     *         example: stage.example.org
     *         description: The domain to which the owners are associated. This is only sent
     *                      when searching for the owners for IP.
     *
     * /api/v1.0/iblox/owners:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Retrieve the Infoblox owner information for zone, ip, cname and host from the extattr fields.
     *                  This information is not included in the DNS API.
     *     tags: [Infoblox - Owners]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: type
     *         type: string
     *         required: true
     *         description: Defines the type of search. Valid values are ip, ipv6, host, cname, zone.
     *         enum: [ip,ipv6,host,cname,zone]
     *         in: query
     *       - name: value
     *         type: string
     *         required: true
     *         description: Defines the value of the ip,cname,host,zone whose Infoblox owner
     *                      information needs to be fetched.
     *         in: query
     *     responses:
     *       200:
     *         description: Returns an array of infoblox owner values.
     *         type: array
     *         items:
     *           $ref: '#/definitions/OwnerDetails'
     *       400:
     *         description: Bad input was specified
     *         schema:
     *           $ref: '#/definitions/IB-BadInputError'
     *       500:
     *         description: Internal server error
     *         schema:
     *           $ref: '#/definitions/ServerError'
     */
    router.route('/iblox/owners')
        .get(celebrate({
            query: {
                type: Joi.string().required().valid('ip', 'ipv6', 'host', 'cname', 'zone'),
                value: Joi.string().required().min(1).when('type', {
                    is: 'ip',
                    then: Joi.string().ip({
                        version: [
                            'ipv4',
                        ]
                    },
                        {
                            is: 'ipv6',
                            then: Joi.string().ip({
                                version: [
                                    'ipv6',
                                ]
                            })
                        })
                }),
                apiKey: Joi.string().allow('')
            }
        }), function (req, res) {
            let promise;
            let record_type = req.query.type;
            record_type = record_type.charAt(0).toUpperCase() + record_type.slice(1);
            promise = ibloxExtattrRecs['getIB' + record_type + 'Extattr'](req.query.value);

            promise.then(function (data) {
                let owners = extract_owners(data);
                res.json(owners);
            }).catch(function () {
                res.status(500).json({
                    'message': 'An error occurred at the server.',
                });
            });
        });

    return (router);
};
