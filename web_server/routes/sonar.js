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
const CIDRMatcher = require('cidr-matcher');

const sonarRdns = require('../config/models/sonar_rdns');

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
 * This module has been deprecated.
 * It has been replaced by the dns routes.
 */


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
 * @swagger
 *
 * definitions:
 *   SonarRDNSModel:
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
 *       fqdn:
 *         type: string
 *         example: stage.example.org
 *       ip:
 *         type: string
 *         example: 11.22.33.44
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
  *   - name: Sonar RDNS - RDNS Search
  *     description: An all purpose RDNS record search API.
  *   - name: Sonar RDNS - RDNS Count
  *     description: Get a count of matching RDNS records
  *
  * /api/v1.0/sonar/rdns:
  *   get:
  *   # Operation-specific security:
  *     security:
  *       - APIKeyHeader: []
  *     description: Retrieves information regarding DNS records based on the provided parameters. The parameters range,
  *                  ipv6_range, domain, ip, ipv6, amazonSearch, txtSearch, dnsType, and cnameTLD are mutually exclusive.
  *     tags: [Sonar RDNS - RDNS Search]
  *     produces:
  *       - application/json
  *     parameters:
  *       - name: range
  *         type: string
  *         required: false
  *         description: Fetch RDNS records associated with the provided CIDR.
  *         in: query
  *       - name: domain
  *         type: string
  *         required: false
  *         description: Fetch RDNS records associated with the provided FQDN.
  *         in: query
  *       - name: ip
  *         type: string
  *         required: false
  *         description: Fetch RDNS records associated with the provided IPv4 address.
  *         in: query
  *       - name: zone
  *         type: string
  *         required: false
  *         description: Fetch all RDNS parameters associated with this zone.
  *     responses:
  *       200:
  *         description: Returns the array of zones.
  *         type: array
  *         items:
  *           $ref: '#/definitions/SonarRDNSModel'
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
  * /api/v1.0/sonar/rdns?count=1:
  *   get:
  *   # Operation-specific security:
  *     security:
  *       - APIKeyHeader: []
  *     description: Returns a count of all matching records based on the parameters provided. The parameters
  *                  zone and range are mutually exclusive.
  *     tags: [Sonar RDNS - RDNS Count]
  *     produces:
  *       - application/json
  *     parameters:
  *       - name: count
  *         type: string
  *         required: true
  *         description: Set to 1 to get a zone-by-zone list of matched records.
  *         in: query
  *       - name: zone
  *         type: string
  *         required: false
  *         description: Limit results to a specific zone (E.g. "example.org").
  *         in: query
  *       - name: range
  *         type: string
  *         required: false
  *         description: Fetch RDNS records associated with the provided CIDR.
  *         in: query
  *     responses:
  *       200:
  *         description: A count of all matching RDNS records.
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
    router.route('/sonar/rdns')
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
                promise = sonarRdns.getSRDNSByIPRangePromise(searchRange);
                promise.then(function (data) {
                    if (!data) {
                        res.status(404).json({ 'message': 'Info not found' });
                        return;
                    }
                    let matcher = new CIDRMatcher();
                    matcher.addNetworkClass(req.query.range);
                    let returnData = [];
                    for (let i = 0; i < data.length; i++) {
                        if (matcher.contains(data[i]['ip'])) {
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
            } else if (req.query.hasOwnProperty('ip')) {
                promise = sonarRdns.getSRDNSByIPPromise(req.query.ip);
            } else if (req.query.hasOwnProperty('domain')) {
                promise = sonarRdns.getSRDNSByDomainPromise(req.query.domain);
            } else if ((req.query.hasOwnProperty('count')) &&
                (req.query.count === '1')) {
                if (req.query.hasOwnProperty('zone')) {
                    promise = sonarRdns.getSRDNSCount(req.query.zone);
                } else {
                    promise = sonarRdns.getSRDNSCount();
                }
            } else if (req.query.hasOwnProperty('zone')) {
                promise = sonarRdns.getSRDNSByZonePromise(req.query.zone);
            } else {
                res.status(400).json({
                    'message': 'A zone, ip, range, or domain must be provided',
                });
                return;
            }
            promise.then(function (data) {
                if (!data) {
                    res.status(404).json({ 'message': 'Info not found' });
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

    return (router);
};
