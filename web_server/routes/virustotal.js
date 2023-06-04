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

const vt = require('../config/models/virustotal');

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
 * securityDefinitions:
 *   # X-API-Key: abcdef12345
 *   APIKeyHeader:
 *     type: apiKey
 *     in: query
 *     name: apiKey
 *
 * definitions:
 *   VT-Sample:
 *     type: object
 *     properties:
 *       date:
 *         type: string
 *         example: '2016-11-14T23:59:59.000Z'
 *         description: The expiry date
 *       positives:
 *         type: integer
 *         example: 0
 *         description: The number of positive hits
 *       total:
 *         type: integer
 *         example: 52
 *         description: The number of scans performed
 *       sha256:
 *         type: string
 *         example: 2ae445f4d92a76730367b4406166fd94aa703a3c147353f69764a715e7e80670
 *         description: The SHA256 for the sample
 *
 *   VT-PCAPsRecord:
 *     type: object
 *     properties:
 *       zone:
 *         type: string
 *         example: example.org
 *       pcaps:
 *         type: array
 *         items:
 *           type: string
 *           example: "79ee6ada01b3443b753d4abba6555809c92c98670a4bc16ca59e09c257030515"
 *
 *   VT-WhoisRecord:
 *     type: object
 *     properties:
 *       zone:
 *         type: string
 *         example: example.org
 *       whois:
 *         type: string
 *         description: The associated whois record
 *         example: '"Domain Name: METADATAWORKINGGROUP.ORG\nRegistry Domain ID: D153033302-LROR\nR....'
 *       whois_timestamp:
 *         type: number
 *         description: When the whois record was collected.
 *         example: 1495425931.16026
 *
 *   VT-IPRecord:
 *     type: object
 *     properties:
 *       zone:
 *         type: string
 *         example: example.org
 *       resolutions:
 *         type: array
 *         items:
 *           type: object
 *           properties:
 *             last_resolved:
 *               type: string
 *               example: "2013-10-19 00:00:00"
 *             ip_address:
 *               type: string
 *               example: "1.2.3.4"
 *
 *   VT-MetaRecord:
 *     type: object
 *     properties:
 *       zone:
 *         type: string
 *         description: The zone (e.g. "example.org", "example.com", etc) for the record
 *       Alexa rank:
 *         type: integer
 *         description: The Alexa rank
 *         example: 100
 *       Alexa category:
 *         type: string
 *         description: The Alexa category
 *         example: "software"
 *       Alexa domain info:
 *         type: string
 *         description: The Alexa domain information
 *         example: "example.org is one of the top 100 sites in the world and is in the Software category"
 *       categories:
 *         type: array
 *         example: ["business", "information technology"]
 *         items:
 *           type: string
 *       Webutation domain info:
 *         type: object
 *         properties:
 *           Safety score:
 *             type: integer
 *           Adult content:
 *             type: string
 *             example: "no"
 *           Verdict:
 *             type: string
 *             example: "unsure"
 *       WOT domain info:
 *         type: object
 *         properties:
 *           Vendor reliability:
 *             type: string
 *             example: Excellent
 *           Child safety:
 *             type: string
 *             example: Excellent
 *           Trustworthiness:
 *             type: string
 *             example: Excellent
 *           Privacy:
 *             type: string
 *             example: Excellent
 *       BitDefender category:
 *         type: string
 *         example: "business"
 *       TrendMicro category:
 *         type: string
 *         example: "computers internet,software downloads"
 *       Websense ThreatSeeker category:
 *         type: String
 *         example: "information technology"
 *       Dr Web category:
 *         type: String
 *         example: "adult content"
 *
 *   VT-DomainRecord:
 *     type: object
 *     properties:
 *       zone:
 *         type: string
 *         example: example.org
 *       subdomains:
 *         type: array
 *         items:
 *           type: string
 *       domain_siblings:
 *         type: array
 *         items:
 *           type: string
 *
 *   VT-SamplesRecord:
 *     type: object
 *     properties:
 *       created:
 *         type: string
 *         example: '2016-11-14T23:59:59.000Z'
 *         description: The expiry date
 *       detected_referrer_samples:
 *         type: array
 *         description: Matching referrer samples
 *         items:
 *           $ref: '#/definitions/VT-Sample'
 *       undetected_referrer_samples:
 *         type: array
 *         description: Non-matching referrer samples
 *         items:
 *           $ref: '#/definitions/VT-Sample'
 *       detected_downloaded_samples:
 *         type: array
 *         description: Matching downloaded samples
 *         items:
 *           $ref: '#/definitions/VT-Sample'
 *       undetected_downloaded_samples:
 *         type: array
 *         description: Non-matching downloaded samples
 *         items:
 *           $ref: '#/definitions/VT-Sample'
 *       detected_communicating_samples:
 *         type: array
 *         description: Matching communicating samples
 *         items:
 *           $ref: '#/definitions/VT-Sample'
 *       undetected_communicating_samples:
 *         type: array
 *         description: Non-matching communicating samples
 *         items:
 *           $ref: '#/definitions/VT-Sample'
 *       detected_urls:
 *         type: array
 *         description: Matching URL samples
 *         items:
 *           type: object
 *           properties:
 *             date:
 *               type: string
 *               example: '2016-11-14T23:59:59.000Z'
 *               description: The expiry date
 *             positives:
 *               type: integer
 *               description: The number of positive hits
 *             total:
 *               type: integer
 *               description: The number of scans performed
 *             url:
 *               type: string
 *               description: The URL for the sample
 *       response_code:
 *         type: integer
 *         example: 1
 *       verbose_msg:
 *         type: string
 *         example: "Domain found in dataset"
 *
 *   VT-Record:
 *     allOf:
 *       - $ref: '#/definitions/VT-SamplesRecord'
 *       - $ref: '#/definitions/VT-PCAPsRecord'
 *       - $ref: '#/definitions/VT-MetaRecord'
 *       - $ref: '#/definitions/VT-WhoisRecord'
 *       - $ref: '#/definitions/VT-IPRecord'
 *       - $ref: '#/definitions/VT-DomainRecord'
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
     *   - name: VirusTotal - Domain Detected search
     *     description: Check for records from VirusTotal that have the provided type and optional zone.
     *
     * /api/v1.0/virustotal/domainDetected:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Finds VirusTotal records based on their type and optionally limited to their zone.
     *     tags: [VirusTotal - Domain Detected search]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: type
     *         type: string
     *         required: true
     *         description: The type of record to match the domain against
     *         enum: [referrer, communicating, urls, dowloaded]
     *         in: query
     *       - name: zone
     *         type: string
     *         required: false
     *         description: The zone ("e.g. example.org") to search for in the results
     *         in: query
     *     responses:
     *       200:
     *         description: Returns a JSON object with the VirusTotal record
     *         schema:
     *           $ref: '#/definitions/VT-Record'
     *       400:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       404:
     *         description: No matching records found.
     *         schema:
     *           $ref: '#/definitions/ResultsNotFound'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     *
     * /api/v1.0/virustotal/domainDetected?count=1:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Counts VirusTotal records based on their type and optionally limited to their zone.
     *     tags: [VirusTotal - Domain Detected search]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: type
     *         type: string
     *         required: true
     *         description: The type of record to match the domain against
     *         enum: [referrer, communicating, urls, dowloaded]
     *         in: query
     *       - name: zone
     *         type: string
     *         required: false
     *         description: The zone ("e.g. example.org") to search for in the results
     *         in: query
     *       - name: count
     *         type: integer
     *         required: true
     *         description: Set to 1 to count the number of matching results
     *         in: query
     *     responses:
     *       200:
     *         description: Returns a JSON object with the number of matched VirusTotal records.
     *         schema:
     *           $ref: '#/definitions/CountResponse'
     *       400:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       404:
     *         description: No matching records found.
     *         schema:
     *           $ref: '#/definitions/ResultsNotFound'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     */
    router.route('/virustotal/domainDetected')
        .get(function (req, res) {

            if (!is_valid_strings(req.query)) {
                res.status(400).json({ 'message': 'Multiple query parameters are not allowed.' });
                return;
            }

            if (!(req.query.hasOwnProperty('type'))) {
                res.status(400).json({ 'message': 'A type must be provided' });
                return;
            }
            let type = req.query.type;
            let count = false;
            if (req.query.hasOwnProperty('count') && req.query.count === '1') {
                count = true;
            }
            let promise;
            if (req.query.hasOwnProperty('zone') &&
                req.query.zone.length > 0) {
                if (type === 'referrer') {
                    promise = vt.getDetectedReferrerSamplesByZonePromise(req.query.zone, count);
                } else if (type === 'communicating') {
                    promise = vt.getDetectedCommunicatingSamplesByZonePromise(req.query.zone, count);
                } else if (type === 'urls') {
                    promise = vt.getDetectedURLsByZonePromise(req.query.zone, count);
                } else if (type === 'downloaded') {
                    promise = vt.getDetectedDownloadedSamplesByZonePromise(req.query.zone, count);
                } else {
                    res.status(400).json({ 'message': 'Unknown Type' });
                    return;
                }
            } else {
                if (type === 'referrer') {
                    promise = vt.getDetectedReferrerSamplesPromise(count);
                } else if (type === 'communicating') {
                    promise = vt.getDetectedCommunicatingSamplesPromise(count);
                } else if (type === 'urls') {
                    promise = vt.getDetectedURLsPromise(count);
                } else if (type === 'downloaded') {
                    promise = vt.getDetectedDownloadedSamplesPromise(count);
                } else {
                    res.status(400).json({ 'message': 'Unknown Type' });
                    return;
                }
            }
            promise.then(function (data) {
                if (!data) {
                    res.status(404).json({ 'message': 'Data not found' });
                    return;
                }
                if (count) {
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
     *   - name: VirusTotal - Domain Report
     *     description: Check whether the provided organization is in any saved certificate transparency logs.
     *
     * /api/v1.0/virustotal/domainReport:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Finds VirusTotal records based on their zone.
     *     tags: [VirusTotal - Domain Report]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: zone
     *         type: string
     *         required: required
     *         description: The zone ("e.g. example.org") to search for in the results
     *         in: query
     *     responses:
     *       200:
     *         description: Returns a JSON object with the VirusTotal record
     *         schema:
     *           $ref: '#/definitions/VT-Record'
     *       400:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       404:
     *         description: No matching records found.
     *         schema:
     *           $ref: '#/definitions/ResultsNotFound'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     */
    router.route('/virustotal/domainReport')
        .get(function (req, res) {

            if (!is_valid_strings(req.query)) {
                res.status(400).json({ 'message': 'Multiple query parameters are not allowed.' });
                return;
            }

            if (!(req.query.hasOwnProperty('zone'))) {
                res.status(400).json({ 'message': 'A zone must be provided' });
                return;
            }
            let promise = vt.getRecordByZonePromise(req.query.zone);
            promise.then(function (data) {
                if (!data) {
                    res.status(404).json({ 'message': 'Zone not found' });
                    return;
                }
                res.status(200).json(data);
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
     *   - name: VirusTotal - Metadata search
     *     description: Returns a subset of the VT Record that deal with ratings and classifications.
     *   - name: VirusTotal - Metadata count
     *     description: Returns count = 1 if there is a record.
     *
     * /api/v1.0/virustotal/domainMetaReport:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Finds VirusTotal metadata records based on their zone.
     *     tags: [VirusTotal - Metadata search]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: zone
     *         type: string
     *         required: true
     *         description: The zone ("e.g. example.org") to search for in the results
     *         in: query
     *     responses:
     *       200:
     *         description: Returns a JSON object with the VirusTotal record
     *         schema:
     *           $ref: '#/definitions/VT-MetaRecord'
     *       400:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       404:
     *         description: No matching records found.
     *         schema:
     *           $ref: '#/definitions/ResultsNotFound'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     *
     * /api/v1.0/virustotal/domainMetaReport?count=1:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Returns count = 1 if a zone matches.
     *     tags: [VirusTotal - Metadata count]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: count
     *         type: string
     *         required: true
     *         description: Set to 1 for this type of query
     *         in: query
     *       - name: zone
     *         type: string
     *         required: true
     *         description: The zone ("e.g. example.org") to search for in the results
     *         in: query
     *     responses:
     *       200:
     *         description: Returns a Count Record if there is a match.
     *         schema:
     *           $ref: '#/definitions/CountResponse'
     *       400:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       404:
     *         description: No matching records found.
     *         schema:
     *           $ref: '#/definitions/ResultsNotFound'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     */
    router.route('/virustotal/domainMetaReport')
        .get(function (req, res) {

            if (!is_valid_strings(req.query)) {
                res.status(400).json({ 'message': 'Multiple query parameters are not allowed.' });
                return;
            }

            if (!(req.query.hasOwnProperty('zone'))) {
                res.status(400).json({ 'message': 'A zone must be provided' });
                return;
            }
            let count = false;
            if (req.query.hasOwnProperty('count') && req.query.count === "1") {
                count = true;
            }
            let promise = vt.getMetaInfoByZonePromise(req.query.zone);
            promise.then(function (data) {
                if ((!data || data.length === 0) && count === false) {
                    res.status(404).json({ 'message': 'Zone not found' });
                    return;
                } else if ((!data || data.length === 0) && count === true) {
                    res.status(200).json({ 'count': 0 })
                } else if (count) {
                    res.status(200).json({ 'count': 1 });
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
     *   - name: VirusTotal - Domain PCAPs search
     *     description: Check for PCAPs from VirusTotal optionally limited to a specific zone.
     *
     * /api/v1.0/virustotal/domainPcaps:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Finds VirusTotal PCaps. The results can optionally limited to their zone (e.g. "example.org").
     *     tags: [VirusTotal - Domain PCAPs search]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: zone
     *         type: string
     *         required: false
     *         description: The zone ("e.g. example.org") to search for in the results
     *         in: query
     *     responses:
     *       200:
     *         description: Returns a JSON object with the VirusTotal PCAP records
     *         schema:
     *           $ref: '#/definitions/VT-PCAPsRecord'
     *       400:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       404:
     *         description: No matching records found.
     *         schema:
     *           $ref: '#/definitions/ResultsNotFound'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     *
     * /api/v1.0/virustotal/domainPcaps?count=1:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Counts VirusTotal pcap records. The count can be limited to the optional limited zone (e.g. "example.org").
     *     tags: [VirusTotal - Domain PCAPs search]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: zone
     *         type: string
     *         required: false
     *         description: The zone ("e.g. example.org") to search for in the results
     *         in: query
     *       - name: count
     *         type: integer
     *         required: true
     *         description: Set to 1 to count the number of matching results
     *         in: query
     *     responses:
     *       200:
     *         description: Returns a JSON object with the number of matched VirusTotal PCAP records.
     *         schema:
     *           $ref: '#/definitions/CountResponse'
     *       400:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       404:
     *         description: No matching records found.
     *         schema:
     *           $ref: '#/definitions/ResultsNotFound'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     */
    router.route('/virustotal/domainPcaps')
        .get(function (req, res) {
            let promise;

            if (!is_valid_strings(req.query)) {
                res.status(400).json({ 'message': 'Multiple query parameters are not allowed.' });
                return;
            }

            if (req.query.hasOwnProperty('zone')) {
                let count = false;
                if (req.query.hasOwnProperty('count') &&
                    req.query.count === '1') {
                    count = true;
                }
                promise = vt.getPcapsByZonePromise(req.query.zone, count);
            } else if (req.query.hasOwnProperty('count') &&
                req.query.count === '1') {
                promise = vt.getAllPcapsPromise(true);
            } else {
                promise = vt.getAllPcapsPromise(false);
            }

            promise.then(function (data) {
                if (!data) {
                    res.status(404).json({ 'message': 'Data not found' });
                    return;
                }
                if (req.query.hasOwnProperty('count') &&
                    req.query.count === '1') {
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
     *   - name: VirusTotal - Domain Whois
     *     description: Returns a subset of the VT Record that deal with ratings and classifications.
     *
     * /api/v1.0/virustotal/domainWhois:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Finds VirusTotal whois records based on their zone.
     *     tags: [VirusTotal - Domain Whois]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: zone
     *         type: string
     *         required: true
     *         description: The zone ("e.g. example.org") to search for in the results
     *         in: query
     *     responses:
     *       200:
     *         description: Returns a JSON object with the VirusTotal Whois record
     *         schema:
     *           $ref: '#/definitions/VT-WhoisRecord'
     *       400:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       404:
     *         description: No matching records found.
     *         schema:
     *           $ref: '#/definitions/ResultsNotFound'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     */
    router.route('/virustotal/domainWhois')
        .get(function (req, res) {

            if (!is_valid_strings(req.query)) {
                res.status(400).json({ 'message': 'Multiple query parameters are not allowed.' });
                return;
            }

            if (!(req.query.hasOwnProperty('zone'))) {
                res.status(400).json({ 'message': 'A zone must be provided' });
                return;
            }
            let promise = vt.getWhoisByZonePromise(req.query.zone);
            promise.then(function (data) {
                if (!data) {
                    res.status(404).json({ 'message': 'Zone not found' });
                    return;
                }
                res.status(200).json(data);
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
     *   - name: VirusTotal - Domain IPs search
     *     description: Check for IP resolution from VirusTotal for a specific zone.
     *
     * /api/v1.0/virustotal/domainIPs:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Finds VirusTotal IP resolutions for the provided zone (e.g. "example.org").
     *     tags: [VirusTotal - Domain IPs search]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: zone
     *         type: string
     *         required: true
     *         description: The zone ("e.g. example.org") to search for in the results
     *         in: query
     *     responses:
     *       200:
     *         description: Returns a JSON object with the VirusTotal IP resolution records
     *         schema:
     *           $ref: '#/definitions/VT-IPRecord'
     *       400:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       404:
     *         description: No matching records found.
     *         schema:
     *           $ref: '#/definitions/ResultsNotFound'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     *
     * /api/v1.0/virustotal/domainIPs?count=1:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Counts VirusTotal IP resolutions for the provided zone (e.g. "example.org").
     *     tags: [VirusTotal - Domain IPs search]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: zone
     *         type: string
     *         required: true
     *         description: The zone ("e.g. example.org") to search for in the results
     *         in: query
     *       - name: count
     *         type: integer
     *         required: true
     *         description: Set to 1 to count the number of matching results
     *         in: query
     *     responses:
     *       200:
     *         description: Returns a JSON object with the number of matched VirusTotal IP resolutions for the given zone.
     *         schema:
     *           $ref: '#/definitions/CountResponse'
     *       400:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       404:
     *         description: No matching records found.
     *         schema:
     *           $ref: '#/definitions/ResultsNotFound'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     */
    router.route('/virustotal/domainIPs')
        .get(function (req, res) {

            if (!is_valid_strings(req.query)) {
                res.status(400).json({ 'message': 'Multiple query parameters are not allowed.' });
                return;
            }

            if (!(req.query.hasOwnProperty('zone'))) {
                res.status(400).json({ 'message': 'A zone must be provided' });
                return;
            }
            let promise = vt.getIPInfoByZonePromise(req.query.zone);
            promise.then(function (data) {
                if (!data || data.length === 0) {
                    res.status(404).json({ 'message': 'Zone not found' });
                    return;
                }
                if (req.query.hasOwnProperty('count') &&
                    req.query.count === '1') {
                    let cnt = data[0]['resolutions'].length;
                    res.status(200).json({ 'count': cnt });
                    return;
                }
                res.status(200).json(data);
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
     *   - name: VirusTotal - Subdomains search
     *     description: Check for domain siblings and subdomains from VirusTotal for a specific zone.
     *
     * /api/v1.0/virustotal/domainSubdomains:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Finds VirusTotal subdomains and siblings for the provided zone (e.g. "example.org").
     *     tags: [VirusTotal - Subdomains search]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: zone
     *         type: string
     *         required: true
     *         description: The zone ("e.g. example.org") to search for in the results
     *         in: query
     *     responses:
     *       200:
     *         description: Returns a JSON object with the VirusTotal domain siblings and subdomain records
     *         schema:
     *           $ref: '#/definitions/VT-DomainRecord'
     *       400:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       404:
     *         description: No matching records found.
     *         schema:
     *           $ref: '#/definitions/ResultsNotFound'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     *
     * /api/v1.0/virustotal/domainSubdomains?count=1:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Counts VirusTotal domain siblings and subdomains for the provided zone (e.g. "example.org").
     *     tags: [VirusTotal - Subdomains search]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: zone
     *         type: string
     *         required: true
     *         description: The zone ("e.g. example.org") to search for in the results
     *         in: query
     *       - name: count
     *         type: integer
     *         required: true
     *         description: Set to 1 to count the number of matching results
     *         in: query
     *     responses:
     *       200:
     *         description: Returns a JSON object with the number of matched VirusTotal subdomains and siblings for the given zone.
     *         schema:
     *           $ref: '#/definitions/CountResponse'
     *       400:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       404:
     *         description: No matching records found.
     *         schema:
     *           $ref: '#/definitions/ResultsNotFound'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     */
    router.route('/virustotal/domainSubdomains')
        .get(function (req, res) {

            if (!is_valid_strings(req.query)) {
                res.status(400).json({ 'message': 'Multiple query parameters are not allowed.' });
                return;
            }

            if (!(req.query.hasOwnProperty('zone'))) {
                res.status(400).json({ 'message': 'A zone must be provided' });
                return;
            }
            let promise = vt.getSubDomainsByZonePromise(req.query.zone);
            promise.then(function (data) {
                if (!data || data.length === 0) {
                    res.status(404).json({ 'message': 'Zone not found' });
                    return;
                }
                if (req.query.hasOwnProperty('count') &&
                    req.query.count === '1') {
                    let cnt = 0;
                    if (data[0]['domain_siblings']) {
                        cnt = cnt + data[0]['domain_siblings'].length;
                    }
                    if (data[0]['subdomains']) {
                        cnt = cnt + data[0]['subdomains'].length;
                    }
                    res.status(200).json({ 'count': cnt });
                    return;
                }
                res.status(200).json(data);
                return;
            });
        });

    return (router);
};
