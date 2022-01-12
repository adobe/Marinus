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
const censys = require('../config/models/censys.js');
const htmlEscape = require('secure-filters').html;
const CIDRMatcher = require('cidr-matcher');

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
 *   CensysRecord:
 *     type: object
 *     properties:
 *       ip:
 *         type: string
 *         example: 1.2.2.3
 *         description: The IP that is the key to the record
 *       zones:
 *         type: array
 *         example: ["example.org", "example.net"]
 *         description: The array of tracked zones
 *       domains:
 *         type: array
 *         example: ["www.example.org", "www.example.net"]
 *         description: An array of associated domains
 *       tags:
 *         type: array
 *         example: []
 *         description: An array of possible tags for additional information
 *       aws:
 *         type: boolean
 *         example: False
 *         description: A boolean indicating whether the IP is issued by AWS
 *       azure:
 *         type: boolean
 *         example: False
 *         description: A boolean indicating whether the IP is issued by Azure
 *       autonomous_system:
 *         type: object
 *         example: See the schema
 *         description: Fields related to autonomous systems such as ASN, routed_prefix, etc.
 *       metadata:
 *         type: object
 *         example: See the schema
 *         description: Metadata regarding the system such as os, manufacturer, etc.
 *       p21:
 *         type: object
 *         example: See the schema
 *         description: Fields related to FTP connections such as prompts, etc.
 *       p22:
 *         type: object
 *         example: See the schema
 *         description: Fields related to SSH connections such as crypotgraphic negotiations, etc.
 *       p23:
 *         type: object
 *         example: See the schema
 *         description: Fields related to telnet servers.
 *       p25:
 *         type: object
 *         example: See the schema
 *         description: Fields related to SMTP servers.
 *       p53:
 *         type: object
 *         example: See the schema
 *         description: Fields related to DNS servers
 *       p80:
 *         type: object
 *         example: See the schema
 *         description: Fields related to HTTP servers including HTTP headers, etc.
 *       p110:
 *         type: object
 *         example: See the schema
 *         description: Fields related to POP3 servers
 *       p143:
 *         type: object
 *         example: See the schema
 *         description: Fields related to IMAP servers
 *       p443:
 *         type: object
 *         example: See the schema
 *         description: Fields related to HTTPS servers including the TLS handshake, etc.
 *       p465:
 *         type: object
 *         example: See the schema
 *         description: Fields related to SMTPS servers including the TLS/SSL handshake, etc.
 *       p502:
 *         type: object
 *         example: See the schema
 *         description: Fields related to modbus servers
 *       p993:
 *         type: object
 *         example: See the schema
 *         description: Fields related to IMAPS servers
 *       p995:
 *         type: object
 *         example: See the schema
 *         description: Fields related to POP3S servers
 *       p7547:
 *         type: object
 *         example: See the schema
 *         description: Fields related to CWMP servers
 *       p47808:
 *         type: object
 *         example: See the schema
 *         description: Fields related to Bacnet servers
 *
 *
 *   HTTPHeaderResponse:
 *     type: object
 *     properties:
 *       p80:
 *         type: object
 *         properties:
 *           http:
 *             type: object
 *             properties:
 *               get:
 *                 type: object
 *                 properties:
 *                   headers:
 *                     type: object
 *                     description: The object representing the header name and value.
 *                     example: {"server": "Apache"}
 *       zones:
 *         type: array
 *         items:
 *           type: string
 *           description: The zones associated with this IP
 *           example: "example.org"
 *       ip:
 *         type: string
 *         description: The IP for the record
 *         example: "12.34.56.78"
 *
 *   HTTPUnknownHeaderResponse:
 *     type: object
 *     properties:
 *       p80:
 *         type: object
 *         properties:
 *           http:
 *             type: object
 *             properties:
 *               get:
 *                 type: object
 *                 properties:
 *                   headers:
 *                     type: object
 *                     properties:
 *                       unknown:
 *                         type: array
 *                         description: An array of unknown headers that includes, but is not limited to, the requested header.
 *                         example: {"mime_version": "1.0", "date": "Tue, 20 Mar 2018 14:56:30 GMT"}
 *       zones:
 *         type: array
 *         items:
 *           type: string
 *           description: The zones associated with this IP
 *           example: "example.org"
 *       ip:
 *         type: string
 *         description: The IP for the record
 *         example: "12.34.56.78"
 */
module.exports = function (envConfig) {
    /**
     * @swagger
     *
     * security:
     *   - APIKeyHeader: []
     *
     * tags:
     *   - name: Censys - Fetch IPs based on zone
     *     description: Fetch IP associated with the provided zone.
     *   - name: Censys - Count IPs based on zone
     *     description: Count IPs associated with the provided zone.
     *
     * /api/v1.0/censys/zones/{zone}:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Returns the Censys records associated with the provided zone (e.g. "example.org"). This works for hosts that have an HTTPS server.
     *     tags: [Censys - Fetch IPs based on zone]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: zone
     *         type: string
     *         required: true
     *         description: The zone ("example.org", "example.com", etc.) to fetch.
     *         in: path
     *     responses:
     *       200:
     *         description: Returns the Censys records for the relevant zone.
     *         type: array
     *         items:
     *           $ref: '#/definitions/CensysRecord'
     *       400:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       404:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/ResultsNotFound'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     *
     * /api/v1.0/censys/zones/{zone}?count=1:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Returns the Censys records associated with the provided zone (e.g. "example.org"). This works for hosts that have an HTTPS server.
     *     tags: [Censys - Count IPs based on zone]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: zone
     *         type: string
     *         required: true
     *         description: The zone ("example.org", "example.com", etc.) to fetch.
     *         in: path
     *       - name: count
     *         type: string
     *         required: true
     *         description: Set to 1 to get a zone-by-zone list of matched records.
     *         in: query
     *     responses:
     *       200:
     *         description: Returns the count of the Censys records for the relevant zone.
     *         type: object
     *         schema:
     *           $ref: '#/definitions/CountResponse'
     *       400:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       404:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/ResultsNotFound'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     */

    router.route('/censys/zones/:zone')
        // get info on a specific zones
        .get(function (req, res) {
            if (!(req.params.hasOwnProperty('zone'))) {
                res.status(400).json({ 'message': 'A zone must be provided.' });
                return;
            }

            let count = false;
            if (req.query.hasOwnProperty('count') && req.query.count === '1') {
                count = true
            }

            let promise = censys.getRecordsByZonePromise(zone, count);

            promise.then(function (data) {
                if (!data) {
                    res.status(404).json({ 'message': 'Zone not found' });
                    return;
                }
                if (req.query.type === 'count') {
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
     *   - name: Censys - Fetch IPs based on port
     *     description: Fetch the full records for any IP associated with the provided port.
     *   - name: Censys - Return only the relevant port information
     *     description: Fetch all records associated with the provided port but limit the response to the relevant port information.
     *   - name: Censys - Get IP list associated with the provided port
     *     description: Get the list of IPs associated with the provided port
     *   - name: Censys - Count IPs associated with the provided port
     *     description: Count the number of IP records associated with the provided port.
     *
     * /api/v1.0/censys/ports:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Returns the Censys records associated with the provided zone. This works for hosts that have an HTTPS server.
     *     tags: [Censys - Fetch IPs based on port]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: port
     *         type: string
     *         required: true
     *         description: The port for this query (e.g. 80, 443, etc.).
     *         in: query
     *     responses:
     *       200:
     *         description: Returns the Censys records for the relevant port.
     *         type: array
     *         items:
     *           $ref: '#/definitions/CensysRecord'
     *       400:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       404:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/ResultsNotFound'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     *
     * /api/v1.0/censys/ports?type=port_only:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Returns the Censys records associated with the provided zone. This works for hosts that have an HTTPS server.
     *     tags: [Censys - Return only the relevant port information]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: port
     *         type: string
     *         required: true
     *         description: The port for this query (e.g. 80, 443, etc.).
     *         in: query
     *       - name: type
     *         type: string
     *         required: true
     *         description: Set to "port_only" for this type of query
     *         in: query
     *       - name: ip
     *         type: string
     *         required: true
     *         description: Limit the results to this IP.
     *         in: query
     *     responses:
     *       200:
     *         description: Returns the information limited to the port in question. The "port" variable name in the example response would actually be "p" + port_number .
     *         type: array
     *         items:
     *           type: object
     *           properties:
     *             ip:
     *               type: string
     *               example: "1.1.1.1"
     *             port:
     *               type: object
     *               description: The name of the object would not be "port". It would be the letter "p"  plus the port number (e.g. "p80", "p443", etc.)
     *               example: See the schema
     *       400:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       404:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/ResultsNotFound'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     *
     * /api/v1.0/censys/ports?type=ip_only:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Returns the Censys records associated with the provided zone. This works for hosts that have an HTTPS server.
     *     tags: [Censys - Get IP list associated with the provided port]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: port
     *         type: string
     *         required: true
     *         description: The port for this query (e.g. 80, 443, etc.).
     *         in: query
     *       - name: type
     *         type: string
     *         required: true
     *         description: Set to "ip_only" for this type of query
     *         in: query
     *       - name: limit
     *         type: int
     *         required: false
     *         description: For large queries, limit the number of responses per page to the specified number.
     *         in: query
     *       - name: page
     *         type: int
     *         required: false
     *         description: For large queries, the page of data to the display from the limited response. Must be > 1.
     *         in: query
     *     responses:
     *       200:
     *         description: Returns the list of IPs that are associated with the provided port.
     *         type: array
     *         items:
     *           type: object
     *           properties:
     *             ip:
     *               type: string
     *               example: "1.1.1.1"
     *       400:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       404:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/ResultsNotFound'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     *
     * /api/v1.0/censys/ports?type=count:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Returns the Censys records associated with the provided zone. This works for hosts that have an HTTPS server.
     *     tags: [Censys - Count IPs associated with the provided port]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: port
     *         type: string
     *         required: true
     *         description: The port for this query (e.g. 80, 443, etc.).
     *         in: query
     *       - name: type
     *         type: string
     *         required: true
     *         description: Set to "count" for this type of query
     *         in: query
     *     responses:
     *       200:
     *         description: Returns the count of the Censys records for the relevant port.
     *         type: object
     *         schema:
     *           $ref: '#/definitions/CountResponse'
     *       400:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       404:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/ResultsNotFound'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     */
    router.route('/censys/ports')
        // get info on specific ports
        .get(function (req, res) {
            if (!(req.query.hasOwnProperty('port'))) {
                res.status(400).json({ 'message': 'A port must be provided.' });
                return;
            }

            let ip = null;
            if (req.query.hasOwnProperty('ip')) {
                ip = req.query.ip;
            }

            let qtype = '';
            if (req.query.hasOwnProperty('type')) {
                qtype = req.query.type;
            }

            let limit = 0;
            if (req.query.hasOwnProperty('limit')) {
                limit = req.query.limit;
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


            let promise;
            if (qtype === 'count') {
                promise = censys.getPortCountPromise(req.query.port);
            } else if (qtype === 'port_only') {
                promise = censys.getPortRecordsByPortPromise(req.query.port, ip);
            } else if (qtype === 'ip_only') {
                promise = censys.getIPListByPortPromise(req.query.port, limit, page);
            } else {
                promise = censys.getFullRecordsByPortPromise(req.query.port, ip);
            }

            promise.then(function (data) {
                if (!data) {
                    res.status(404).json({ 'message': 'Port not found' });
                    return;
                }
                if (req.query.type === 'count') {
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
     *   - name: Censys - Fetch individual IP record
     *     description: Fetch the full records for the associated IP address
     *   - name: Censys - Fetch records associated with an IP range
     *     description: Fetch the full records for the associated IP range.
     *   - name: Censys - Count records associated with an IP range
     *     description: Count the number of records within the associated IP range.
     *
     * /api/v1.0/censys/ips?range={range}:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Fetch the full records for the associated IP range
     *     tags: [Censys - Fetch records associated with an IP range]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: range
     *         type: string
     *         required: true
     *         description: The IP range for this query
     *         in: query
     *     responses:
     *       200:
     *         description: Returns the Censys records for the relevant IP range.
     *         type: array
     *         items:
     *           $ref: '#/definitions/CensysRecord'
     *       400:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       404:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/ResultsNotFound'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     *
     * /api/v1.0/censys/ips?range={range}&count=1:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Count the number of records for the associated IP range
     *     tags: [Censys - Count records associated with an IP range]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: range
     *         type: string
     *         required: true
     *         description: The IP range for this query
     *         in: query
     *       - name: count
     *         type: string
     *         required: true
     *         description: Set to one for this type of query
     *         in: query
     *     responses:
     *       200:
     *         description: Returns the count of the Censys records for the relevant IP range.
     *         type: object
     *         schema:
     *           $ref: '#/definitions/CountResponse'
     *       400:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       404:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/ResultsNotFound'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     *
     * /api/v1.0/censys/ips?ip={address}:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Fetch the full records for the associated IP address
     *     tags: [Censys - Fetch individual IP record]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: ip
     *         type: string
     *         required: true
     *         description: The IP address for this query
     *         in: query
     *     responses:
     *       200:
     *         description: Returns the Censys records for the relevant IP address.
     *         type: object
     *         schema:
     *           $ref: '#/definitions/CensysRecord'
     *       400:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       404:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/ResultsNotFound'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     */
    router.route('/censys/ips')
        // get info on a specific ip or range
        .get(function (req, res) {
            let promise;
            if (req.query.hasOwnProperty('range')) {
                let searchRange = createRange(req.query.range);
                if (searchRange.startsWith('Error')) {
                    res.status(400).json({ 'message': htmlEscape(searchRange) });
                    return;
                }
                let count = false;
                if (req.query.hasOwnProperty('count') && req.query.count === '1') {
                    count = true;
                }
                promise = censys.getRecordByIpRangePromise(searchRange);
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
                            returnData.push(rdata[i]);
                        }
                    }
                    if (count) {
                        res.status(200).json({ 'count': returnData.length });
                        return;
                    }
                    res.status(200).json(returnData);
                    return;
                });
                return;
            } else if (req.query.hasOwnProperty('ip')) {
                promise = censys.getRecordByIpPromise(req.query.ip);
            } else {
                res.status(400).json({
                    'message': 'An IP or IP Range must be provided.',
                });
                return;
            }

            promise.then(function (data) {
                if (!data) {
                    res.status(404).json({ 'message': 'IP not found' });
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
     *   - name: Censys - Fetch individual HTTP Header
     *     description: Fetch the full records for the associated HTTP Header
     *   - name: Censys - Count individual HTTP Headers
     *     description: Count the number of full records for the associated HTTP Header
     *   - name: Censys - Fetch individual Unknown HTTP Header
     *     description: Fetch the full records for the associated Unknown HTTP Header
     *   - name: Censys - Get distinct values
     *     description: Get the distinct values for the associated HTTP Header
     *   - name: Censys - Fetch individual HTTP Headers by value
     *     description: Fetch the full records for the associated HTTP Header values
     *   - name: Censys - Fetch individual Unknown HTTP Headers by value
     *     description: Fetch the full records for the associated Unknown HTTP Header values
     *
     * /api/v1.0/censys/headers/{header}:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Fetch the full records for the associated HTTP Header
     *     tags: [Censys - Fetch individual HTTP Header]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: header
     *         type: string
     *         required: true
     *         description: The header for this query
     *         in: path
     *       - name: zone
     *         type: string
     *         required: false
     *         description: Limit responses to only those for the provided zone (e.g. "example.org")
     *         in: query
     *     responses:
     *       200:
     *         description: Returns the Censys records for the relevant header limited to the requested header.
     *         type: array
     *         items:
     *           $ref: '#/definitions/HTTPHeaderResponse'
     *       400:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       404:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/ResultsNotFound'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     *
     * /api/v1.0/censys/headers/{header}?count=1:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Count the number of full records for the associated HTTP Header. This doesn't apply to Censys "unknown" records.
     *     tags: [Censys - Count individual HTTP Headers]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: header
     *         type: string
     *         required: true
     *         description: The header for this query
     *         in: path
     *       - name: zone
     *         type: string
     *         required: false
     *         description: Limit responses to only those for the provided zone (e.g. "example.org")
     *         in: query
     *       - name: header_type
     *         type: string
     *         required: false
     *         description: This must be set to "unknown" when searching an unknown header type
     *         in: query
     *       - name: count
     *         type: string
     *         required: true
     *         description: Must be set to one for this type of query
     *         in: query
     *     responses:
     *       200:
     *         description: Returns the count of the Censys records for the relevant header limited to the requested header.
     *         type: object
     *         schema:
     *           $ref: '#/definitions/CountResponse'
     *       400:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       404:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/ResultsNotFound'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     *
     * /api/v1.0/censys/headers/{header}?header_type=unknown:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Fetch the full records for the associated the Unknown HTTP Header. Censys only tracks certain headers by name and the rest are grouped under "Unknown".
     *     tags: [Censys - Fetch individual Unknown HTTP Header]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: header
     *         type: string
     *         required: true
     *         description: The header for this query
     *         in: path
     *       - name: header_type
     *         type: string
     *         required: true
     *         description: This must be set to "unknown" for this type of query
     *         in: query
     *       - name: zone
     *         type: string
     *         required: false
     *         description: Limit responses to only those for the provided zone (e.g. "example.org")
     *         in: query
     *     responses:
     *       200:
     *         description: Returns the Censys records for the relevant Unknown header limited to the requested header.
     *         type: array
     *         items:
     *           $ref: '#/definitions/HTTPUnknownHeaderResponse'
     *       400:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       404:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/ResultsNotFound'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     *
     * /api/v1.0/censys/headers/{header}?distinct=1:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Get the list of distinct values for the provided HTTP header.
     *     tags: [Censys - Get distinct values]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: header
     *         type: string
     *         required: true
     *         description: The header for this query
     *         in: path
     *       - name: distinct
     *         type: string
     *         required: true
     *         description: Must be set to 1 for this type of query
     *         in: query
     *       - name: header_type
     *         type: string
     *         required: false
     *         description: This must be set to "unknown" for this type of query
     *         in: query
     *       - name: zone
     *         type: string
     *         required: false
     *         description: Limit responses to only those for the provided zone (e.g. "example.org")
     *         in: query
     *     responses:
     *       200:
     *         description: Returns the distinct values for the relevant Unknown header limited to the requested header.
     *         type: array
     *         items:
     *           type: object
     *           properties:
     *             _id:
     *               type: string
     *               example: "UniqueHTTPHeaderValue1"
     *             count:
     *               type: number
     *               example: 1
     *       400:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       404:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/ResultsNotFound'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     *
     * /api/v1.0/censys/headers/{header}?value={value}:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Fetch the full records for the associated HTTP Header by value
     *     tags: [Censys - Fetch individual HTTP Headers by value]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: header
     *         type: string
     *         required: true
     *         description: The header for this query
     *         in: path
     *       - name: value
     *         type: string
     *         required: true
     *         description: Limit responses to only those for the provided value
     *         in: query
     *       - name: zone
     *         type: string
     *         required: false
     *         description: Limit responses to only those for the provided zone (e.g. "example.org")
     *         in: query
     *     responses:
     *       200:
     *         description: Returns the Censys records for the relevant header limited to the requested header value.
     *         type: array
     *         items:
     *           $ref: '#/definitions/HTTPHeaderResponse'
     *       400:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       404:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/ResultsNotFound'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     *
     * /api/v1.0/censys/headers/{header}?header_type=unknown&value={value}:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Fetch the full records for the associated HTTP Header value
     *     tags: [Censys - Fetch individual Unknown HTTP Headers by value]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: header
     *         type: string
     *         required: true
     *         description: The header for this query
     *         in: path
     *       - name: value
     *         type: string
     *         required: true
     *         description: Limit responses to only those for the provided value
     *         in: query
     *       - name: header_type
     *         type: string
     *         required: true
     *         description: This must be set to "unknown" for this type of query
     *         in: query
     *       - name: zone
     *         type: string
     *         required: false
     *         description: Limit responses to only those for the provided zone (e.g. "example.org")
     *         in: query
     *     responses:
     *       200:
     *         description: Returns the Censys records for the relevant header limited to the requested header value.
     *         type: array
     *         items:
     *           $ref: '#/definitions/HTTPHeaderResponse'
     *       400:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       404:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/ResultsNotFound'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     */
    router.route('/censys/headers/:header')
        // Retrieve information on headers
        .get(function (req, res) {
            if (!(req.params.hasOwnProperty('header'))) {
                res.status(400).json({
                    'message': 'A header value must be provided.',
                });
                return;
            }

            let header = req.params.header;

            if (header.includes(".")) {
                res.status(400).json({
                    'message': 'Headers can not contain periods.',
                });
                return;
            }

            let header_type = "known";
            if (req.query.hasOwnProperty("header_type") && req.query.header_type === "unknown") {
                header_type = "unknown";
            }

            let promise;
            let count = false;
            let zone = '';
            if (req.query.hasOwnProperty('zone') && req.query.zone !== '') {
                zone = req.query.zone;
            }

            if (req.query.hasOwnProperty('count') && req.query.count === '1') {
                if (header_type === "unknown") {
                    promise = censys.getUnknownHttpHeaderPromise(header, zone, true);
                } else {
                    promise = censys.getHttpHeaderPromise(header, zone, true);
                }
                count = true;
            } else if (req.query.hasOwnProperty('distinct') &&
                req.query.distinct === '1') {
                if (header_type === "unknown") {
                    promise = censys.getDistinctUnknownHttpHeaderPromise(header, zone);
                } else {
                    promise = censys.getDistinctHttpHeaderPromise(header, zone);
                }
            } else if (req.query.hasOwnProperty('value')) {
                if (header_type === "unknown") {
                    promise = censys.getUnknownHttpHeaderByValuePromise(header, req.query.value, zone);
                } else {
                    promise = censys.getHttpHeaderByValuePromise(header, req.query.value, zone);
                }
            } else {
                if (header_type === "unknown") {
                    promise = censys.getUnknownHttpHeaderPromise(header, zone, false);
                } else {
                    promise = censys.getHttpHeaderPromise(header, zone, false);
                }
            }
            promise.then(function (data) {
                if (!data || data.length === 0) {
                    res.status(404).json({ 'message': 'Header not found' });
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
     *   - name: Censys - Fetch TLS certificate by algorithm
     *     description: Fetch the full records for the associated TLS certificate algorithm (p443)
     *   - name: Censys - Count TLS certificates by algorithm
     *     description: Count the number of records with the associated TLS certificates by algorithm (p443)
     *
     * /api/v1.0/censys/algorithm/{algorithm}:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Fetch the full records for the associated HTTP Header
     *     tags: [Censys - Fetch TLS certificate by algorithm]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: algorithm
     *         type: string
     *         required: true
     *         description: The algorithm used by the TLS certificate
     *         in: path
     *       - name: zone
     *         type: string
     *         required: false
     *         description: Limit responses to only those for the provided zone (e.g. "example.org")
     *         in: query
     *     responses:
     *       200:
     *         description: Returns the Censys records for the relevant TLS certificate algorithm.
     *         type: array
     *         items:
     *           type: object
     *           properties:
     *             ip:
     *               type: string
     *               example: "12.23.34.56"
     *             p443:
     *               type: object
     *               properties:
     *                 https:
     *                   type: object
     *                   properties:
     *                     tls:
     *                       type: object
     *                       properties:
     *                         certificate:
     *                           type: object
     *                           example: See the schema
     *                         validation:
     *                           type: object
     *                           properties:
     *                             browser_error:
     *                               type: string
     *                               example: "A browser error for the certificate validation"
     *                             browser_trusted:
     *                               type: boolean
     *                               example: False
     *       400:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       404:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/ResultsNotFound'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     *
     * /api/v1.0/censys/algorithm/{algorithm}?count=1:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Count the number of records with the associated TLS certificates by algorithm (p443)
     *     tags: [Censys - Count TLS certificates by algorithm]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: algorithm
     *         type: string
     *         required: true
     *         description: The algorithm used by the TLS certificate
     *         in: path
     *       - name: count
     *         type: string
     *         required: true
     *         description: Must be set to "1" for this type of query
     *         in: query
     *       - name: zone
     *         type: string
     *         required: false
     *         description: Limit responses to only those for the provided zone (e.g. "example.org")
     *         in: query
     *     responses:
     *       200:
     *         description: Returns the Censys records for the relevant TLS certificate algorithm.
     *         type: array
     *         items:
     *           $ref: '#/definitions/CountResponse'
     *       400:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       404:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/ResultsNotFound'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     *
     */
    router.route('/censys/algorithm/:algorithm')
        // get info on a specific algorithm
        .get(function (req, res) {
            if (!(req.params.hasOwnProperty('algorithm')) ||
                req.params.algorithm.length === 0) {
                res.status(400).json({ 'message': 'An algorithm must be provided.' });
                return;
            }
            let count = false;
            if (req.query.hasOwnProperty('count') && req.query.count === '1') {
                count = true;
            }

            let promise;
            if (req.query.hasOwnProperty('zone')) {
                promise = censys.getSSLAlgorithmByZonePromise(req.params.algorithm, req.query.zone, count);
            } else {
                promise = censys.getSSLAlgorithmPromise(req.params.algorithm, count);
            }
            promise.then(function (data) {
                if (!data || data.length === 0) {
                    res.status(404).json({ 'message': 'Algorithm not found' });
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
     *   - name: Censys - Fetch certificate by TLS value
     *     description: Fetch the full records for the associated TLS value  (p443)
     *   - name: Censys - Fetch TLS certificates by common name
     *     description: Fetch the full records for the associated TLS common name (p443)
     *   - name: Censys - Count the records with the associated TLS value
     *     description: Count the number of records for the associated TLS value (p443)
     *
     * /api/v1.0/censys/certs:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Fetch the full records for the associated TLS values (p443). One of the optional values must be provided.
     *     tags: [Censys - Fetch certificate by TLS value]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: zone
     *         type: string
     *         required: false
     *         description: Limit responses to only those for the provided zone (e.g. "example.org")
     *         in: query
     *       - name: org
     *         type: string
     *         required: false
     *         description: Limit responses to only those for the provided org (e.g. "Acme Inc.")
     *         in: query
     *       - name: serial_number
     *         type: string
     *         required: false
     *         description: Limit responses to only those for the provided serial_number
     *         in: query
     *       - name: fingerprint_sha1
     *         type: string
     *         required: false
     *         description: Limit responses to only those for the provided SHA1 fingerprint
     *         in: query
     *       - name: fingerprint_sha256
     *         type: string
     *         required: false
     *         description: Limit responses to only those for the provided SHA256 fingerprint
     *         in: query
     *     responses:
     *       200:
     *         description: Returns the Censys records for the relevant TLS value.
     *         type: array
     *         items:
     *           $ref: '#/definitions/CensysRecord'
     *       400:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       404:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/ResultsNotFound'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     *
     * /api/v1.0/censys/certs?common_name={common_name}:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Fetch the full records for the associated TLS Common Name (p443)
     *     tags: [Censys - Fetch TLS certificates by common name]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: common_name
     *         type: string
     *         required: true
     *         description: Limit responses to only those for the provided common_name
     *         in: query
     *     responses:
     *       200:
     *         description: Returns the Censys records for the relevant TLS common name.
     *         type: array
     *         items:
     *           type: object
     *           properties:
     *             ip:
     *               type: string
     *               example: "12.23.34.56"
     *             p443:
     *               type: object
     *               example: "See the schema"
     *       400:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       404:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/ResultsNotFound'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     *
     * /api/v1.0/censys/certs?count=1:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Count the full records for the associated TLS value (p443)
     *     tags: [Censys - Count the records with the associated TLS value]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: count
     *         type: string
     *         required: true
     *         description: Must be set to "1" for this type of query
     *         in: query
     *       - name: zone
     *         type: string
     *         required: false
     *         description: Limit responses to only those for the provided zone (e.g. "example.org")
     *         in: query
     *       - name: org
     *         type: string
     *         required: false
     *         description: Limit responses to only those for the provided org (e.g. "Acme Inc.")
     *         in: query
     *       - name: serial_number
     *         type: string
     *         required: false
     *         description: Limit responses to only those for the provided serial_number
     *         in: query
     *       - name: fingerprint_sha1
     *         type: string
     *         required: false
     *         description: Limit responses to only those for the provided SHA1 fingerprint
     *         in: query
     *       - name: fingerprint_sha256
     *         type: string
     *         required: false
     *         description: Limit responses to only those for the provided SHA256 fingerprint
     *         in: query
     *     responses:
     *       200:
     *         description: Count the Censys records for the relevant TLS certificate value.
     *         type: object
     *         schema:
     *           $ref: '#/definitions/CountResponse'
     *       400:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       404:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/ResultsNotFound'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     */
    router.route('/censys/certs')
        // get info on a specific domain
        .get(function (req, res) {
            let promise;
            if (req.query.hasOwnProperty('org')) {
                let org = req.query.org;

                if (req.query.hasOwnProperty('count') && req.query.count === '1') {
                    promise = censys.getSSLOrgCountPromise(org);
                } else {
                    promise = censys.getRecordsBySSLOrgPromise(org);
                }
            } else if (req.query.hasOwnProperty('common_name')) {
                promise = censys.getSSLByCommonNamePromise(req.query.common_name);
            } else if (req.query.hasOwnProperty('zone')) {
                if (req.query.hasOwnProperty('count') && req.query.count === '1') {
                    promise = censys.getSSLByZonePromise(req.query.zone, true);
                } else {
                    promise = censys.getSSLByZonePromise(req.query.zone, false);
                }
            } else if (req.query.hasOwnProperty('serial_number')) {
                if (req.query.hasOwnProperty('count') && req.query.count === '1') {
                    promise = censys.getRecordsBySSLSerialNumberPromise(req.query.serial_number, true);
                } else {
                    promise = censys.getRecordsBySSLSerialNumberPromise(req.query.serial_number, false);
                }
            } else if (req.query.hasOwnProperty('fingerprint_sha1')) {
                if (req.query.hasOwnProperty('count') && req.query.count === '1') {
                    promise = censys.getRecordsBySSLFingerprintPromise(req.query.fingerprint_sha1, true);
                } else {
                    promise = censys.getRecordsBySSLFingerprintPromise(req.query.fingerprint_sha1, false);
                }
            } else if (req.query.hasOwnProperty('fingerprint_sha256')) {
                if (req.query.hasOwnProperty('count') && req.query.count === '1') {
                    promise = censys.getRecordsBySSL256FingerprintPromise(req.query.fingerprint_sha256, true);
                } else {
                    promise = censys.getRecordsBySSL256FingerprintPromise(req.query.fingerprint_sha256, false);
                }
            } else {
                res.status(400);
                res.json({ 'message': 'An org or a common_name must be provided' });
                return;
            }

            promise.then(function (data) {
                if (!data) {
                    res.status(404).json({ 'message': 'Cert not found' });
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
     *   - name: Censys - Fetch certificates for the internal domain
     *     description: Fetch the full records for the associated internal domain
     *
     * /api/v1.0/censys/corp_certs:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Fetch the full records for the internal domain specified in the config file.
     *     tags: [Censys - Fetch certificates for the internal domain]
     *     produces:
     *       - application/json
     *     responses:
     *       200:
     *         description: Returns the Censys records for the internal domain specified in the config file.
     *         type: array
     *         items:
     *           type: object
     *           properties:
     *             ip:
     *               type: string
     *               example: "12.23.34.56"
     *             p443:
     *               type: object
     *               example: "See the schema"
     *       400:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       404:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/ResultsNotFound'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     */
    router.route('/censys/corp_certs')
        // get info on corporate certs
        .get(function (req, res) {
            let promise = censys.getSSLByCorpNamePromise(envConfig.internalDomain);

            promise.then(function (data) {
                if (!data) {
                    res.status(404).json({ 'message': 'Records not found' });
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
     *   - name: Censys - Fetch the list of certificate CA values
     *     description: Fetch the list of Certificate Authority values from the certificates
     *
     * /api/v1.0/censys/cert_ca:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Fetch the list of certificate Certificate Authority values
     *     tags: [Censys - Fetch the list of certificate CA values]
     *     produces:
     *       - application/json
     *     responses:
     *       200:
     *         description: Returns the array of Certificate Authority values form the certificates on port 443.
     *         type: array
     *         items:
     *           type: string
     *           example: "DigiCert Assured ID Root CA"
     *       400:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       404:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/ResultsNotFound'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     */
    router.route('/censys/cert_ca')
        // Get unique CA values from chain[0]
        .get(function (req, res) {
            let promise = censys.getCAIssuersListPromise();

            promise.then(function (data) {
                if (!data) {
                    res.status(500).json({ 'message': 'Error retrieving CA List' });
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
     *   - name: Censys - Fetch certificate by TLS CA value
     *     description: Fetch the full records for the associated TLS Certificate Authority value  (p443)
     *   - name: Censys - Count the records with the associated TLS CA value
     *     description: Count the number of records for the associated TLS Certificate Authority value (p443)
     *
     * /api/v1.0/censys/cert_ca/{cert_ca}:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description:   Fetch the full records for the associated TLS values (p443). One of the optional values must be provided.
     *     tags: [Censys - Fetch certificate by TLS value]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: cert_ca
     *         type: string
     *         required: true
     *         description: The URL escaped certificate authority value
     *         in: path
     *       - name: limit
     *         type: number
     *         required: false
     *         description: Limit the number of matching records to the provided value
     *         in: query
     *     responses:
     *       200:
     *         description: Returns the Censys records for the relevant TLS CA value.
     *         type: array
     *         items:
     *           $ref: '#/definitions/CensysRecord'
     *       400:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       404:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/ResultsNotFound'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     *
     * /api/v1.0/censys/cert_ca/{cert_ca}?count=1:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Count the full records for the associated TLS value (p443)
     *     tags: [Censys - Count the records with the associated TLS value]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: cert_ca
     *         type: string
     *         required: true
     *         description: The URL escaped certificate authority value
     *         in: path
     *       - name: count
     *         type: string
     *         required: true
     *         description: Must be set to "1" for this type of query
     *         in: query
     *     responses:
     *       200:
     *         description: Count the Censys records for the relevant TLS certificate CA value.
     *         type: object
     *         schema:
     *           $ref: '#/definitions/CountResponse'
     *       400:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       404:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/ResultsNotFound'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     */
    router.route('/censys/cert_ca/:ca')
        // Get records for an individual CA
        .get(function (req, res) {
            if (!(req.params.hasOwnProperty('ca'))) {
                res.status(400).json({ 'message': 'A CA value must be provided.' });
                return;
            }

            let promise;
            let count = false;
            let ca = unescape(req.params.ca);
            let limit = 0;
            if (req.query.hasOwnProperty('limit')) {
                limit = parseInt(req.query.limit);
            }

            if (req.query.hasOwnProperty('count') && req.query.count === '1') {
                count = true;
                promise = censys.getRecordsBySSLCAPromise(ca, true, limit);
            } else {
                promise = censys.getRecordsBySSLCAPromise(ca, false, limit);
            }

            promise.then(function (data) {
                if (!data) {
                    res.status(404).json({ 'message': 'CA not found' });
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
     *   - name: Censys - Fetch certificates that expired in 200x
     *     description: Fetch the records where the TLS certificate expired in 200x
     *
     * /api/v1.0/censys/expired_certs_2k:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Fetch the TLS ecords where the certificate expired in 200x.
     *     tags: [Censys - Fetch certificates that expired in 200x]
     *     produces:
     *       - application/json
     *     responses:
     *       200:
     *         description: Returns the Censys records for the internal domain specified in the config file.
     *         type: array
     *         items:
     *           type: object
     *           properties:
     *             ip:
     *               type: string
     *               example: "12.23.34.56"
     *             p443:
     *               type: object
     *               example: "See the schema"
     *       400:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       404:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/ResultsNotFound'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     */
    router.route('/censys/expired_certs_2k')
        // get info on expired certs
        .get(function (req, res) {
            let promise = censys.getSSLByValidity2kPromise();

            promise.then(function (data) {
                if (!data) {
                    res.status(404).json({ 'message': 'Data not found' });
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
     *   - name: Censys - Fetch certificates that expired in the given year
     *     description: Fetch the records where the TLS certificate expired in the provided year
     *
     * /api/v1.0/censys/expired_certs_by_year:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Fetch the TLS ecords where the certificate expired in 200x.
     *     tags: [Censys - Fetch certificates that expired in the given year]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: year
     *         type: string
     *         required: true
     *         description: This is intended to be a year value but it can also be a year plus month and/or day (e.g. "2018-01-01")
     *         in: path
     *     responses:
     *       200:
     *         description: Returns the Censys records for the internal domain specified in the config file.
     *         type: array
     *         items:
     *           type: object
     *           properties:
     *             ip:
     *               type: string
     *               example: "12.23.34.56"
     *             p443:
     *               type: object
     *               example: "See the schema"
     *       400:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       404:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/ResultsNotFound'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     */
    router.route('/censys/expired_certs_by_year')
        // get info on expired certs
        .get(function (req, res) {
            if (!(req.query.hasOwnProperty('year'))) {
                res.status(400).json({ 'message': 'A year must be provided.' });
                return;
            } else if (req.query.year.match(/^[0-9\-]+$/) == null) {
                res.status(400).json({ 'message': 'A valid year must be provided.' });
                return;
            }

            let promise = censys.getSSLByValidityYearPromise(req.query.year);

            promise.then(function (data) {
                if (!data || data.length === 0) {
                    res.status(404).json({ 'message': 'Data not found' });
                    return;
                }

                let results = [];
                let today = new Date();
                let thisYear = today.getFullYear().toString();
                let test = data[0]['p443']['https']['tls']['certificate']['parsed']['validity']['end'].startsWith(thisYear);
                for (let i = 0; i < data.length; i++) {
                    // For the current year, only include certificates that expired before today
                    if (test) {
                        let tempDate = new Date(data[i]['p443']['https']['tls']['certificate']['parsed']['validity']['end']);
                        if (tempDate < today) {
                            results.push(data[i]);
                        }
                    } else {
                        results.push(data[i]);
                    }
                }
                res.status(200).json(results);
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
     *   - name: Censys - Fetch records the Heartbleed vulnerability has been flagged
     *     description: Fetch the full records the Heartbleed vulnerability has been flagged by Censys
     *   - name: Censys - Count records the Heartbleed vulnerability has been flagged
     *     description: Count the records the Heartbleed vulnerability has been flagged by Censys
     *
     * /api/v1.0/censys/heartbleed:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Fetch records the Heartbleed vulnerability has been flagged by Censys
     *     tags: [Censys - Fetch records the Heartbleed vulnerability has been flagged]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: org
     *         type: string
     *         required: false
     *         description: The organization value associated with the TLS certificate
     *         in: query
     *     responses:
     *       200:
     *         description: Returns the relevant Censys heartbleed records.
     *         type: array
     *         items:
     *           $ref: '#/definitions/CensysRecord'
     *       400:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       404:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/ResultsNotFound'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     *
     * /api/v1.0/censys/heartbleed?count=1:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Count the records where the Heartbleed vulnerability has been flagged by Censys
     *     tags: [Censys - Count records the Heartbleed vulnerability has been flagged]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: count
     *         type: string
     *         required: true
     *         description: Must be set to "1" for this type of query
     *         in: query
     *       - name: org
     *         type: string
     *         required: false
     *         description: The organization value associated with the TLS certificate
     *         in: query
     *     responses:
     *       200:
     *         description: Count the Censys records for the relevant TLS certificate CA value.
     *         type: object
     *         schema:
     *           $ref: '#/definitions/CountResponse'
     *       400:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       404:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/ResultsNotFound'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     */
    router.route('/censys/heartbleed')
        .get(function (req, res) {
            let org;
            if (req.query.hasOwnProperty('org')) {
                org = req.query.org;
            } else {
                org = null;
            }
            let promise;
            if (req.query.hasOwnProperty('count') && req.query.count === '1') {
                promise = censys.getSSLHeartbleedPromise(org, true);
            } else {
                promise = censys.getSSLHeartbleedPromise(org, false);
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
     * @swagger
     *
     * security:
     *   - APIKeyHeader: []
     *
     * tags:
     *   - name: Censys - Count the records using the provided TLS protocol
     *     description: Count the records using the provided TLS protocol
     *
     * /api/v1.0/censys/protocol_count:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Count the records using the provided TLS protocol
     *     tags: [Censys - Count the records using the provided TLS protocol]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: protocol
     *         type: string
     *         required: true
     *         description: The TLS protocol ("ssl_2", "ssl_3", "tls", "dhe", "dhe_export", "rsa_export")
     *         in: query
     *     responses:
     *       200:
     *         description: Count the Censys records for the relevant TLS protocol.
     *         type: object
     *         schema:
     *           $ref: '#/definitions/CountResponse'
     *       400:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       404:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/ResultsNotFound'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     */
    router.route('/censys/protocol_count')
        .get(function (req, res) {
            let promise;
            if (req.query.hasOwnProperty('protocol') &&
                ((req.query.protocol === 'ssl_2') ||
                    (req.query.protocol === 'ssl_3') ||
                    (req.query.protocol === 'tls') ||
                    (req.query.protocol === 'dhe') ||
                    (req.query.protocol === 'dhe_export') ||
                    (req.query.protocol === 'rsa_export'))) {
                promise = censys.getSSLProtocolCountPromise(req.query.protocol);
            } else {
                res.status(400).json({
                    'message': 'A protocol (ssl_2,ssl_3,dhe,dhe_export,rsa_export, or tls) must be specified',
                });
                return;
            }

            promise.then(function (data) {
                if (!data) {
                    res.status(404).json({ 'message': 'Data not found' });
                    return;
                }
                res.status(200).json({ 'count': data });
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
     *   - name: Censys - Count the records associated with the internal domain
     *     description: Count the records associated with the internal domain
     *
     * /api/v1.0/censys/corp_ssl_count:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Count the records associated with the internal domain specified in the config file
     *     tags: [Censys - Count the records associated with the internal domain]
     *     produces:
     *       - application/json
     *     responses:
     *       200:
     *         description: Count the Censys records associated with the specified internal domain.
     *         type: object
     *         schema:
     *           $ref: '#/definitions/CountResponse'
     *       404:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/ResultsNotFound'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     */
    router.route('/censys/corp_ssl_count')
        .get(function (req, res) {
            let promise = censys.getCorpSSLCountPromise(envConfig.internalDomain);
            promise.then(function (data) {
                if (!data) {
                    res.status(404).json({ 'message': 'Data not found' });
                    return;
                }
                res.status(200).json({ 'count': data });
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
     *   - name: Censys - Count the total number of Censys records
     *     description: Count the total number of Censys records
     *
     * /api/v1.0/censys/total_count:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Count the total number of Censys records
     *     tags: [Censys - Count the total number of Censys records]
     *     produces:
     *       - application/json
     *     responses:
     *       200:
     *         description: Count the Censys records associated with the specified internal domain.
     *         type: object
     *         schema:
     *           $ref: '#/definitions/CountResponse'
     *       404:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/ResultsNotFound'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     */
    router.route('/censys/total_count')
        .get(function (req, res) {
            let promise = censys.getFullCountPromise();
            promise.then(function (data) {
                if (!data) {
                    res.status(404).json({ 'message': 'Data not found' });
                    return;
                }
                res.status(200).json({ 'count': data });
                return;
            });
        });

    return (router);
};
