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

var zgrab443 = require('../config/models/zgrab_443_data');
var zgrab80 = require('../config/models/zgrab_80_data');
var zgrabPort = require('../config/models/zgrab_port');

function reformatResponse(results) {
    /**
     * Handles recursive searches where a MongoDB project command was necessary
     */
    let new_response = [];

    for (let i = 0; i < results.length; i++) {
        let new_data = {};
        new_data['domain'] = results[i]['domain'];
        new_data['ip'] = results[i]['ip'];
        new_data['_id'] = results[i]['_id'];
        new_data['data'] = {};
        new_data['data']['http'] = {};
        new_data['data']['http']['response'] = results[i]['data']['http'][0];
        new_response.push(new_data);
    }
    return (new_response);
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
 *   HTTPScanResponse:
 *     type: object
 *     properties:
 *       data:
 *         type: object
 *         properties:
 *           http:
 *             type: object
 *             properties:
 *                description:
 *                  type: string
 *                  example: "The rest of the schema is extremely complex and described here: https://github.com/zmap/zgrab/blob/master/zgrab_schema.py"
 *       domain:
 *         type: string
 *         example: www.example.org
 *       ip:
 *         type: string
 *         example: 19.5.1.10
 *       error:
 *         type: string
 *         example: "unable to connect"
 *       tracked:
 *         type: boolean
 *         example: true
 *       aws:
 *         type: boolean
 *         example: true
 *       azure:
 *         type: boolean
 *         example: true
 *       zones:
 *         type: array
 *         items:
 *           type: string
 *           example: example.org
 *       timestamp:
 *         type: string
 *         example: 2018-07-22T11:00:32.821Z
 *
 *   HTTPSScanResponse:
 *     type: object
 *     properties:
 *       data:
 *         type: object
 *         properties:
 *           https:
 *             type: object
 *             properties:
 *                description:
 *                  type: string
 *                  example: "The schema is extremely complex and described here: https://github.com/zmap/zgrab/blob/master/zgrab_schema.py"
 *       domain:
 *         type: string
 *         example: www.example.org
 *       ip:
 *         type: string
 *         example: 19.5.1.10
 *       error:
 *         type: string
 *         example: "unable to connect"
 *       tracked:
 *         type: boolean
 *         example: true
 *       aws:
 *         type: boolean
 *         example: true
 *       azure:
 *         type: boolean
 *         example: true
 *       zones:
 *         type: array
 *         items:
 *           type: string
 *           example: example.org
 *       timestamp:
 *         type: string
 *         example: 2018-07-22T11:00:32.821Z
 *
 *
 *   HTTPHeaderResponse:
 *     type: array
 *     items:
 *       type: object
 *       properties:
 *         domain:
 *           type: string
 *           example: "www.example.org"
 *         ip:
 *           type: string
 *           example: "<nil>"
 *         zones:
 *           type: array
 *           items:
 *             type: string
 *             example: "example.org"
 *         data:
 *           type: object
 *           properties:
 *             http:
 *               type: object
 *               properties:
 *                 response:
 *                   type: object
 *                   properties:
 *                     headers:
 *                       type: object
 *                       properties:
 *                         additionalProperties:
 *                           type: array
 *                           items:
 *                             type: string
 *                             example: "{The header value}"
 *
 *   HTTPCertificateResponse:
 *     type: array
 *     items:
 *       type: object
 *       properties:
 *         domain:
 *           type: string
 *           example: "www.example.org"
 *         ip:
 *           type: string
 *           example: "<nil>"
 *         data:
 *           type: object
 *           properties:
 *             http:
 *               type: object
 *               properties:
 *                  result:
 *                    type: object
 *                    properties:
 *                        response:
 *                          type: object
 *                          properties:
 *                            request:
 *                              type: object
 *                              properties:
 *                                tls_log:
 *                                  type: object
 *                                  properties:
 *                                    handshake_log:
 *                                      type: object
 *                                      properties:
 *                                        server_certificates:
 *                                          type: object
 *                                          properties:
 *                                            certificate:
 *                                              type: object
 *                                              properties:
 *                                                validation:
 *                                                type: object
 *
 * 
 *   HTTPSZoneList:
 *     type: array
 *     items:
 *       type: object
 *       properties:
 *         zone:
 *           type: string
 *           example: adobe.com
 *         count:
 *           type: int
 *           example: 5
 *                           
 */

module.exports = function (envConfig) {

    // Zgrab 2.0 support
    if (envConfig.hasOwnProperty("zgrabVersion") && envConfig.zgrabVersion == 2) {
        zgrab443 = require('../config/models/zgrab2_443_data');
        zgrab80 = require('../config/models/zgrab2_80_data');
        zgrabPort = require('../config/models/zgrab2_port');
    }


    /**
      * @swagger
      *
      * security:
      *   - APIKeyHeader: []
      *
      * tags:
      *   - name: Port scans - Fetch IP port data
      *     description: Fetch data for a specific IP address.
      *   - name: Port scans - Count IP port data
      *     description: Count data for a specific IP address.
      *
      * /api/v1.0/zgrab/ip:
      *   get:
      *   # Operation-specific security:
      *     security:
      *       - APIKeyHeader: []
      *     description: Returns the port data for the provided IP.
      *     tags: [Port scans - Fetch IP port data]
      *     produces:
      *       - application/json
      *     parameters:
      *       - name: ip
      *         type: string
      *         required: true
      *         description: The IP for this request.
      *         in: query
      *       - name: port
      *         type: int
      *         required: false
      *         description: The port for this request.
      *         in: query
      *       - name: use_port_data
      *         type: int
      *         required: false
      *         description: Set to 1 to override the use zgrab_(443|80) collections
      *         in: query
      *     responses:
      *       200:
      *         description: Returns the relevant set or subset of IPs.
      *         type: array
      *         items:
      *           type: object
      *           properties:
      *             ip:
      *               type: string
      *               example: "8.8.8.8"
      *             data:
      *               type: object
      *               description: Data on known ports for the IP. See the schema.
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
      * /api/v1.0/zgrab/ip?count=1:
      *   get:
      *   # Operation-specific security:
      *     security:
      *       - APIKeyHeader: []
      *     description: Returns whether there is port data for the provided IP and port.
      *     tags: [Port scans - Count IP port data]
      *     produces:
      *       - application/json
      *     parameters:
      *       - name: count
      *         type: int
      *         required: true
      *         description: Set to 1 for this request.
      *         in: query
      *       - name: ip
      *         type: string
      *         required: true
      *         description: The IP for this request.
      *         in: query
      *       - name: port
      *         type: int
      *         required: false
      *         description: The port for this request.
      *         in: query
      *       - name: use_port_data
      *         type: int
      *         required: false
      *         description: Set to 1 to override the use zgrab port specific collections
      *         in: query
      *     responses:
      *       200:
      *         description: Returns the relevant set or subset of IPs.
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
    router.route('/zgrab/ip')
        // get the port data for the provided IP.
        .get(function (req, res) {

            if (!is_valid_strings(req.query)) {
                res.status(400).json({ 'message': 'Multiple query parameters are not allowed.' });
                return;
            }

            if (!(req.query.hasOwnProperty('ip'))) {
                res.status(400).json({ 'message': 'An IP must be provided' });
                return;
            }

            let count = false;
            if (req.query.hasOwnProperty('count') && req.query.count === '1') {
                count = true;
            }

            let port = null;
            if (req.query.hasOwnProperty('port')) {
                port = req.query.port;
            }

            let promise;
            if (port === "22" || port === "25" || port === "465") {
                promise = zgrabPort.getRecordByIPPromise(req.query.ip, port, count);
            } else if (port === "443" && req.query.hasOwnProperty("use_port_data") && req.query.use_port_data === "1") {
                promise = zgrabPort.getRecordByIPPromise(req.query.ip, port, count);
            } else if (port === "443") {
                promise = zgrab443.getRecordByIPPromise(req.query.ip, count);
            } else if (port === "80") {
                promise = zgrab80.getRecordByIPPromise(req.query.ip, count);
            } else {
                promise = zgrabPort.getRecordByIPPromise(req.query.ip, null, count);
            }

            promise.then(function (data) {
                if (count && (port === "22" || port === "25" || port === "465")) {
                    res.status(200).json({ 'count': data.length });
                } else if (count && port === "443" && req.query.use_port_data === "1") {
                    res.status(200).json({ 'count': data.length });
                } else if (count) {
                    res.status(200).json({ 'count': data });
                } else {
                    if (!data) {
                        res.status(404).json({ 'message': 'IP not found' });
                        return;
                    }
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
      *   - name: Port scans - Fetch domain port data
      *     description: Fetch data for a specific domain name.
      *   - name: Port scans - Count domain port data
      *     description: Count data for a specific domain name.
      *
      * /api/v1.0/zgrab/domain:
      *   get:
      *   # Operation-specific security:
      *     security:
      *       - APIKeyHeader: []
      *     description: Returns the port data for the provided domain.
      *     tags: [Port scans - Fetch domain port data]
      *     produces:
      *       - application/json
      *     parameters:
      *       - name: domain
      *         type: string
      *         required: true
      *         description: The domain for this request.
      *         in: query
      *       - name: port
      *         type: int
      *         required: false
      *         description: The port for this request.
      *         in: query
      *       - name: use_port_data
      *         type: int
      *         required: false
      *         description: Set to 1 to override the use zgrab port specific collections
      *         in: query
      *     responses:
      *       200:
      *         description: Returns the relevant set or subset of domains.
      *         type: array
      *         items:
      *           type: object
      *           properties:
      *             domain:
      *               type: string
      *               example: "www.example.org"
      *             data:
      *               type: object
      *               description: Data on known ports for the domain. See the schema.
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
      * /api/v1.0/zgrab/domain?count=1:
      *   get:
      *   # Operation-specific security:
      *     security:
      *       - APIKeyHeader: []
      *     description: Returns whether there is port data for the provided domain and port.
      *     tags: [Port scans - Count domain port data]
      *     produces:
      *       - application/json
      *     parameters:
      *       - name: count
      *         type: int
      *         required: true
      *         description: Set to 1 for this request.
      *         in: query
      *       - name: domain
      *         type: string
      *         required: true
      *         description: The domain for this request.
      *         in: query
      *       - name: port
      *         type: int
      *         required: false
      *         description: The port for this request.
      *         in: query
      *       - name: use_port_data
      *         type: int
      *         required: false
      *         description: Set to 1 to override the use zgrab_(443|80) collections
      *         in: query
      *     responses:
      *       200:
      *         description: Returns the relevant domains.
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
    router.route('/zgrab/domain')
        // get the port data for the provided IP.
        .get(function (req, res) {

            if (!is_valid_strings(req.query)) {
                res.status(400).json({ 'message': 'Multiple query parameters are not allowed.' });
                return;
            }

            if (!(req.query.hasOwnProperty('domain'))) {
                res.status(400).json({ 'message': 'A domain must be provided' });
                return;
            }

            let port = null;
            if (req.query.hasOwnProperty('port')) {
                port = req.query.port;
            }

            if (port != null && !(["22", "25", "80", "443", "465"].includes(port))) {
                res.status(400).json({ 'message': 'Only ports 22, 25, 80, 443, and 465 are supported.' });
                return;
            }

            let count = false;
            if (req.query.hasOwnProperty('count') && req.query.count === '1') {
                count = true;
            }

            let promise;
            if (port === "22" || port === "25" || port === "465") {
                promise = zgrabPort.getRecordByDomainPromise(req.query.domain, port, count);
            } else if (port === "443" && req.query.hasOwnProperty("use_port_data") && req.query.use_port_data === "1") {
                promise = zgrabPort.getRecordByDomainPromise(req.query.domain, port, count);
            } else if (port === "443") {
                promise = zgrab443.getSSLByCommonNamePromise(req.query.domain, false);
            } else if (port === "80") {
                promise = zgrab80.getRecordByDomainPromise(req.query.domain, count);
            } else {
                promise = zgrabPort.getRecordByDomainPromise(req.query.domain, null, count);
            }

            promise.then(function (data) {
                if (count && port === "443" && req.query.use_port_data !== "1") {
                    res.status(200).json({ 'count': data.length });
                } else if (count) {
                    res.status(200).json({ 'count': data });
                } else {
                    if (!data) {
                        res.status(404).json({ 'message': 'Domain not found' });
                        return;
                    }
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
     *   - name: Port scans - Fetch zone port data
     *     description: Fetch data for a specific zone.
     *   - name: Port scans - Count zone port data
     *     description: Count data for a specific zone.
     *
     * /api/v1.0/zgrab/zone:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Returns the port data for the provided zone.
     *     tags: [Port scans - Fetch zone port data]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: zone
     *         type: string
     *         required: true
     *         description: The zone for this request.
     *         in: query
     *       - name: port
     *         type: int
     *         required: false
     *         description: The port for this request.
     *         in: query
     *       - name: use_port_data
     *         type: int
     *         required: false
     *         description: Set to 1 to override the use zgrab port specific collections
     *         in: query
     *     responses:
     *       200:
     *         description: Returns the relevant set zone data.
     *         type: array
     *         items:
     *           type: object
     *           properties:
     *             zone:
     *               type: string
     *               example: "example.org"
     *             data:
     *               type: object
     *               description: Data on known ports for the zone. See the schema.
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
     * /api/v1.0/zgrab/zone?count=1:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Returns whether there is port data for the provided zone and port.
     *     tags: [Port scans - Count zone port data]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: count
     *         type: int
     *         required: true
     *         description: Set to 1 for this request.
     *         in: query
     *       - name: zone
     *         type: string
     *         required: true
     *         description: The zone for this request.
     *         in: query
     *       - name: port
     *         type: int
     *         required: false
     *         description: The port for this request.
     *         in: query
     *       - name: use_port_data
     *         type: int
     *         required: false
     *         description: Set to 1 to override the use zgrab_(443|80) collections
     *         in: query
     *     responses:
     *       200:
     *         description: Returns the relevant zone.
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
    router.route('/zgrab/zone')
        // get the port data for the provided zone
        .get(function (req, res) {

            if (!is_valid_strings(req.query)) {
                res.status(400).json({ 'message': 'Multiple query parameters are not allowed.' });
                return;
            }

            if (!(req.query.hasOwnProperty('zone'))) {
                res.status(400).json({ 'message': 'A zone must be provided' });
                return;
            }

            let port = null;
            if (req.query.hasOwnProperty('port')) {
                port = req.query.port;
            }

            if (port != null && !(["22", "25", "80", "443", "465"].includes(port))) {
                res.status(400).json({ 'message': 'Only ports 22, 25, 443, and 465 are supported.' });
                return;
            }

            let count = false;
            if (req.query.hasOwnProperty('count') && req.query.count === '1') {
                count = true;
            }

            var promise;
            if (port === "22" || port === "25" || port === "465") {
                promise = zgrabPort.getRecordByZonePromise(req.query.zone, port, count);
            } else if (port === "443" && req.query.hasOwnProperty("use_port_data") && req.query.use_port_data === "1") {
                promise = zgrabPort.getRecordByZonePromise(req.query.zone, port, count);
            } else if (port === "443") {
                promise = zgrab443.getRecordsByZonePromise(req.query.zone, count)
            } else if (port === "80") {
                promise = zgrab80.getRecordsByZonePromise(req.query.zone, count);
            } else {
                promise = zgrabPort.getRecordByZonePromise(req.query.zone, null, count);
            }

            promise.then(function (data) {
                if (count && (port === "22" || port === "25" || port === "465")) {
                    res.status(200).json({ 'count': data.length });
                } else if (port === "443" && count && req.query.use_port_data === "1") {
                    res.status(200).json({ 'count': data.length });
                } else if (count) {
                    res.status(200).json({ 'count': data });
                } else {
                    if (!data) {
                        res.status(404).json({ 'message': 'Zone not found' });
                        return;
                    }
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
      *   - name: Port 22 scans - Fetch IPs list
      *     description: Returns the list of IPs that responded to a port 22 SSH request.
      *   - name: Port 22 scans - Count IPs list
      *     description: Returns the count of IPs that responded to a port 22 SSH request.
      *
      * /api/v1.0/zgrab/22/ips:
      *   get:
      *   # Operation-specific security:
      *     security:
      *       - APIKeyHeader: []
      *     description: Returns the list of IPs that responded to a port 22 SSH request.
      *     tags: [Port 22 scans - Fetch IPs list]
      *     produces:
      *       - application/json
      *     parameters:
      *       - name: limit
      *         type: number
      *         required: false
      *         description: Limit the number of IPs per page.
      *         in: query
      *       - name: page
      *         type: number
      *         required: false
      *         description: The page to request. This must be set in conjunction with the limit parameter. The default is 1.
      *         in: query
      *     responses:
      *       200:
      *         description: Returns the relevant set or subset of IPs.
      *         type: array
      *         items:
      *           type: object
      *           properties:
      *             ip:
      *               type: string
      *               example: "8.8.8.8"
      *             azure:
      *               type: Boolean
      *             aws:
      *               type: Boolean
      *             tracked:
      *               type: Boolean
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
      * /api/v1.0/zgrab/22/ips?count=1:
      *   get:
      *   # Operation-specific security:
      *     security:
      *       - APIKeyHeader: []
      *     description: Counts the list of IPs that responded to a port 22 SSH requests.
      *     tags: [Port 22 scans - Count IPs list]
      *     produces:
      *       - application/json
      *     parameters:
      *       - name: count
      *         type: string
      *         required: true
      *         description: Set to 1 in order to retrieve the count of matching records
      *         in: query
      *     responses:
      *       200:
      *         description: Returns the number of relevant scans.
      *         schema:
      *           $ref: '#/definitions/CountResponse'
      *       400:
      *         description: Bad request parameters.
      *         schema:
      *           $ref: '#/definitions/BadInputError'
      *       500:
      *         description: Server error.
      *         schema:
      *           $ref: '#/definitions/ServerError'
      */
    router.route('/zgrab/22/ips')
        // get list of IPs that respond to port 22
        .get(function (req, res) {

            if (!is_valid_strings(req.query)) {
                res.status(400).json({ 'message': 'Multiple query parameters are not allowed.' });
                return;
            }

            let count = false;
            if (req.query.hasOwnProperty('count') && req.query.count === '1') {
                count = true;
            }

            let limit = 0;
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

            let promise = zgrabPort.getXSSHIPListPromise(count, limit, page);

            promise.then(function (data) {
                if (count) {
                    res.status(200).json({ 'count': data });
                } else {
                    if (!data) {
                        res.status(500).json({ 'message': 'Error retrieving list' });
                        return;
                    }
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
     *   - name: Port 25 scans - Fetch IPs list
     *     description: Returns the list of IPs that responded to a port 25 STMP request.
     *   - name: Port 25 scans - Count IPs list
     *     description: Returns the count of IPs that responded to a port 25 STMP request.
     *
     * /api/v1.0/zgrab/25/ips:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Returns the list of IPs that responded to a port 25 SMTP request.
     *     tags: [Port 25 scans - Fetch IPs list]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: limit
     *         type: number
     *         required: false
     *         description: Limit the number of IPs per page.
     *         in: query
     *       - name: page
     *         type: number
     *         required: false
     *         description: The page to request. This must be set in conjunction with the limit parameter. The default is 1.
     *         in: query
     *     responses:
     *       200:
     *         description: Returns the relevant set or subset of IPs.
     *         type: array
     *         items:
     *           type: object
     *           properties:
     *             ip:
     *               type: string
     *               example: "8.8.8.8"
     *             azure:
     *               type: Boolean
     *             aws:
     *               type: Boolean
     *             tracked:
     *               type: Boolean
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
     * /api/v1.0/zgrab/25/ips?count=1:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Counts the list of IPs that responded to a port 25 STMP requests.
     *     tags: [Port 25 scans - Count IPs list]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: count
     *         type: string
     *         required: true
     *         description: Set to 1 in order to retrieve the count of matching records
     *         in: query
     *     responses:
     *       200:
     *         description: Returns the number of relevant scans.
     *         schema:
     *           $ref: '#/definitions/CountResponse'
     *       400:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     */
    router.route('/zgrab/25/ips')
        // get list of IPs that respond to port 25
        .get(function (req, res) {
            let count = false;

            if (!is_valid_strings(req.query)) {
                res.status(400).json({ 'message': 'Multiple query parameters are not allowed.' });
                return;
            }

            if (req.query.hasOwnProperty('count') && req.query.count === '1') {
                count = true;
            }

            let limit = 0;
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

            let promise = zgrabPort.getSMTPIPListPromise(count, limit, page);

            promise.then(function (data) {
                if (count) {
                    res.status(200).json({ 'count': data });
                } else {
                    if (!data) {
                        res.status(500).json({ 'message': 'Error retrieving list' });
                        return;
                    }
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
     *   - name: Port 465 scans - Fetch IPs list
     *     description: Returns the list of IPs that responded to a port 465 STMPS request.
     *   - name: Port 465 scans - Count IPs list
     *     description: Returns the count of IPs that responded to a port 465 STMPS request.
     *
     * /api/v1.0/zgrab/465/ips:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Returns the list of IPs that responded to a port 465 SMTPS request.
     *     tags: [Port 465 scans - Fetch IPs list]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: limit
     *         type: number
     *         required: false
     *         description: Limit the number of IPs per page.
     *         in: query
     *       - name: page
     *         type: number
     *         required: false
     *         description: The page to request. This must be set in conjunction with the limit parameter. The default is 1.
     *         in: query
     *     responses:
     *       200:
     *         description: Returns the relevant set or subset of IPs.
     *         type: array
     *         items:
     *           type: object
     *           properties:
     *             ip:
     *               type: string
     *               example: "8.8.8.8"
     *             azure:
     *               type: Boolean
     *             aws:
     *               type: Boolean
     *             tracked:
     *               type: Boolean
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
     * /api/v1.0/zgrab/465/ips?count=1:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Counts the list of IPs that responded to a port 465 STMPS requests.
     *     tags: [Port 465 scans - Count IPs list]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: count
     *         type: string
     *         required: true
     *         description: Set to 1 in order to retrieve the count of matching records
     *         in: query
     *     responses:
     *       200:
     *         description: Returns the number of relevant scans.
     *         schema:
     *           $ref: '#/definitions/CountResponse'
     *       400:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     */
    router.route('/zgrab/465/ips')
        // get list of IPs that respond to port 465
        .get(function (req, res) {
            let count = false;

            if (!is_valid_strings(req.query)) {
                res.status(400).json({ 'message': 'Multiple query parameters are not allowed.' });
                return;
            }

            if (req.query.hasOwnProperty('count') && req.query.count === '1') {
                count = true;
            }

            let limit = 0;
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

            let promise = zgrabPort.getSMTPSIPListPromise(count, limit, page);

            promise.then(function (data) {
                if (count) {
                    res.status(200).json({ 'count': data });
                } else {
                    if (!data) {
                        res.status(500).json({ 'message': 'Error retrieving list' });
                        return;
                    }
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
     *   - name: Port 443 scans - Fetch zones list
     *     description: Return a list of all of the zones that responded to a port 443 TCP connection.
     *
     * /api/v1.0/zgrab/443/zones:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Retrieve the list of all zones that responded to a port 443 response. This will include zones that
     *                  redirected to another site.
     *     tags: [Port 443 scans - Fetch zones list]
     *     produces:
     *       - application/json
     *     responses:
     *       200:
     *         description: Returns the distinct zones for port 443
     *         schema:
     *           $ref: '#/definitions/HTTPSZoneList'
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
    router.route('/zgrab/443/zones')
        // get info on a specific zones
        .get(function (req, res) {
            let promise = zgrab443.getDistinctZonesPromise();

            promise.then(function (data) {
                if (!data) {
                    res.status(404).json({ 'message': 'Error performing distinct call' });
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
     *   - name: Port 443 scans - Fetch zone
     *     description: Returns all records associated with the requested zone.
     *
     * /api/v1.0/zgrab/443/zones/{zone}:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Retrieve all zgrab scan data with the associated zone. This typically returns a very large response. You
     *                  may want to do a count first to see how many records you are retrieving.
     *     tags: [Port 443 scans - Fetch zone]
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
     *         description: Returns the relevant scans.
     *         type: array
     *         items:
     *           $ref: '#/definitions/HTTPSScanResponse'
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
     * /api/v1.0/zgrab/443/zones/{zone}?count=1:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Retrieve all zgrab scan data with the associated zone
     *     tags: [Port 443 scans - Fetch zone]
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
     *         description: Set to 1 in order to retrieve the count of matching records
     *         in: query
     *       - name: limit
     *         type: number
     *         required: false
     *         description: Limit the number of results per page.
     *         in: query
     *       - name: page
     *         type: number
     *         required: false
     *         description: The page to request. This must be set in conjunction with the limit parameter. The default is 1.
     *         in: query
     *     responses:
     *       200:
     *         description: Returns the number of relevant scans.
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
    router.route('/zgrab/443/zones/:zone')
        // get info on a specific zones
        .get(function (req, res) {

            if (!is_valid_strings(req.query)) {
                res.status(400).json({ 'message': 'Multiple query parameters are not allowed.' });
                return;
            }

            if (!(req.params.hasOwnProperty('zone'))) {
                res.status(400).json({ 'message': 'A zone must be provided.' });
                return;
            }
            let zone = req.params.zone;

            let count = false;
            if (req.query.hasOwnProperty('count') && req.query.count === '1') {
                count = true;
            }

            let limit = 0;
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

            let promise = zgrab443.getRecordsByZonePromise(zone, count, limit, page);

            promise.then(function (data) {
                if (!data) {
                    res.status(404).json({ 'message': 'Zone not found' });
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
     *   - name: Port 443 scans - Fetch domain list
     *     description: Returns the list of domains that responded to a port 443 request.
     *
     * /api/v1.0/zgrab/443/domains:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Returns the list of domains that responded to a port 443 request.
     *     tags: [Port 443 scans - Fetch domain list]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: limit
     *         type: number
     *         required: false
     *         description: Limit the number of domains per page.
     *         in: query
     *       - name: page
     *         type: number
     *         required: false
     *         description: The page to request. This must be set in conjunction with the limit parameter. The default is 1.
     *         in: query
     *     responses:
     *       200:
     *         description: Returns the relevant set or subset of domains.
     *         type: array
     *         items:
     *           type: object
     *           properties:
     *             domain:
     *               type: string
     *               example: "www.example.org"
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
     * /api/v1.0/zgrab/443/domains?count=1:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Counts the list of domains that responded to a port 443 request.
     *     tags: [Port 443 scans - Fetch domain list]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: count
     *         type: string
     *         required: true
     *         description: Set to 1 in order to retrieve the count of matching records
     *         in: query
     *     responses:
     *       200:
     *         description: Returns the number of relevant scans.
     *         schema:
     *           $ref: '#/definitions/CountResponse'
     *       400:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     */
    router.route('/zgrab/443/domains')
        // get list of domains that respond to 443
        .get(function (req, res) {
            let count = false;

            if (!is_valid_strings(req.query)) {
                res.status(400).json({ 'message': 'Multiple query parameters are not allowed.' });
                return;
            }

            if (req.query.hasOwnProperty('count') && req.query.count === '1') {
                count = true;
            }

            let limit = 0;
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

            let promise = zgrab443.getDomainListPromise(count, limit, page);

            promise.then(function (data) {
                if (count) {
                    res.status(200).json({ 'count': data });
                } else {
                    if (!data) {
                        res.status(500).json({ 'message': 'Error retrieving list' });
                        return;
                    }
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
     *   - name: Port 443 scans - Fetch IPs list
     *     description: Returns the list of IPs that responded to a port 443 request.
     *   - name: Port 443 scans - Count IPs list
     *     description: Returns the count of IPs that responded to a port 443 request.
     *
     * /api/v1.0/zgrab/443/ips:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Returns the list of IPs that responded to a port 443 request.
     *     tags: [Port 443 scans - Fetch IPs list]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: limit
     *         type: number
     *         required: false
     *         description: Limit the number of IPs per page.
     *         in: query
     *       - name: page
     *         type: number
     *         required: false
     *         description: The page to request. This must be set in conjunction with the limit parameter. The default is 1.
     *         in: query
     *     responses:
     *       200:
     *         description: Returns the relevant set or subset of IPs.
     *         type: array
     *         items:
     *           type: object
     *           properties:
     *             ip:
     *               type: string
     *               example: "8.8.8.8"
     *             azure:
     *               type: Boolean
     *             aws:
     *               type: Boolean
     *             tracked:
     *               type: Boolean
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
     * /api/v1.0/zgrab/443/ips?count=1:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Counts the list of IPs that responded to a port 443 request.
     *     tags: [Port 443 scans - Count IPs list]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: count
     *         type: string
     *         required: true
     *         description: Set to 1 in order to retrieve the count of matching records
     *         in: query
     *     responses:
     *       200:
     *         description: Returns the number of relevant scans.
     *         schema:
     *           $ref: '#/definitions/CountResponse'
     *       400:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     */
    router.route('/zgrab/443/ips')
        // get list of IPs that respond to port 443
        .get(function (req, res) {
            let count = false;

            if (!is_valid_strings(req.query)) {
                res.status(400).json({ 'message': 'Multiple query parameters are not allowed.' });
                return;
            }

            if (req.query.hasOwnProperty('count') && req.query.count === '1') {
                count = true;
            }

            let limit = 0;
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

            let promise = zgrab443.getIPListPromise(count, limit, page);

            promise.then(function (data) {
                if (count) {
                    res.status(200).json({ 'count': data });
                } else {
                    if (!data) {
                        res.status(404).json({ 'message': 'Error retrieving list' });
                        return;
                    }
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
     *   - name: Port 443 scans - Fetch headers
     *     description: Returns all records associated with the requested header.
     *
     * /api/v1.0/zgrab/443/headers/{header}:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Retrieve all zgrab scan data with the associated header.
     *     tags: [Port 443 scans - Fetch headers]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: header
     *         type: string
     *         required: true
     *         description: The name of the header to fetch.
     *         in: path
     *       - name: zone
     *         type: string
     *         required: false
     *         description: The zone ("example.org", "example.com", etc.) to fetch.
     *         in: query
     *     responses:
     *       200:
     *         description: Returns the relevant header responses.
     *         schema:
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
     * /api/v1.0/zgrab/443/headers/{header}?count=1:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Retrieve all zgrab scan data with the associated header.
     *     tags: [Port 443 scans - Fetch headers]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: header
     *         type: string
     *         required: true
     *         description: The name of the header to fetch.
     *         in: path
     *       - name: count
     *         type: string
     *         required: true
     *         description: Set to 1 in order to retrieve the count of matching records
     *         in: query
     *       - name: zone
     *         type: string
     *         required: false
     *         description: The zone ("example.org", "example.com", etc.) to fetch.
     *         in: query
     *     responses:
     *       200:
     *         description: Returns the number of relevant header counts.
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
     * /api/v1.0/zgrab/443/headers/{header}?distinct=1:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Retrieve all distinct header values for the associated header.
     *     tags: [Port 443 scans - Fetch headers]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: header
     *         type: string
     *         required: true
     *         description: The name of the header to fetch.
     *         in: path
     *       - name: distinct
     *         type: string
     *         required: true
     *         description: Set to 1 in order to retrieve the count of distinct values for the header.
     *         in: query
     *       - name: zone
     *         type: string
     *         required: false
     *         description: The zone ("example.org", "example.com", etc.) to fetch.
     *         in: query
     *     responses:
     *       200:
     *         description: Returns the header value and corresponding count of each value.
     *         type: array
     *         items:
     *           type: object
     *           properties:
     *             _id:
     *                type: array
     *                items:
     *                  type: string
     *                  example: "Apache"
     *             count:
     *               type: number
     *               example: 10
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
     * /api/v1.0/zgrab/443/headers/{header}?value={value}:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Retrieve all distinct header values for the associated header.
     *     tags: [Port 443 scans - Fetch headers]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: header
     *         type: string
     *         required: true
     *         description: The name of the header to fetch.
     *         in: path
     *       - name: value
     *         type: string
     *         required: true
     *         description: Limit results to this this specific value for the provided header.
     *         in: query
     *       - name: zone
     *         type: string
     *         required: false
     *         description: The zone ("example.org", "example.com", etc.) to fetch.
     *         in: query
     *     responses:
     *       200:
     *         description: Returns the header value and corresponding count of each value.
     *         schema:
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
    router.route('/zgrab/443/headers/:header')
        .get(function (req, res) {
            if (!(req.params.hasOwnProperty('header'))) {
                res.status(400).json({
                    'message': 'A header value must be provided.',
                });
                return;
            }

            let header = req.params.header;
            let promise;
            let count = false;

            if (!is_valid_strings(req.query)) {
                res.status(400).json({ 'message': 'Multiple query parameters are not allowed.' });
                return;
            }

            let zone = '';
            if (req.query.hasOwnProperty('zone') && req.query.zone !== '') {
                zone = req.query.zone;
            }

            if (req.query.hasOwnProperty('count') && req.query.count === '1') {
                promise = zgrab443.getHttpHeaderPromise(header, zone, true);
                count = true;
            } else if (req.query.hasOwnProperty('distinct') &&
                req.query.distinct === '1') {
                promise = zgrab443.getDistinctHttpHeaderPromise(header, zone);
            } else if (req.query.hasOwnProperty('value')) {
                promise = zgrab443.getHttpHeaderByValuePromise(header, req.query.value, zone);
            } else {
                promise = zgrab443.getHttpHeaderPromise(header, zone, false);
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
     *   - name: Port 443 scans - Fetch by algorithm
     *     description: Returns all records associated with the requested TLS algorithm.
     *
     * /api/v1.0/zgrab/443/algorithm/{algorithm}:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Retrieve all zgrab scan data with the associated TLS algorithm. This takes a long time to execute.
     *     tags: [Port 443 scans - Fetch by algorithm]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: algorithm
     *         type: string
     *         required: true
     *         description: The name of the TLS algorithm to fetch.
     *         in: path
     *       - name: zone
     *         type: string
     *         required: false
     *         description: The zone ("example.org", "example.com", etc.) to fetch.
     *         in: query
     *       - name: recursive
     *         type: string
     *         required: false
     *         description: Set to 1 to support a recursive query. In the event that original request resulted in a redirect,
     *                      setting this to 1 will provide the algorithm that was used in the final request. Omitting this value
     *                      will search based on the initial algorithm prior to processing any redirect requests.
     *         in: query
     *       - name: limit
     *         type: number
     *         required: false
     *         description: Limit the number of results per page. The default is 100.
     *         in: query
     *       - name: page
     *         type: number
     *         required: false
     *         description: The page to request. This must be set in conjunction with the limit parameter. The default is 1.
     *         in: query
     *     responses:
     *       200:
     *         description: Returns the relevant algorithm responses.
     *         type: array
     *         items:
     *           $ref: '#/definitions/HTTPSScanResponse'
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
     * /api/v1.0/zgrab/443/algorithm/{algorithm}?count=1:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Retrieve all zgrab scan data with the associated TLS algorithm. This takes a long time to execute.
     *     tags: [Port 443 scans - Fetch by algorithm]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: algorithm
     *         type: string
     *         required: true
     *         description: The name of the TLS algorithm to fetch.
     *         in: path
     *       - name: count
     *         type: string
     *         required: true
     *         description: Set to 1 in order to retrieve the count of matching records
     *         in: query
     *       - name: zone
     *         type: string
     *         required: false
     *         description: The zone ("example.org", "example.com", etc.) to fetch.
     *         in: query
     *       - name: recursive
     *         type: string
     *         required: false
     *         description: Set to 1 to support a recursive query. In the event that original request resulted in a redirect,
     *                      setting this to 1 will provide the algorithm that was used in the final request. Omitting this value
     *                      will search based on the initial algorithm prior to processing any redirect requests.
     *         in: query
     *     responses:
     *       200:
     *         description: Returns the number of relevant header counts.
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
    router.route('/zgrab/443/algorithm/:algorithm')
        // get info on a specific algorithm
        .get(function (req, res) {
            if (!(req.params.hasOwnProperty('algorithm')) ||
                req.params.algorithm.length === 0) {
                res.status(400).json({ 'message': 'An algorithm must be provided.' });
                return;
            }

            if (!is_valid_strings(req.query)) {
                res.status(400).json({ 'message': 'Multiple query parameters are not allowed.' });
                return;
            }

            let count = false;
            if (req.query.hasOwnProperty('count') && req.query.count === '1') {
                count = true;
            }

            let recursive = false;
            if (req.query.hasOwnProperty('recursive') && req.query.recursive === '1') {
                recursive = true;
            }

            let limit = 100;
            if (req.query.hasOwnProperty('limit')) {
                limit = parseInt(req.query.limit);
                if (isNaN(limit)) {
                    res.status(400).json({ 'message': 'A valid limit value must be provided.' });
                    return;
                }
                if (limit <= 0) {
                    limit = 100;
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

            let promise;
            if (req.query.hasOwnProperty('zone')) {
                promise = zgrab443.getSSLAlgorithmByZonePromise(req.params.algorithm, req.query.zone, count, recursive, limit, page);
            } else {
                promise = zgrab443.getSSLAlgorithmPromise(req.params.algorithm, count, recursive, limit, page);
            }

            promise.then(function (data) {
                if (!data) {
                    res.status(404).json({ 'message': 'Algorithm not found' });
                    return;
                }
                if (count) {
                    if (recursive === true) {
                        res.status(200).json({ 'count': data });
                    } else {
                        if (data.length === 0) {
                            res.status(200).json({ 'count': 0 });
                        } else {
                            res.status(200).json(data[0]);
                        }
                    }
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
     *   - name: Port 443 scans - Cert search
     *     description: Returns all certificates associated with the provided parameters.
     *
     * /api/v1.0/zgrab/443/certs:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Retrieve all zgrab scan data with the associated TLS algorithm. The values org, zone, common_name,
     *                  fingerprint_sha1, and fingerprint_sha256 are mutually exclusive. This returns the full record for
     *                  each request which is quite large. Therefore, if testing via Swagger, limit the requests to a small
     *                  number (<5) for org and zone searches.
     *     tags: [Port 443 scans - Cert search]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: zone
     *         type: string
     *         required: false
     *         description: The zone ("example.org", "example.com", etc.) to fetch. Recursive does not apply to this search.
     *         in: query
     *       - name: common_name
     *         type: string
     *         required: false
     *         description: The Common Name of the owner of the certificate. This can be used with recursive.
     *         in: query
     *       - name: serial_number
     *         type: string
     *         required: false
     *         description: The Serial Number of the certificate. This can be used with recursive.
     *         in: query
     *       - name: org
     *         type: string
     *         required: false
     *         description: The Organization of the owner of the certificate. This can be used with recursive.
     *         in: query
     *       - name: fingerprint_sha1
     *         type: string
     *         required: false
     *         description: The SHA1 fingerprint of the certificate. This can be used with recursive.
     *         in: query
     *       - name: fingerprint_sha256
     *         type: string
     *         required: false
     *         description: The SHA256 fingerprint of the certificate. This can be used with recursive.
     *         in: query
     *       - name: recursive
     *         type: string
     *         required: false
     *         description: Set to 1 to support a recursive query. In the event that original request resulted in a redirect,
     *                      setting this to 1 will provide the algorithm that was used in the final request. Omitting this value
     *                      will search based on the initial algorithm prior to processing any redirect requests. This is not
     *                      used in a zone search.
     *         in: query
     *       - name: limit
     *         type: number
     *         required: false
     *         description: Limit the number of results per page. Useful for org or zone searches that may have a high number
     *                      of results.
     *         in: query
     *       - name: page
     *         type: number
     *         required: false
     *         description: The page to request. This must be set in conjunction with the limit parameter. The default is 1.
     *         in: query
     *     responses:
     *       200:
     *         description: Returns the relevant header responses.
     *         schema:
     *           $ref: '#/definitions/HTTPCertificateResponse'
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
     * /api/v1.0/zgrab/443/certs?count=1:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Retrieve all zgrab scan data with the associated TLS algorithm. This takes a long time to execute.
     *     tags: [Port 443 scans - Cert search]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: count
     *         type: string
     *         required: false
     *         description: Set to 1 in order to retrieve the count of matching records
     *         in: required
     *       - name: zone
     *         type: string
     *         required: false
     *         description: The zone ("example.org", "example.com", etc.) to fetch. Recursive does not apply to this search.
     *         in: query
     *       - name: org
     *         type: string
     *         required: false
     *         description: The Organization of the owner of the certificate. This can be used with recursive.
     *         in: query
     *       - name: fingerprint_sha1
     *         type: string
     *         required: false
     *         description: The SHA1 fingerprint of the certificate. This can be used with recursive.
     *         in: query
     *       - name: fingerprint_sha256
     *         type: string
     *         required: false
     *         description: The SHA256 fingerprint of the certificate. This can be used with recursive.
     *         in: query
     *       - name: recursive
     *         type: string
     *         required: false
     *         description: Set to 1 to support a recursive query. In the event that original request resulted in a redirect,
     *                      setting this to 1 will provide the algorithm that was used in the final request. Omitting this value
     *                      will search based on the initial algorithm prior to processing any redirect requests. This is not
     *                      used in a zone search.
     *         in: query
     *     responses:
     *       200:
     *         description: Returns the number of relevant header counts.
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
     */
    router.route('/zgrab/443/certs')
        // get info on a specific certificate
        .get(function (req, res) {

            let recursive = false;
            if (req.query.hasOwnProperty('recursive') && req.query.recursive === "1") {
                recursive = true;
            }

            if (!is_valid_strings(req.query)) {
                res.status(400).json({ 'message': 'Multiple query parameters are not allowed.' });
                return;
            }

            let limit = 0;
            if (req.query.hasOwnProperty('limit')) {
                limit = parseInt(req.query.limit);
                if (isNaN(limit)) {
                    res.status(400).json({ 'message': 'A valid limit value must be provided.' });
                    return;
                }
                if (limit <= 0) {
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

            let promise;

            if (req.query.hasOwnProperty('org')) {
                let org = req.query.org;

                if (req.query.hasOwnProperty('count') && req.query.count === '1') {
                    promise = zgrab443.getSSLOrgCountPromise(org, recursive);
                } else {
                    promise = zgrab443.getRecordsBySSLOrgPromise(org, recursive, limit, page);
                }
            } else if (req.query.hasOwnProperty('common_name')) {
                promise = zgrab443.getSSLByCommonNamePromise(req.query.common_name, recursive);
            } else if (req.query.hasOwnProperty('serial_number')) {
                if (req.query.hasOwnProperty('count') && req.query.count === '1') {
                    promise = zgrab443.getSSLBySerialNumberPromise(req.query.serial_number.toLowerCase(), true, recursive);
                } else {
                    promise = zgrab443.getSSLBySerialNumberPromise(req.query.serial_number.toLowerCase(), false, recursive);
                }
            } else if (req.query.hasOwnProperty('zone')) {
                if (req.query.hasOwnProperty('count') && req.query.count === '1') {
                    promise = zgrab443.getSSLByZonePromise(req.query.zone, true);
                } else {
                    promise = zgrab443.getSSLByZonePromise(req.query.zone, false, limit, page);
                }
            } else if (req.query.hasOwnProperty('fingerprint_sha1')) {
                if (req.query.hasOwnProperty('count') && req.query.count === '1') {
                    promise = zgrab443.getRecordsBySSLFingerprintPromise(req.query.fingerprint_sha1, true, recursive);
                } else {
                    promise = zgrab443.getRecordsBySSLFingerprintPromise(req.query.fingerprint_sha1, false, recursive);
                }
            } else if (req.query.hasOwnProperty('fingerprint_sha256')) {
                if (req.query.hasOwnProperty('count') && req.query.count === '1') {
                    promise = zgrab443.getRecordsBySSL256FingerprintPromise(req.query.fingerprint_sha256, true, recursive);
                } else {
                    promise = zgrab443.getRecordsBySSL256FingerprintPromise(req.query.fingerprint_sha256, false, recursive);
                }
            } else {
                res.status(400);
                res.json({ 'message': 'An org, zone, fingerprint_sha1, fingerprint_sha256, or a common_name must be provided' });
                return;
            }

            promise.then(function (data) {
                if (!data) {
                    res.status(404).json({ 'message': 'Cert not found' });
                    return;
                }
                if (req.query.hasOwnProperty('count') && req.query.count === '1') {
                    if (recursive === true) {
                        res.status(200).json({ 'count': data });
                    } else {
                        if (data.length === 0) {
                            res.status(200).json({ 'count': 0 });
                        } else {
                            res.status(200).json(data[0]);
                        }
                    }
                } else {
                    if (recursive === true) {
                        res.status(200).json(data);
                    } else {
                        let result = reformatResponse(data);
                        res.status(200).json(result);
                    }
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
     *   - name: Port 443 scans - Cert CA list
     *     description: Returns the list of known CAs from the scans and their counts.
     *
     * /api/v1.0/zgrab/443/cert_ca:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Retrieve a list of Certificate Authorities identified by the scans.
     *     tags: [Port 443 scans - Cert CA list]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: recursive
     *         type: string
     *         required: false
     *         description: Set to 1 to support a recursive query. In the event that original request resulted in a redirect,
     *                      setting this to 1 will provide the algorithm that was used in the final request. Omitting this value
     *                      will search based on the initial algorithm prior to processing any redirect requests.
     *         in: query
     *     responses:
     *       200:
     *         description: Returns the relevant CA list and counts.
     *         type: array
     *         items:
     *           type: object
     *           properties:
     *             id:
     *               type: string
     *               example: "Go Daddy Secure Certificate Authority - G2"
     *             count:
     *               type: int
     *               example: 5
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
    router.route('/zgrab/443/cert_ca')
        // Get unique CA values from chain[0]
        .get(function (req, res) {

            if (!is_valid_strings(req.query)) {
                res.status(400).json({ 'message': 'Multiple query parameters are not allowed.' });
                return;
            }

            let recursive = false;
            if (req.query.hasOwnProperty('recursive') && req.query.recursive === "1") {
                recursive = true;
            }

            let promise = zgrab443.getCAIssuersListPromise(recursive);

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
     *   - name: Port 443 scans - Cert CA search
     *     description: Returns the list of all scans associated with the provided CA.
     *
     * /api/v1.0/zgrab/443/cert_ca/{ca}:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Returns the list of all scans associated with the provided Certificate Authority (CA). This returns the
     *                  full scan response which is quite large. If testing via Swagger, set the limit to a small number (<5)
     *                  because the response body will be large.
     *     tags: [Port 443 scans - Cert CA search]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: ca
     *         type: string
     *         required: true
     *         description: The Certificate Authority value that will be used for the search.
     *         in: path
     *       - name: recursive
     *         type: string
     *         required: false
     *         description: Set to 1 to support a recursive query. In the event that original request resulted in a redirect,
     *                      setting this to 1 will provide the algorithm that was used in the final request. Omitting this value
     *                      will search based on the initial algorithm prior to processing any redirect requests.
     *         in: query
     *       - name: limit
     *         type: number
     *         required: false
     *         description: Limit the number of results per page. Useful for searches that may have a high number of results.
     *         in: query
     *       - name: page
     *         type: number
     *         required: false
     *         description: The page to request. This must be set in conjunction with the limit parameter. The default is 1.
     *         in: query
     *     responses:
     *       200:
     *         description: Returns the relevant CA scan data.
     *         type: array
     *         items:
     *           $ref: '#/definitions/HTTPSScanResponse'
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
     * /api/v1.0/zgrab/443/cert_ca/{ca}?count=1:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Returns the count of all scans associated with the provided CA.
     *     tags: [Port 443 scans - Cert CA search]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: ca
     *         type: string
     *         required: true
     *         description: The CA value that will be used for the search.
     *         in: path
     *       - name: count
     *         type: string
     *         required: true
     *         description: Set to 1 for this type of search.
     *         in: query
     *       - name: recursive
     *         type: string
     *         required: false
     *         description: Set to 1 to support searching post-redirect. In the event that the original request resulted in a redirect,
     *                      setting this to 1 will return the data that was returned from the last page in the redirect chain. Omitting
     *                      this value will check both non-redirect and redirect requests and return the result from the first response.
     *         in: query
     *     responses:
     *       200:
     *         description: Returns the count for relevant CA scan data.
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
    router.route('/zgrab/443/cert_ca/:ca')
        // Get records for an individual CA
        .get(function (req, res) {
            if (!(req.params.hasOwnProperty('ca'))) {
                res.status(400).json({ 'message': 'A CA value must be provided.' });
                return;
            }

            if (!is_valid_strings(req.query)) {
                res.status(400).json({ 'message': 'Multiple query parameters are not allowed.' });
                return;
            }

            let promise;
            let count = false;
            let ca = unescape(req.params.ca);

            let limit = 0;
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

            let recursive = false;
            if (req.query.hasOwnProperty('recursive') && req.query.recursive === "1") {
                recursive = true;
            }

            if (req.query.hasOwnProperty('count') && req.query.count === '1') {
                count = true;
                promise = zgrab443.getRecordsBySSLCAPromise(ca, true, page, limit, recursive);
            } else {
                promise = zgrab443.getRecordsBySSLCAPromise(ca, false, page, limit, recursive);
            }

            promise.then(function (data) {
                if (!data) {
                    res.status(404).json({ 'message': 'CA not found' });
                    return;
                }
                if (count) {
                    if (recursive === true) {
                        res.status(200).json({ 'count': data });
                    } else {
                        if (data.length === 0) {
                            res.status(200).json({ 'count': 0 });
                        } else {
                            res.status(200).json(data[0]);
                        }
                    }
                } else {
                    if (recursive === true) {
                        res.status(200).json(data);
                    } else {
                        res.status(200).json(reformatResponse(data));
                    }
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
     *   - name: Port 443 scans - Expired 200x certs
     *     description: Find expired certs from the 200x era
     *
     * /api/v1.0/zgrab/443/expired_certs_2k:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Find expired certs from the 200x era. This returns the full scan response which is quite large.
     *                  If testing via Swagger, set the limit to a small number (<5) because the response body will be large.
     *     tags: [Port 443 scans - Expired 200x certs]
     *     produces:
     *       - application/json
     *     responses:
     *       200:
     *         description: Returns the relevant expired certs.
     *         type: array
     *         items:
     *           $ref: '#/definitions/HTTPSScanResponse'
     *       404:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/ResultsNotFound'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     */
    router.route('/zgrab/443/expired_certs_2k')
        // get info on expired certs
        .get(function (req, res) {
            let recursive = false;

            let promise = zgrab443.getSSLByValidity2kPromise(recursive);

            promise.then(function (data) {
                if (!data) {
                    res.status(404).json({ 'message': 'Data not found' });
                    return;
                }

                if (recursive === true) {
                    res.status(200).json(data);
                } else {
                    let result = reformatResponse(data);
                    res.status(200).json(result);
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
     *   - name: Port 443 scans - Expired certs by year
     *     description: Find expired certs from the 200x era
     *
     * /api/v1.0/zgrab/443/expired_certs_by_year:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Find expired certs from the 201x era. This returns the full scan response which is quite large.
     *                  If testing via Swagger, set the limit to a small number (<5) because the response body will be large.
     *     tags: [Port 443 scans - Expired certs by year]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: year
     *         type: string
     *         required: true
     *         description: A year in the 201x format. This is a regex search so you can optionally make it year + month.
     *         in: query
     *     responses:
     *       200:
     *         description: Returns the relevant expired certs.
     *         type: array
     *         items:
     *           $ref: '#/definitions/HTTPSScanResponse'
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
    router.route('/zgrab/443/expired_certs_by_year')
        // get info on expired certs
        .get(function (req, res) {
            let recursive = false;

            if (!is_valid_strings(req.query)) {
                res.status(400).json({ 'message': 'Multiple query parameters are not allowed.' });
                return;
            }

            if (!(req.query.hasOwnProperty('year'))) {
                res.status(400).json({ 'message': 'A year must be provided.' });
                return;
            } else if (req.query.year.match(/^[0-9\-]+$/) == null) {
                res.status(400).json({ 'message': 'A valid year must be provided.' });
                return;
            }

            let promise = zgrab443.getSSLByValidityYearPromise(req.query.year, recursive);

            promise.then(function (data) {
                if (!data || data.length === 0) {
                    res.status(404).json({ 'message': 'Data not found' });
                    return;
                }

                if (recursive === false) {
                    data = reformatResponse(data);
                }

                let results = [];
                let today = new Date();
                let thisYear = today.getFullYear().toString();
                let test;
                if (data[0]['data']['http']['response']['request'].hasOwnProperty('tls_log')) {
                    test = data[0]['data']['http']['response']['request']['tls_log']['handshake_log']['server_certificates']['certificate']['parsed']['validity']['end'].startsWith(thisYear);
                } else {
                    test = data[0]['data']['http']['response']['request']['tls_handshake']['server_certificates']['certificate']['parsed']['validity']['end'].startsWith(thisYear);
                }
                for (let i = 0; i < data.length; i++) {
                    if (test) {
                        let tempDate;
                        if (data[0]['data']['http']['response']['request'].hasOwnProperty('tls_log')) {
                            tempDate = new Date(data[i]['data']['http']['response']['request']['tls_log']['handshake_log']['server_certificates']['certificate']['parsed']['validity']['end']);
                        } else {
                            tempDate = new Date(data[i]['data']['http']['response']['request']['tls_handshake']['server_certificates']['certificate']['parsed']['validity']['end']);
                        }
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
     *   - name: Port 443 scans - Fetch certificates for the internal domain
     *     description: Fetch the full records for the associated internal domain
     *   - name: Port 443 scans - Count certificates for the internal domain
     *     description: Count the number of records for the associated internal domain
     *
     * /api/v1.0/zgrab/443/corp_certs:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Fetch the full records for the internal domain specified in the config file.
     *     tags: [Port 443 scans - Fetch certificates for the internal domain]
     *     produces:
     *       - application/json
     *     responses:
     *       200:
     *         description: Returns the zgrab port scan records for the internal domain specified in the config file.
     *         type: array
     *         items:
     *           type: object
     *           properties:
     *             ip:
     *               type: string
     *               example: "12.23.34.56"
     *             data.tls:
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
     * /api/v1.0/zgrab/443/corp_certs?count=1:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Count the records for the internal domain specified in the config file.
     *     tags: [Port 443 scans - Count certificates for the internal domain]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: count
     *         type: string
     *         required: true
     *         description: Set to 1 in order to retrieve the count of matching records
     *         in: query
     *     responses:
     *       200:
     *         description: Returns the number of relevant scans.
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
    router.route('/zgrab/443/corp_certs')
        // get info on corporate certs
        .get(function (req, res) {
            let count = false;

            if (!is_valid_strings(req.query)) {
                res.status(400).json({ 'message': 'Multiple query parameters are not allowed.' });
                return;
            }

            if (req.query.hasOwnProperty('count') && req.query.count === '1') {
                count = true
            }

            let promise = zgrabPort.getSSLByCorpNamePromise(envConfig.internalDomain, count);

            promise.then(function (data) {
                if (!data) {
                    res.status(404).json({ 'message': 'Records not found' });
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
     *   - name: Port 80 scans - Fetch zones list
     *     description: Return a list of all of the zones that responded to a port 80 TCP connection.
     *
     * /api/v1.0/zgrab/80/zones:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Retrieve the list of all zones that responded to a port 80 response. This will include zones that
     *                  redirected to another site.
     *     tags: [Port 80 scans - Fetch zones list]
     *     produces:
     *       - application/json
     *     responses:
     *       200:
     *         description: Returns the distinct zones for port 80
     *         schema:
     *           $ref: '#/definitions/HTTPSZoneList'
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
    router.route('/zgrab/80/zones')
        // get info on a specific zones
        .get(function (req, res) {
            let promise = zgrab80.getDistinctZonesPromise();

            promise.then(function (data) {
                if (!data) {
                    res.status(404).json({ 'message': 'Error performing distinct call' });
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
     *   - name: Port 80 scans - Fetch zone
     *     description: Returns all records associated with the requested zone.
     *
     * /api/v1.0/zgrab/80/zones/{zone}:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Retrieve all zgrab scan data with the associated zone
     *     tags: [Port 80 scans - Fetch zone]
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
     *         description: Returns the relevant scans.
     *         type: array
     *         items:
     *           $ref: '#/definitions/HTTPScanResponse'
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
     * /api/v1.0/zgrab/80/zones/{zone}?count=1:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Retrieve all zgrab scan data with the associated zone
     *     tags: [Port 80 scans - Fetch zone]
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
     *         description: Set to 1 in order to retrieve the count of matching records
     *         in: query
     *     responses:
     *       200:
     *         description: Returns the number of relevant scans.
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
    router.route('/zgrab/80/zones/:zone')
        // get info on a specific zones
        .get(function (req, res) {
            if (!(req.params.hasOwnProperty('zone'))) {
                res.status(400).json({ 'message': 'A zone must be provided.' });
                return;
            }

            if (!is_valid_strings(req.query)) {
                res.status(400).json({ 'message': 'Multiple query parameters are not allowed.' });
                return;
            }

            let count = false;
            if (req.query.hasOwnProperty('count') && req.query.count === '1') {
                count = true
            }

            let promise = zgrab80.getRecordsByZonePromise(zone, count);

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
     *   - name: Port 80 scans - Fetch domain list
     *     description: Returns the list of domains that responded to a port 80 request.
     *
     * /api/v1.0/zgrab/80/domains:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Returns the list of domains that responded to a port 80 request.
     *     tags: [Port 80 scans - Fetch domain list]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: limit
     *         type: number
     *         required: false
     *         description: Limit the number of domains per page.
     *         in: query
     *       - name: page
     *         type: number
     *         required: false
     *         description: The page to request. This must be set in conjunction with the limit parameter. The default is 1.
     *         in: query
     *     responses:
     *       200:
     *         description: Returns the relevant set or subset of domains.
     *         type: array
     *         items:
     *           type: object
     *           properties:
     *             domain:
     *               type: string
     *               example: "www.example.org"
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
     * /api/v1.0/zgrab/80/domains?count=1:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Counts the list of domains that responded to a port 80 request.
     *     tags: [Port 80 scans - Fetch domain list]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: count
     *         type: string
     *         required: true
     *         description: Set to 1 in order to retrieve the count of matching records
     *         in: query
     *     responses:
     *       200:
     *         description: Returns the number of relevant scans.
     *         schema:
     *           $ref: '#/definitions/CountResponse'
     *       400:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     */
    router.route('/zgrab/80/domains')
        // get list of domains that respond to port 80
        .get(function (req, res) {
            let count = false;

            if (!is_valid_strings(req.query)) {
                res.status(400).json({ 'message': 'Multiple query parameters are not allowed.' });
                return;
            }

            if (req.query.hasOwnProperty('count') && req.query.count === '1') {
                count = true;
            }

            let limit = 0;
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

            let promise = zgrab80.getDomainListPromise(count, limit, page);

            promise.then(function (data) {
                if (!data) {
                    res.status(500).json({ 'message': 'Error retrieving list' });
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
     *   - name: Port 80 scans - Fetch IPs list
     *     description: Returns the list of IPs that responded to a port 80 request.
     *
     * /api/v1.0/zgrab/80/ips:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Returns the list of IPs that responded to a port 80 request.
     *     tags: [Port 80 scans - Fetch IPs list]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: limit
     *         type: number
     *         required: false
     *         description: Limit the number of IPs per page.
     *         in: query
     *       - name: page
     *         type: number
     *         required: false
     *         description: The page to request. This must be set in conjunction with the limit parameter. The default is 1.
     *         in: query
     *     responses:
     *       200:
     *         description: Returns the relevant set or subset of IPs.
     *         type: array
     *         items:
     *           type: object
     *           properties:
     *             ip:
     *               type: string
     *               example: "8.8.8.8"
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
     * /api/v1.0/zgrab/80/ips?count=1:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Counts the list of IPs that responded to a port 80 request.
     *     tags: [Port 80 scans - Fetch IPs list]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: count
     *         type: string
     *         required: true
     *         description: Set to 1 in order to retrieve the count of matching records
     *         in: query
     *     responses:
     *       200:
     *         description: Returns the number of relevant scans.
     *         schema:
     *           $ref: '#/definitions/CountResponse'
     *       400:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     */
    router.route('/zgrab/80/ips')
        // get list of IPs that respond to Port 80
        .get(function (req, res) {

            if (!is_valid_strings(req.query)) {
                res.status(400).json({ 'message': 'Multiple query parameters are not allowed.' });
                return;
            }

            let count = false;
            if (req.query.hasOwnProperty('count') && req.query.count === '1') {
                count = true;
            }

            let limit = 0;
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

            let promise = zgrab80.getIPListPromise(count, limit, page);

            promise.then(function (data) {
                if (!data) {
                    res.status(500).json({ 'message': 'Error retrieving list' });
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
     *   - name: Port 80 scans - Fetch headers
     *     description: Returns all records associated with the requested header.
     *
     * /api/v1.0/zgrab/80/headers/{header}:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Retrieve all zgrab scan data with the associated header.
     *     tags: [Port 80 scans - Fetch headers]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: header
     *         type: string
     *         required: true
     *         description: The name of the header to fetch.
     *         in: path
     *       - name: zone
     *         type: string
     *         required: false
     *         description: The zone ("example.org", "example.com", etc.) to fetch.
     *         in: path
     *     responses:
     *       200:
     *         description: Returns the relevant header responses.
     *         schema:
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
     * /api/v1.0/zgrab/80/headers/{header}?count=1:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Retrieve all zgrab scan data with the associated header.
     *     tags: [Port 80 scans - Fetch headers]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: header
     *         type: string
     *         required: true
     *         description: The name of the header to fetch.
     *         in: path
     *       - name: count
     *         type: string
     *         required: true
     *         description: Set to 1 in order to retrieve the count of matching records
     *         in: query
     *       - name: zone
     *         type: string
     *         required: false
     *         description: The zone ("example.org", "example.com", etc.) to fetch.
     *         in: path
     *     responses:
     *       200:
     *         description: Returns the number of relevant header counts.
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
     * /api/v1.0/zgrab/80/headers/{header}?distinct=1:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Retrieve all distinct header values for the associated header.
     *     tags: [Port 80 scans - Fetch headers]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: header
     *         type: string
     *         required: true
     *         description: The name of the header to fetch.
     *         in: path
     *       - name: distinct
     *         type: string
     *         required: true
     *         description: Set to 1 in order to retrieve the count of distinct values for the header.
     *         in: query
     *       - name: zone
     *         type: string
     *         required: false
     *         description: The zone ("example.org", "example.com", etc.) to fetch.
     *         in: path
     *     responses:
     *       200:
     *         description: Returns the header value and corresponding count of each value.
     *         type: array
     *         items:
     *           type: object
     *           properties:
     *             _id:
     *                type: array
     *                items:
     *                  type: string
     *                  example: "Apache"
     *             count:
     *               type: number
     *               example: 10
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
     * /api/v1.0/zgrab/80/headers/{header}?value={value}:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Retrieve all distinct header values for the associated header.
     *     tags: [Port 80 scans - Fetch headers]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: header
     *         type: string
     *         required: true
     *         description: The name of the header to fetch.
     *         in: path
     *       - name: value
     *         type: string
     *         required: true
     *         description: Limit results to this this specific value for the provided header.
     *         in: query
     *       - name: zone
     *         type: string
     *         required: false
     *         description: The zone ("example.org", "example.com", etc.) to fetch.
     *         in: path
     *     responses:
     *       200:
     *         description: Returns the header value and corresponding count of each value.
     *         schema:
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
    router.route('/zgrab/80/headers/:header')
        .get(function (req, res) {
            if (!(req.params.hasOwnProperty('header'))) {
                res.status(400).json({
                    'message': 'A header value must be provided.',
                });
                return;
            }

            if (!is_valid_strings(req.query)) {
                res.status(400).json({ 'message': 'Multiple query parameters are not allowed.' });
                return;
            }

            let header = req.params.header;
            let promise;
            let count = false;
            let zone = '';
            if (req.query.hasOwnProperty('zone') && req.query.zone !== '') {
                zone = req.query.zone;
            }

            if (req.query.hasOwnProperty('count') && req.query.count === '1') {
                promise = zgrab80.getHttpHeaderPromise(header, zone, true);
                count = true;
            } else if (req.query.hasOwnProperty('distinct') &&
                req.query.distinct === '1') {
                promise = zgrab80.getDistinctHttpHeaderPromise(header, zone);
            } else if (req.query.hasOwnProperty('value')) {
                promise = zgrab80.getHttpHeaderByValuePromise(header, req.query.value, zone);
            } else {
                promise = zgrab80.getHttpHeaderPromise(header, zone, false);
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
     *   - name: Port counts - Fetch summary statistics
     *     description: Returns counts for the total number of records in each collection.
     *
     * /api/v1.0/zgrab/counts:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Returns counts for the total number of records in each collection.
     *     tags: [Port counts - Fetch summary statistics]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: collection
     *         type: string
     *         required: true
     *         description: The collection to be counted.
     *         enum: [zgrab80, zgrab443, zgrabPort]
     *         in: path
     *     responses:
     *       200:
     *         description: Returns the count of records for the relevant collection.
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

    router.route('/zgrab/counts')
        .get(function (req, res) {
            if (!is_valid_strings(req.query)) {
                res.status(400).json({ 'message': 'Multiple query parameters are not allowed.' });
                return;
            }

            if (!(req.query.hasOwnProperty('collection'))) {
                res.status(400).json({
                    'message': 'A collection value must be provided.',
                });
                return;
            }

            let collection = req.query.collection;
            let promise;


            if (collection === "zgrab80") {
                promise = zgrab80.getFullCountPromise();
            } else if (collection === "zgrab443") {
                promise = zgrab443.getFullCountPromise();
            } else if (collection === "zgrabPort") {
                promise = zgrabPort.getFullCountPromise();
            } else {
                res.status(400).json({ 'message': 'Unknown collection value' });
                return;
            }

            promise.then(function (data) {
                if (!data || data.length === 0) {
                    res.status(500).json({ 'message': 'Error retrieving count' });
                    return;
                }

                res.status(200).json({ 'count': data });
                return;
            });
        });

    return (router);
};
