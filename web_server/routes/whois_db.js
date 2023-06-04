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
const whoisDB = require('../config/models/whois_db');

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
 *
 *   Whois-Response:
 *     type: object
 *     description: This object varies greatly based on the response from the various whois servers.
 *     properties:
 *       domain:
 *         type: string
 *         description: Often set to null
 *         example: "example.org"
 *       domain_name:
 *         type: array
 *         description: Sometimes a single string
 *         items:
 *           type: string
 *           example: "example.org"
 *       creation_date:
 *         type: array
 *         description: Varies. Sometimes a string based on the whois server
 *         items:
 *           type: string
 *           example: 2018-05-07T17:56:10.480Z
 *       updated:
 *         type: string
 *         example: 2018-05-07T17:56:10.480Z
 *       updated_date:
 *         type: array
 *         description: Varies. Sometimes a string based on the whois server
 *         items:
 *           type: string
 *           example: 2018-05-07T17:56:10.480Z
 *       expiration_date:
 *         type: string
 *         example: 2018-05-07T17:56:10.480Z
 *       status:
 *         type: array
 *         items:
 *           type: string
 *           example: ["clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited"]
 *       dnssec:
 *         type: string
 *         example: "Unsigned"
 *       name:
 *         type: string
 *         example: "Domain Administrator"
 *       org:
 *         type: string
 *         example: "Acme Incorporated"
 *       address:
 *         type: string
 *         example: "123 Park Avenue"
 *       city:
 *         type: string
 *         example: "San Jose"
 *       state:
 *         type: string
 *         example: "California"
 *       country:
 *         type: string
 *         example: "US"
 *       zipcode:
 *         type: string
 *         example: "95110"
 *       registrar:
 *         type: string
 *         example: "NOM-IQ Ltd dba Com Laude"
 *       referral_url:
 *         type: string
 *         example: "http://www.comlaude.com"
 *       whois_server:
 *         type: string
 *         description: Sometimes an array
 *         example: "whois.comlaude.com"
 *       emails:
 *         type: array
 *         description: Sometimes a single string
 *         items:
 *           type: string
 *           example: "dns-admin@example.org"
 *       name_servers:
 *         type: array
 *         items:
 *           type: string
 *           example: "adobe-dns-01.adobe.com"
 *       text:
 *         type: string
 *         description: The plain text version of the record
 *         example: 'Domain Name: example.org\nWHOIS Server: NIC .PE\nSponsoring Registrar:...'
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
     *   - name: Whois - Whois lookups
     *     description: Lookup whois records based on various properties.
     *   - name: Whois - Whois zone lookup
     *     description: Lookup whois records for the specified zone.
     *   - name: Whois - Whois lookups distinct name_servers
     *     description: Retrieve the complete list of distinct name_servers.
     *   - name: Whois - Whois lookups name server groups
     *     description: Retrieve the list of first level domains that can be used to group the name_servers.
     *   - name: Whois - Whois count
     *     description: Count records based on different properties.
     *
     * /api/v1.0/whois_db:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Finds whois records based on different properties. At least one parameter must be provided.
     *     tags: [Whois - Whois lookups]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: name_server
     *         type: string
     *         required: false
     *         description: A regex will be performed on this value to find name_servers with the provided string
     *         in: query
     *       - name: dnssec
     *         type: string
     *         required: false
     *         description: Find records whose DNSSec value matches this value.
     *         enum: [signed, unsigned, inactive, unknown]
     *         in: query
     *       - name: email
     *         type: string
     *         required: false
     *         description: Search for whois records associated with this email
     *         in: query
     *     responses:
     *       200:
     *         description: Returns an object representing the Whois response. Exact format varies.
     *         type: array
     *         items:
     *           $ref: '#/definitions/Whois-Response'
     *       400:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     *
     * /api/v1.0/whois_db?zone={zone}:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Finds whois records based on a specific zone.
     *     tags: [Whois - Whois zone lookup]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: zone
     *         type: string
     *         required: true
     *         description: The zone ("e.g. example.org") whose record you need
     *         in: query
     *     responses:
     *       200:
     *         description: Returns an object representing the Whois response. Exact format varies.
     *         type: object
     *         schema:
     *           $ref: '#/definitions/Whois-Response'
     *       400:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     *
     * /api/v1.0/whois_db?disctinct_groups=1:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Retrieve the list of the name servers' first level domains for the purposes of grouping.
     *     tags: [Whois - Whois lookups name server groups]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: distinct_groups
     *         type: string
     *         required: true
     *         description: Set to 1 in order to retrieve the list of first level domains for the name_servers.
     *         in: query
     *     responses:
     *       200:
     *         description: Returns an object with the first level domains of the name servers.
     *         type: object
     *         properties:
     *           name_server_groups:
     *             type: array
     *             items:
     *               type: string
     *               example: example.org
     *       400:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     *
     * /api/v1.0/whois_db?disctinct=1:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Return the complete, distinct list of all name_servers that are in use
     *     tags: [Whois - Whois lookups distinct name_servers]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: distinct
     *         type: string
     *         required: true
     *         description: Set to 1 in order to retrieve the complete list of all name_servers.
     *         in: query
     *     responses:
     *       200:
     *         description: Returns an object with the array of distinct name server values.
     *         type: object
     *         properties:
     *           name_servers:
     *             type: array
     *             items:
     *               type: string
     *               example: name-sever-1.example.org
     *       400:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     *
     * /api/v1.0/whois_db?count=1:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Count records based on different properties. If no other parameters are provided, a count of all records is returned.
     *     tags: [Whois - Whois count]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: count
     *         type: string
     *         required: true
     *         description: Set to 1 in order to retrieve the count.
     *         in: query
     *       - name: name_server
     *         type: string
     *         required: false
     *         description: A regex will be performed on this value to find name_servers with the provided string.
     *         in: query
     *       - name: dnssec
     *         type: string
     *         required: false
     *         description: Find records whose DNSSec value matches this value.
     *         enum: [signed, unsigned, inactive, unknown]
     *         in: query
     *       - name: email
     *         type: string
     *         required: false
     *         description: Search for whois records associated with this email
     *         in: query
     *     responses:
     *       200:
     *         description: Returns an object representing the number of matched Whois records
     *         type: object
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
    router.route('/whois_db')
        .get(function (req, res) {
            let promise;

            if (!is_valid_strings(req.query)) {
                res.status(400).json({ 'message': 'Multiple query parameters are not allowed.' });
                return;
            }

            if (req.query.hasOwnProperty('zone')) {
                promise = whoisDB.getRecordByZonePromise(req.query.zone);
            } else if (req.query.hasOwnProperty('name_server')) {
                let ns = req.query.name_server;
                if (ns === 'null') {
                    if (req.query.hasOwnProperty('count') && req.query.count === '1') {
                        promise = whoisDB.getWhoisDNSServerNullRecords(true);
                    } else {
                        promise = whoisDB.getWhoisDNSServerNullRecords(false);
                    }
                } else {
                    if (req.query.hasOwnProperty('count') && req.query.count === '1') {
                        promise = whoisDB.getWhoisDNSServerRecords(ns, true);
                    } else {
                        promise = whoisDB.getWhoisDNSServerRecords(ns, false);
                    }
                }
            } else if (req.query.hasOwnProperty('distinct') && req.query.distinct === '1') {
                promise = whoisDB.getWhoisDistinctDNSServerRecords();
                promise.then(function (data) {
                    if (data === null) {
                        res.status(404).json({ 'message': 'Error fetching list' });
                        return;
                    }

                    // Merge the results into a case-insensitve list
                    let new_list = new Set();
                    for (let entry in data) {
                        if (data[entry] != null) {
                            new_list.add(data[entry].toLowerCase());
                        }
                    }
                    res.status(200).json({ "name_servers": Array.from(new_list) });
                });
                return;
            } else if (req.query.hasOwnProperty('distinct_groups') && req.query.distinct_groups === '1') {
                promise = whoisDB.getWhoisDistinctDNSServerGroupRecords();
                promise.then(function (data) {
                    if (data === null) {
                        res.status(404).json({ 'message': 'Error fetching list' });
                        return;
                    }
                    res.status(200).json({ "name_server_groups": data });
                });
                return;
            } else if (req.query.hasOwnProperty('dnssec')) {
                let dnssec = req.query.dnssec;
                if (dnssec !== 'signed'
                    && dnssec !== 'unsigned'
                    && dnssec !== 'inactive'
                    && dnssec !== 'unknown') {
                    res.status(400).json({ 'message': 'Unrecognized DNSSEC request' });
                    return;
                }

                if (dnssec === 'unknown') {
                    if (req.query.hasOwnProperty('count') && req.query.count === '1') {
                        promise = whoisDB.getWhoisDNSSECOtherRecords(true);
                    } else {
                        promise = whoisDB.getWhoisDNSSECOtherRecords(false);
                    }
                } else {
                    if (req.query.hasOwnProperty('count') && req.query.count === '1') {
                        promise = whoisDB.getWhoisDNSSECRecords(dnssec, true);
                    } else {
                        promise = whoisDB.getWhoisDNSSECRecords(dnssec, false);
                    }
                }
            } else if (req.query.hasOwnProperty('email')) {
                let email = req.query.email;
                let re = new RegExp('^([a-zA-Z0-9_\\-\\.]+)@([a-zA-Z0-9_\\-\\.]+)\.([a-zA-Z]{2,5})$');
                if (email !== 'none' && !(re.test(email))) {
                    res.status(400).json({
                        'message': 'An invalid email has been provided',
                    });
                    return;
                }
                let count = false;
                if (req.query.hasOwnProperty('count') && req.query.count === '1') {
                    count = true;
                }
                if (email === 'none') {
                    promise = whoisDB.getWhoisEmailNullRecords(count);
                } else {
                    promise = whoisDB.getWhoisEmailRecords(email, count);
                }
            } else if (req.query.hasOwnProperty('count')) {
                promise = whoisDB.getWhoisRecordCount();
                promise.then(function (data) {
                    if (data === null) {
                        res.status(404).json({ 'message': 'Count failed.' });
                        return;
                    }

                    if (req.query.hasOwnProperty('count') && req.query.count === '1') {
                        res.status(200).json({ 'count': data });
                    } else {
                        res.status(200).json(data);
                    }
                    return;
                });
            } else {
                res.status(400).json({ 'message': 'A zone, count, email, dnssec, distinct, distinct_groups, or name_server value must be provided.' });
                return;
            }
            promise.then(function (data) {
                if (data === null) {
                    res.status(404).json({ 'message': 'Records not found' });
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

    return (router);
};
