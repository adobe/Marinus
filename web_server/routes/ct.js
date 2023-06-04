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
const ct = require('../config/models/cert_transparency');


function isValidDate(d_string) {
    // Currently assumes Unix timestamp
    let d = parseInt(d_string);
    return !isNaN(d);
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
 * securityDefinitions:
 *   # X-API-Key: abcdef12345
 *   APIKeyHeader:
 *     type: apiKey
 *     in: query
 *     name: apiKey
 *
 * definitions:
 *   CT-CertificateRecord:
 *     type: object
 *     properties:
 *       basic_constraint_ca:
 *         type: boolean
 *         example: true
 *         description: Whether the certificate has basic constraints applied
 *       extended_key_usages:
 *         type: array
 *         items:
 *           type: string
 *         example: '["serverAuth","clientAuth"]'
 *         description: Extended key usages from the certificate
 *       isExpired:
 *         type: boolean
 *         example: true
 *         description: Whether the certificate is expired
 *       isSelfSigned:
 *         type: boolean
 *         example: true
 *         description: Whether the certificate is self signed
 *       issuer_common_name:
 *         type: array
 *         description: The issuer common name values
 *         items:
 *           type: string
 *       issuer_country_name:
 *         type: array
 *         description: The issuer country name values
 *         items:
 *           type: string
 *       key_usages:
 *         type: array
 *         description: The key usage values
 *         items:
 *           type: string
 *       not_after:
 *         type: string
 *         example: '2016-11-14T23:59:59.000Z'
 *         description: The expiry date
 *       not_before:
 *         type: string
 *         example: '2016-11-14T23:59:59.000Z'
 *         description: The certificate start date
 *       marinus_createdate:
 *         type: string
 *         example: '2016-11-14T23:59:59.000Z'
 *         description: The date Marinus recorded the certificate
 *       marinus_updated:
 *         type: string
 *         example: '2016-11-14T23:59:59.000Z'
 *         description: The date Marinus last updated the certificate
 *       serial_number:
 *         type: string
 *         example: a1:b2:c3:d4:e5:f6
 *         description: The serial number for the certificate
 *       signature_algorithm:
 *         type: string
 *         example: RSA-SHA256
 *         description: The certificate signature algorithm
 *       subject_common_names:
 *         type: array
 *         description: The subject common names values
 *         items:
 *           type: string
 *       subject_dns_names:
 *         type: array
 *         description: The subject dns names values
 *         items:
 *           type: string
 *       subject_ip_addresses:
 *         type: array
 *         description: The subject ip addresses values
 *         items:
 *           type: string
 *       subject_locality_name:
 *         type: array
 *         description: The subject locality name values
 *         items:
 *           type: string
 *       subject_orgnaization_name:
 *         type: array
 *         description: The subject organization name values
 *         items:
 *           type: string
 *       subject_organizational_unit_name:
 *         type: array
 *         description: The subject organizational unit name values
 *         items:
 *           type: string
 *       subject_postal_code:
 *         type: array
 *         description: The subject postal code values
 *         items:
 *           type: string
 *       subject_state_or_province_name:
 *         type: array
 *         description: The subject state or province name values
 *         items:
 *           type: string
 *       subject_street_address:
 *         type: array
 *         description: The subject street address values
 *         items:
 *           type: string
 *       raw:
 *         type: string
 *         example: 'MIIFFDCCA/ygAwIBAgIQDh.....'
 *         description: The raw certificate
 *       fullcertificate:
 *         type: string
 *         example: 'Certificate:\n  tbsCertificate:\n    version: 3\n    serialNumber:.....'
 *         description: The full certificate in English
 *       sources:
 *         type: array
 *         example: '["pilot", "aviator", "facebook"]'
 *         description: Where the CT certificate was found
 *         items:
 *           type: string
 *       fingerprint_sha1:
 *         type: string
 *         example: '25e77c1b23adfd3d16502cea71bd86b7dde783bb'
 *         description: The SHA1 fingerprint of the raw certificate
 *       fingerprint_sha256:
 *         type: string
 *         example: 'd8a9a9c144d3c9122f7e8d8b8ae2c0c848d35aa1104ec44f42ebcde5e21132e3'
 *         description: The SHA256 fingerprint of the raw certificate
 *       scts:
 *         type: array
 *         example: '[{version: number, log_id: string, log_name: string, timestamp: date, hash_alg: number, sig_alg: number, sig_alg_name: string, signature: string, extensions: string}]'
 *         description: The SCTS record
 *         items:
 *           type: object
 *
 *   CT-LogResponse:
 *     type: array
 *     items:
 *       $ref: '#/definitions/CT-CertificateRecord'
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
     *   - name: CT - Organization search
     *     description: Check whether the provided organization is in any of the saved certificate transparency logs.
     *
     * /api/v1.0/ct/org:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Finds Certificate Transparency certificates based on their organization.
     *     tags: [CT - Organization search]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: org
     *         type: string
     *         required: true
     *         description: The organization
     *         in: query
     *     responses:
     *       200:
     *         description: Returns a JSON object with the matched certificates.
     *         schema:
     *           $ref: '#/definitions/CT-LogResponse'
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
     * /api/v1.0/ct/org?count=1&org={org}:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Counts Certifcate Transparency certificates issued to a specific organization.
     *     tags: [CT - Organization search]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: org
     *         type: string
     *         required: true
     *         description: The organization
     *         in: query
     *       - name: count
     *         type: integer
     *         required: true
     *         description: Set to 1 to count the number of matching results
     *         in: query
     *     responses:
     *       200:
     *         description: Returns a JSON object with the number of matched certificates.
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
    router.route('/ct/org')
        .get(function (req, res) {

            if (!is_valid_strings(req.query)) {
                res.status(400).json({ 'message': 'Multiple query parameters are not allowed.' });
                return;
            }

            if (!(req.query.hasOwnProperty('org'))) {
                res.status(400).json({ 'message': 'An org must be provided.' });
                return;
            }
            let org = req.query.org;
            let promise;
            if (req.query.hasOwnProperty('count') && req.query.count === '1') {
                promise = ct.getSSLOrgCountPromise(org);
            } else {
                promise = ct.getCertTransOrgPromise(org);
            }
            promise.then(function (data) {
                if (data === null) {
                    res.status(404).json({ 'message': 'Org not found' });
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
     *   - name: CT - Zone search
     *     description: Check whether the provided zone (e.g. "example.org") is in any saved certificate transparency logs.
     *
     * /api/v1.0/ct/zone:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Finds CT certificates based on their zone (e.g. "example.org", "example.com", etc.).
     *     tags: [CT - Zone search]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: zone
     *         type: string
     *         required: true
     *         description: The zone to search (e.g. "example.org", "example.com", etc.)
     *         in: query
     *     responses:
     *       200:
     *         description: Returns a JSON object with the matched certificates.
     *         schema:
     *           $ref: '#/definitions/CT-LogResponse'
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
     * /api/v1.0/ct/zone?count=1&zone={zone}:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Counts CT certificates based on their zone (e.g. "example.org", "example.com", etc.).
     *     tags: [CT - Zone search]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: zone
     *         type: string
     *         required: true
     *         description: The zone to search (e.g. "example.org", "example.com", etc.)
     *         in: query
     *       - name: count
     *         type: integer
     *         required: true
     *         description: Set to 1 to count the number of matching results
     *         in: query
     *     responses:
     *       200:
     *         description: Returns a JSON object with the number of matched certificates.
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
    router.route('/ct/zone')
        .get(function (req, res) {

            if (!is_valid_strings(req.query)) {
                res.status(400).json({ 'message': 'Multiple query parameters are not allowed.' });
                return;
            }

            if (!(req.query.hasOwnProperty('zone'))) {
                res.status(400).json({ 'message': 'A zone name must be provided.' });
                return;
            }
            let count = false;
            if (req.query.hasOwnProperty('count') && req.query.count === '1') {
                count = true;
            }
            let promise = ct.getCertTransZonePromise(req.query.zone, count);

            promise.then(function (data) {
                if (data === null) {
                    res.status(404).json({ 'message': 'Zone not found' });
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
     *   - name: CT - Common name search
     *     description: Finds CT certificates based on their common name and/or subject_dns_names.
     *
     * /api/v1.0/ct/common_name:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Check whether the provided value (e.g. "www.example.org") is in the common name or
     *                  subject_dns_names of any saved certificate transparency logs.
     *     tags: [CT - Common name search]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: cn
     *         type: string
     *         required: true
     *         description: The common name value to search (e.g. "www.example.org", etc.)
     *         in: query
     *     responses:
     *       200:
     *         description: Returns a JSON object with the matched certificates.
     *         schema:
     *           $ref: '#/definitions/CT-LogResponse'
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
    router.route('/ct/common_name')
        .get(function (req, res) {

            if (!is_valid_strings(req.query)) {
                res.status(400).json({ 'message': 'Multiple query parameters are not allowed.' });
                return;
            }

            if (!(req.query.hasOwnProperty('cn'))) {
                res.status(400).json({ 'message': 'A CN/DNS name must be provided.' });
                return;
            }
            let promise = ct.getCertTransCNPromise(req.query.cn);

            promise.then(function (data) {
                if (data === null) {
                    res.status(404).json({ 'message': 'CN not found' });
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
     *   - name: CT - Common name IP search
     *     description: Check whether the provided IP (e.g "1.2.3.4") is in the common name/subject_dns_names of any
     *                  saved certificate transparency logs.
     *
     * /api/v1.0/ct/ip:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Finds CT certificates based on whether the provided IP (e.g. "1.2.3.4") is in their common name
     *                  or subject_dns_names.
     *     tags: [CT - Common name IP search]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: ip
     *         type: string
     *         required: true
     *         description: The IP value to search (e.g. "1.2.3.4" etc.)
     *         in: query
     *     responses:
     *       200:
     *         description: Returns a JSON object with the matched certificates.
     *         schema:
     *           $ref: '#/definitions/CT-LogResponse'
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
    router.route('/ct/ip')
        .get(function (req, res) {

            if (!is_valid_strings(req.query)) {
                res.status(400).json({ 'message': 'Multiple query parameters are not allowed.' });
                return;
            }

            if (!(req.query.hasOwnProperty('ip'))) {
                res.status(400).json({ 'message': 'An IP address must be provided.' });
                return;
            }
            let promise = ct.getCertTransCNPromise(req.query.ip);

            promise.then(function (data) {
                if (data === null) {
                    res.status(404).json({ 'message': 'IP not found' });
                    return;
                }
                res.status(200);
                res.json(data);
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
     *   - name: CT - Serial number search
     *     description: Find CT certificates that contain the provied serial number represented as a hex string.
     *   - name: CT - Serial number count
     *     description: Count the CT certificates that contain the provied serial number represented as a hex string.
     *
     * /api/v1.0/ct/serial_number/{sn}:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Check for certificates with the provided serial number represented as a hex string
     *     tags: [CT - Serial number search]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: sn
     *         type: string
     *         required: true
     *         description: The serial number for the certificate expressed as a hex string
     *         in: path
     *     responses:
     *       200:
     *         description: Returns a JSON object with the matched certificates.
     *         schema:
     *           $ref: '#/definitions/CT-LogResponse'
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
     * /api/v1.0/ct/serial_number/{sn}?count=1:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Count the certificates with the provided serial number represented as a hex string
     *     tags: [CT - Serial number count]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: sn
     *         type: string
     *         required: true
     *         description: The serial number for the certificate expressed as a hex string
     *         in: path
     *       - name: count
     *         type: integer
     *         required: true
     *         description: Set to 1 to count the number of matching results
     *         in: query
     *     responses:
     *       200:
     *         description: Returns a count of the matched certificates.
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
    router.route('/ct/serial_number/:sn')
        .get(function (req, res) {

            if (!is_valid_strings(req.query)) {
                res.status(400).json({ 'message': 'Multiple query parameters are not allowed.' });
                return;
            }

            if (!(req.params.hasOwnProperty('sn'))) {
                res.status(400).json({ 'message': 'A serial_number name must be provided.' });
                return;
            }

            let count = false;
            if (req.query.hasOwnProperty('count') && req.query.count == "1") {
                count = true;
            }

            let promise = ct.getCertTransBySerialNumberPromise(req.params.sn.toLowerCase(), count);

            promise.then(function (data) {
                if (data === null) {
                    res.status(404).json({ 'message': 'Serial number not found' });
                    return;
                }
                if (count) {
                    res.status(200).json({ 'count': data });
                    return;
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
     *   - name: CT - Fingerprint search
     *     description: Check whether the provided zone SHA1 or SHA256 hash matches any saved certificate transparency logs.
     *   - name: CT - Fingerprint search count
     *     description: Count when the provided zone SHA1 or SHA256 hash matches any saved certificate transparency logs.
     *
     * /api/v1.0/ct/fingerprint/{fingerprint}:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Finds CT certificates based on their SHA1 or SHA256 fingerprint.
     *     tags: [CT - Fingerprint search]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: fingerprint
     *         type: string
     *         required: true
     *         description: The SHA1 or SHA256 fingerprint
     *         in: path
     *     responses:
     *       200:
     *         description: Returns a JSON object with the matched certificates.
     *         schema:
     *           $ref: '#/definitions/CT-LogResponse'
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
     * /api/v1.0/ct/fingerprint/{fingerprint}?count=1:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Counts CT certificates based on their zone (e.g. "example.org", "example.com", etc.).
     *     tags: [CT - Fingerprint search count]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: fingerprint
     *         type: string
     *         required: true
     *         description: The SHA1 or SHA256 fingerprint
     *         in: path
     *       - name: count
     *         type: integer
     *         required: true
     *         description: Set to 1 to count the number of matching results
     *         in: query
     *     responses:
     *       200:
     *         description: Returns a JSON object with the number of matched certificates.
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
    router.route('/ct/fingerprint/:fingerprint')
        .get(function (req, res) {

            if (!is_valid_strings(req.query)) {
                res.status(400).json({ 'message': 'Multiple query parameters are not allowed.' });
                return;
            }

            if (!(req.params.hasOwnProperty('fingerprint'))) {
                res.status(400).json({
                    'message': 'An fingerprint value must be provided.',
                });
                return;
            }

            var count = false;
            if (req.query.hasOwnProperty('count') && req.query.count === "1") {
                count = true;
            }

            let promise;
            if (req.params.fingerprint.length === 64) {
                promise = ct.getCTCertByFingerprintSHA256(req.params.fingerprint, count);
            } else if (req.params.fingerprint.length === 40) {
                promise = ct.getCTCertByFingerprintSHA1(req.params.fingerprint, count);
            } else {
                res.status(400).json({ 'message': 'Invalid fingerprint value.' });
                return;
            }

            promise.then(function (data) {
                if (data === null) {
                    res.status(404).json({ 'message': 'Fingerprint not found' });
                    return;
                }

                if (count) {
                    res.status(200).json({ 'count': data });
                    return;
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
   *   - name: CT - Marinus date search
   *     description: Check for certificates based on when they were recorded or updated within Marinus.
   *   - name: CT - Marinus date search count
   *     description: Count certificates based on when they were recorded or updated within Marinus.
   *
   * /api/v1.0/ct/marinus_dates:
   *   get:
   *   # Operation-specific security:
   *     security:
   *       - APIKeyHeader: []
   *     description: Check for certificates based on when they were recorded within Marinus. The Marinus creation date and/or update date is not the same as the certificate creation date.
   *     tags: [CT - Marinus date search]
   *     produces:
   *       - application/json
   *     parameters:
   *       - name: search_type
   *         type: string
   *         required: true
   *         description: Only "gt", "lt", and "range" is allowed
   *         in: query
   *         enum: ["gt", "lt", "range"]
   *       - name: marinus_date
   *         type: string
   *         example: '1564970118000'
   *         required: true
   *         description: This is the default date for 'lt' and 'gt' searches. It is a Unix timestamp with milliseconds. It is used for the 'gt' value in a range check.
   *         in: query
   *       - name: end_date
   *         type: string
   *         example: '1564970118000'
   *         description: The 'lt' value in a range search. It is a Unix timestamp with milliseconds.
   *         required: false
   *         in: query
   *       - name: date_type
   *         type: string
   *         required: false
   *         description: Only "created", and "updated" are allowed. The default is "created."
   *         in: query
   *         enum: ["created", "updated"]
   *     responses:
   *       200:
   *         description: Returns a JSON array object with the matched certificates.
   *         schema:
   *           $ref: '#/definitions/CT-LogResponse'
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
   * /api/v1.0/ct/marinus_dates?count=1:
   *   get:
   *   # Operation-specific security:
   *     security:
   *       - APIKeyHeader: []
   *     description: Count certificates based on when they were recorded or updated within Marinus. The Marinus creation date and/or update date is not the same as the certificate creation date.
   *     tags: [CT - Marinus date search count]
   *     produces:
   *       - application/json
   *     parameters:
   *       - name: search_type
   *         type: string
   *         required: true
   *         description: Only "gt", "lt", and "range" is allowed
   *         in: query
   *         enum: ["gt", "lt", "range"]
   *       - name: date_type
   *         type: string
   *         required: false
   *         description: Only "created", and "updated" are allowed. The default is "created."
   *         in: query
   *         enum: ["created", "updated"]
   *       - name: marinus_date
   *         type: string
   *         example: '1564970118000'
   *         required: true
   *         description: This is the default date for 'lt' and 'gt' searches. It is a Unix timestamp with milliseconds. It is used for the 'gt' value in a range check.
   *         in: query
   *       - name: end_date
   *         type: string
   *         example: '1564970118000'
   *         description: The 'lt' value in a range search. It is a Unix timestamp with milliseconds.
   *         required: false
   *         in: query
   *       - name: count
   *         type: integer
   *         required: true
   *         description: Set to 1 to count the number of matching results
   *         in: query
   *     responses:
   *       200:
   *         description: Returns a JSON object with the number of matched certificates.
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
    router.route('/ct/marinus_dates')
        .get(function (req, res) {

            if (!is_valid_strings(req.query)) {
                res.status(400).json({ 'message': 'Multiple query parameters are not allowed.' });
                return;
            }

            if (!(req.query.hasOwnProperty('search_type'))) {
                res.status(400).json({
                    'message': 'A search type must be provided.',
                });
                return;
            }

            let search_type = req.query.search_type;

            if (search_type !== "gt" && search_type !== "lt" && search_type !== "range") {
                res.status(400).json({
                    'message': 'An invalid search type was be provided.',
                });
                return;
            }

            if (!(req.query.hasOwnProperty('marinus_date'))) {
                res.status(400).json({
                    'message': 'A Marinus date must be provided.',
                });
                return;
            }

            if (isValidDate(req.query.marinus_date) === false) {
                res.status(400).json({
                    'message': 'A Marinus date must be in a Unix timestamp format.',
                });
                return;
            }

            let timestamp = parseInt(req.query.marinus_date);

            var date_type = "created";
            if (req.query.hasOwnProperty('date_type') && req.query.count === "updated") {
                date_type = "updated";
            }

            var count = false;
            if (req.query.hasOwnProperty('count') && req.query.count === "1") {
                count = true;
            }

            let promise;
            if (search_type === "gt") {
                if (date_type == "created") {
                    promise = ct.getCTCertByGTMarinusUpdated(timestamp, count);
                } else {
                    promise = ct.getCTCertByGTMarinusCreate(timestamp, count);
                }
            } else if (search_type === "lt") {
                if (date_type == "created") {
                    promise = ct.getCTCertByLTMarinusUpdated(timestamp, count);
                } else {
                    promise = ct.getCTCertByLTMarinusCreate(timestamp, count);
                }
            } else {
                if (!(req.query.hasOwnProperty('end_date'))) {
                    res.status(400).json({
                        'message': 'An end_date must be provided for range searches.',
                    });
                    return;
                }

                if (isValidDate(req.query.end_date) === false) {
                    res.status(400).json({
                        'message': 'The end date must be in a JavaScript Date supported format.',
                    });
                    return;
                }

                let end_timestamp = parseInt(req.query.end_date);

                if (date_type == "created") {
                    promise = ct.getCTCertByMarinusCreateRange(timestamp, end_timestamp, count);
                } else {
                    promise = ct.getCTCertByMarinusUpdateRange(timestamp, end_timestamp, count);
                }
            }

            promise.then(function (data) {
                if (data === null) {
                    res.status(404).json({ 'message': 'Records not found' });
                    return;
                }

                if (count) {
                    res.status(200).json({ 'count': data });
                    return;
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
     *   - name: CT - Issuers list
     *     description: Get the list of issuer_common_names from the saved certificate transparency logs.
     *
     * /api/v1.0/ct/issuers:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Get the list of issuer_common_names from the saved certificate transparency logs.
     *     tags: [CT - Issuers list]
     *     produces:
     *       - application/json
     *     responses:
     *       200:
     *         description: A list of the Issuer Common Name values.
     *         type: array
     *         items:
     *           type: string
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     */
    router.route('/ct/issuers')
        .get(function (req, res) {
            let promise = ct.getDistinctIssuers(true);
            promise.then(function (data) {
                if (data === null) {
                    res.status(500).json({ 'message': 'Error with query' });
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
     *   - name: CT - Issuer search
     *     description: Check whether the provided issuer common name hash matches any saved certificate transparency logs.
     *
     * /api/v1.0/ct/issuer/{issuer}:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Finds CT certificates based on their issuer common name. Expired certificates are not included.
     *     tags: [CT - Issuer search]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: issuer
     *         type: string
     *         required: true
     *         description: The issuer common name value
     *         in: path
     *     responses:
     *       200:
     *         description: Returns a JSON object with the matched certificates.
     *         schema:
     *           $ref: '#/definitions/CT-LogResponse'
     *       404:
     *         description: No matching records found.
     *         schema:
     *           $ref: '#/definitions/ResultsNotFound'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     *
     * /api/v1.0/ct/issuer/{issuer}?count=1:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Counts CT certificates based on their issuer common name. Expired certificates are not included.
     *     tags: [CT - Issuer search]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: issuer
     *         type: string
     *         required: true
     *         description: The issuer common name value
     *         in: path
     *       - name: count
     *         type: integer
     *         required: true
     *         description: Set to 1 to count the number of matching results
     *         in: query
     *     responses:
     *       200:
     *         description: Returns a JSON object with the number of matched certificates.
     *         schema:
     *           $ref: '#/definitions/CountResponse'
     *       404:
     *         description: No matching records found.
     *         schema:
     *           $ref: '#/definitions/ResultsNotFound'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     */
    router.route('/ct/issuers/:issuer')
        .get(function (req, res) {
            let count = false;

            if (!is_valid_strings(req.query)) {
                res.status(400).json({ 'message': 'Multiple query parameters are not allowed.' });
                return;
            }

            if (req.query.hasOwnProperty('count') && req.query.count === '1') {
                count = true;
            }
            let promise = ct.getCertTransIssuers(req.params.issuer, count, true);
            promise.then(function (data) {
                if (data == null) {
                    res.status(404).json({ 'message': 'Issuer not found' });
                    return;
                }
                if (count) {
                    res.status(200).json({ 'count': data });
                    return;
                } else {
                    res.status(200).json(data);
                }
            });
        });

    /**
     * @swagger
     *
     * security:
     *   - APIKeyHeader: []
     *
     * tags:
     *   - name: CT - Id search
     *     description: Finds a certificate by its ID in the Mongo database.
     *
     * /api/v1.0/ct/id/{id}:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Finds CT certificates based on their ID in the Mongo database.
     *     tags: [CT - Id search]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: id
     *         type: string
     *         required: true
     *         description: The Mongo ID value
     *         in: path
     *     responses:
     *       200:
     *         description: Returns a JSON object with the matched certificates.
     *         schema:
     *           $ref: '#/definitions/CT-LogResponse'
     *       404:
     *         description: No matching records found.
     *         schema:
     *           $ref: '#/definitions/ResultsNotFound'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     */
    router.route('/ct/id/:id')
        .get(function (req, res) {
            let promise = ct.getCertTransById(req.params.id);

            promise.then(function (data) {
                if (data == null) {
                    res.status(404).json({ 'message': 'ID not found' });
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
     *   - name: CT - Download Id
     *     description: Allows a user to download a certificate by its ID in the Mongo database, SHA1, or SHA256 value.
     * /api/v1.0/ct/download/{id}:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Allows a user to download a certificate by its ID in the Mongo database, SHA1, or SHA256 value.
     *     tags: [CT - Download Id]
     *     produces:
     *       - application/octet-stream
     *     parameters:
     *       - name: id
     *         type: string
     *         required: true
     *         description: The ID value from the Mongo DB, SHA1 value, or SHA256 value.
     *         in: path
     *     responses:
     *       200:
     *         description: The certificate file.
     *         content:
     *           application/octet-stream:
     *             schema:
     *               type: string
     *               format: binary
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
    router.route('/ct/download/:id')
        .get(function (req, res) {
            let promise;
            if (req.params.id.length === 24) {
                promise = ct.getCertTransById(req.params.id);
            } else if (req.params.id.length === 40) {
                promise = ct.getCTCertByFingerprintSHA1(req.params.id);
            } else if (req.params.id.length === 64) {
                promise = ct.getCTCertByFingerprintSHA256(req.params.id);
            } else {
                res.status(400);
                res.res.json({ 'message': 'Unrecognized ID' });
                return;
            }

            promise.then(function (data) {
                if (data === null) {
                    res.status(404).json({ 'message': 'ID not found' });
                    return;
                }
                res.setHeader('Content-disposition', 'attachment; filename=' + data['_id'] + '.der');
                res.setHeader('Content-type', 'application/octet-stream');
                let b64string = data['raw'];
                let buf = new Buffer(b64string, 'base64');
                res.status(200).send(buf);
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
     *   - name: CT - Corporate certificates
     *     description: Returns the list of corporate certificates from the certificate transparency logs.
     *   - name: CT - Count corporate certificates
     *     description: Returns the count of corporate certificates from the certificate transparency logs.
     *
     * /api/v1.0/ct/corp_certs:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Returns the list of corporate certificates (".corp.example.org") from the certificate transparency logs.
     *     tags: [CT - Corporate certificates]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: exclude_expired
     *         type: integer
     *         required: false
     *         description: Set to 1 in order to exclude expired certificates
     *         default: 0
     *         in: query
     *     responses:
     *       200:
     *         description: Returns a JSON object with the matched certificates.
     *         schema:
     *           $ref: '#/definitions/CT-LogResponse'
     *       404:
     *         description: No matching records found.
     *         schema:
     *           $ref: '#/definitions/ResultsNotFound'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     *
     * /api/v1.0/ct/corp_certs?count=1:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Returns the count of corporate certificates (".corp.example.org") from the certificate transparency logs.
     *     tags: [CT - Count corporate certificates]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: count
     *         type: integer
     *         required: true
     *         description: Set to 1 in order to get a matched records count
     *         default: 1
     *         in: query
     *       - name: exclude_expired
     *         type: integer
     *         required: false
     *         description: Set to 1 in order to exclude expired certificates
     *         default: 0
     *         in: query
     *     responses:
     *       200:
     *         description: Returns a JSON object with the matched certificates.
     *         schema:
     *           $ref: '#/definitions/CT-LogResponse'
     *       404:
     *         description: No matching records found.
     *         schema:
     *           $ref: '#/definitions/ResultsNotFound'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     */
    router.route('/ct/corp_certs')
        .get(function (req, res) {
            let count = false;

            if (!is_valid_strings(req.query)) {
                res.status(400).json({ 'message': 'Multiple query parameters are not allowed.' });
                return;
            }

            if (req.query.hasOwnProperty("count") && req.query.count === "1") {
                count = true;
            }
            let promise;
            if (req.query.hasOwnProperty('exclude_expired') && req.query.exclude_expired === "1") {
                promise = ct.getCertTransCorpPromise(envConfig.internalDomain, true, count);
            } else {
                promise = ct.getCertTransCorpPromise(envConfig.internalDomain, false, count);
            }

            promise.then(function (data) {
                if (data === null) {
                    res.status(404).json({ 'message': 'CN not found' });
                    return;
                }
                if (count) {
                    res.status(200).json({ 'count': data });
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
     *   - name: CT - Signature Algorithm
     *     description: Returns certificates with the specified algorithm from the certificate transparency logs.
     *
     * /api/v1.0/ct/signature_algorithm:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Returns the list of  current certificates from the certificate transparency logs with the specified
     *                  algoritm. Expired certificates are not included.
     *     tags: [CT - Signature Algorithm]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: algorithm
     *         type: string
     *         required: false
     *         description: The algorithm to match within expired certificates
     *         default: RSA-SHA1
     *         in: query
     *     responses:
     *       200:
     *         description: Returns a JSON object with the matched certificates.
     *         schema:
     *           $ref: '#/definitions/CT-LogResponse'
     *       404:
     *         description: No matching records found.
     *         schema:
     *           $ref: '#/definitions/ResultsNotFound'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     *
     * /api/v1.0/ct/signature_algorithm?count=1&algorithm={algorithm}:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Counts current CT certificates based on their signature algorithm. Expired certificates are excluded.
     *     tags: [CT - Signature Algorithm]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: algorithm
     *         type: string
     *         required: false
     *         default: RSA-SHA1
     *         description: The signature algorithm value
     *         in: query
     *       - name: count
     *         type: integer
     *         required: true
     *         description: Set to 1 to count the number of matching results
     *         in: query
     *     responses:
     *       200:
     *         description: Returns a JSON object with the number of matched certificates.
     *         schema:
     *           $ref: '#/definitions/CountResponse'
     *       404:
     *         description: No matching records found.
     *         schema:
     *           $ref: '#/definitions/ResultsNotFound'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     */
    router.route('/ct/signature_algorithm')
        .get(function (req, res) {

            if (!is_valid_strings(req.query)) {
                res.status(400).json({ 'message': 'Multiple query parameters are not allowed.' });
                return;
            }

            let alg = 'RSA-SHA1';
            if (req.query.hasOwnProperty('algorithm')) {
                alg = req.query.algorithm;
            }

            let count = false;
            if (req.query.hasOwnProperty('count') && req.query.count === '1') {
                count = true;
            }

            let promise = ct.getUnexpiredSigAlg(alg, count);
            promise.then(function (data) {
                if (!data) {
                    res.status(500).json({ 'message': 'Error during query' });
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
     *   - name: CT - Corporate certificate count
     *     description: Counts the number corporate certificates from the certificate transparency logs.
     *
     * /api/v1.0/ct/corp_count:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Counts the number of corporate certificates (".corp.example.org") from the certificate transparency logs.
     *     tags: [CT - Corporate certificate count]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: exclude_expired
     *         type: integer
     *         required: false
     *         description: Set to 1 in order to exclude expired certificates
     *         default: 0
     *         in: query
     *     responses:
     *       200:
     *         description: Returns a JSON object with the matched certificates.
     *         schema:
     *           $ref: '#/definitions/CountResponse'
     *       404:
     *         description: No matching records found.
     *         schema:
     *           $ref: '#/definitions/ResultsNotFound'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     */
    router.route('/ct/corp_count')
        .get(function (req, res) {
            let promise = ct.getCorpCount(envConfig.internalDomain);
            promise.then(function (data) {
                if (!data) {
                    res.status(500).json({ 'message': 'Error during query' });
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
     *   - name: CT - Total Count
     *     description: Returns the total count of certificates within the saved certificate transparency logs.
     *
     * /api/v1.0/ct/total_count:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Returns the total count of certificates within the saved certificate transparency logs.
     *     tags: [CT - Total Count]
     *     produces:
     *       - application/json
     *     responses:
     *       200:
     *         description: Returns a JSON object with the count of matched certificates.
     *         schema:
     *           $ref: '#/definitions/CountResponse'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     */
    router.route('/ct/total_count')
        .get(function (req, res) {
            let promise = ct.getCertCount();
            promise.then(function (data) {
                if (!data) {
                    res.status(500).json({ 'message': 'Error during query' });
                    return;
                }
                res.status(200).json({ 'count': data });
                return;
            });
        });

    return (router);
};
