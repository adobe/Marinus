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
const rangeCheck = require('range_check');
const escapeStringRegexp = require('escape-string-regexp');

const awsIPs = require('../config/models/aws_ips');
const akamaiIPs = require('../config/models/akamai_ips');
const azureiIPs = require('../config/models/azure_ips');
const gcpIPs = require('../config/models/gcp_ips');
const custom_errors = require('../config/error');


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


module.exports = function (envConfig) {
    /**
     * @swagger
     *
     * security:
     *   - APIKeyHeader: []
     *
     * tags:
     *   - name: AWS - IP check
     *     description: Check whether the provided IPv4 address is known to belong in AWS.
     *
     * definitions:
     *   AWSIPv4CheckResponse:
     *     type: object
     *     properties:
     *       status:
     *         type: boolean
     *         example: true
     *         description: A boolean indicating whether the IP belongs to AWS
     *       record:
     *         type: string
     *         example: 1.2.3.0/24
     *         description: The matching AWS CIDR range.
     *
     * /api/v1.0/aws/ip_check:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Determines whether an IPv4 address belongs to AWS in general. This does not check whether the IP is assigned to your organization within AWS.
     *     tags: [AWS - IP check]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: ip
     *         type: string
     *         required: true
     *         description: The IPv4 address to check.
     *         in: query
     *     responses:
     *       200:
     *         description: Returns an object with status and the matching AWS IPv4 CIDR.
     *         type: object
     *         schema:
     *           $ref: '#/definitions/AWSIPv4CheckResponse'
     *       400:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     */
    router.route('/aws/ip_check')
        .get(function (req, res) {

            if (!is_valid_strings(req.query)) {
                res.status(400).json({ 'message': 'Multiple query parameters are not allowed.' });
                return;
            }

            if (!(req.query.hasOwnProperty('ip'))) {
                res.status(400).json({
                    'message': 'An IP must be provided',
                });
                return;
            }

            let promise = awsIPs.getAwsIpZonesPromise();
            promise.then(function (results) {
                if (!results) {
                    res.status(500).json({
                        'message': 'Error fetching AWS information!',
                    });
                    return;
                }
                let matcher;
                for (let i = 0; i < results[0]['prefixes'].length; i++) {
                    /**
                     * This is inefficient since you could add all the prefixes
                     * to a single CIDRMatcher, and then check once.
                     * However, then you would not know which record was matched.
                     */
                    matcher = new CIDRMatcher();
                    matcher.addNetworkClass(results[0]['prefixes'][i]['ip_prefix']);
                    if (matcher.contains(req.query.ip)) {
                        res.status(200).json({
                            'result': true,
                            'record': results[0]['prefixes'][i],
                        });
                        return;
                    }
                }

                res.status(200).json({ 'result': false });
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
     *   - name: AWS - IPv6 check
     *     description: Check whether the provided IPv6 address is known to belong in AWS.
     *
     * definitions:
     *   AWSIPv6CheckResponse:
     *     type: object
     *     properties:
     *       status:
     *         type: boolean
     *         example: true
     *         description: A boolean indicating whether the IPv6 belongs to AWS
     *       record:
     *         type: string
     *         example: 2a05:d07c:2000::/40
     *         description: The matching AWS CIDR range.
     *
     * /api/v1.0/aws/ipv6_check:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Determines whether an IPv6 address belongs to AWS.
     *     tags: [AWS - IPv6 check]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: ip
     *         type: string
     *         required: true
     *         description: The IPv6 address to check.
     *         in: query
     *     responses:
     *       200:
     *         description: Returns an object with status and matching IPv6 CIDR.
     *         type: object
     *         schema:
     *           $ref: '#/definitions/AWSIPv6CheckResponse'
     *       400:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     */
    router.route('/aws/ipv6_check')
        .get(function (req, res) {

            if (!is_valid_strings(req.query)) {
                res.status(400).json({ 'message': 'Multiple query parameters are not allowed.' });
                return;
            }

            if (!(req.query.hasOwnProperty('ip'))) {
                res.status(400).json({
                    'message': 'An IPv6 IP must be provided',
                });
                return;
            }

            let promise = awsIPs.getAwsIpv6ZonesPromise();
            promise.then(function (results) {
                if (!results) {
                    res.status(500).json({
                        'message': 'Error fetching AWS information!',
                    });
                    return;
                }

                for (let i = 0; i < results[0]['ipv6_prefixes'].length; i++) {
                    /**
                     * This is inefficient since you could add all the prefixes
                     * to a single rangecheck call.
                     * However, then you would not know which record was matched.
                     */
                    if (rangeCheck.inRange(req.query.ip, results[0]['ipv6_prefixes'][i]['ipv6_prefix'])) {
                        res.status(200).json({
                            'result': true,
                            'record': results[0]['ipv6_prefixes'][i],
                        });
                        return;
                    }
                }

                res.status(200).json({ 'result': false });
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
     *   - name: Akamai - IP check
     *     description: Check whether the provided IPv4 address is known to belong in Akamai.
     *
     * definitions:
     *   AkamaiIPv4CheckResponse:
     *     type: object
     *     properties:
     *       status:
     *         type: boolean
     *         example: true
     *         description: A boolean indicating whether the IP belongs to Akamai
     *       record:
     *         type: string
     *         example: 1.2.3.0/24
     *         description: The matching Akamai CIDR range.
     *
     * /api/v1.0/akamai/ip_check:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Determines whether an IPv4 address belongs to Akamai.
     *     tags: [Akamai - IP check]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: ip
     *         type: string
     *         required: true
     *         description: The IPv4 address to check.
     *         in: query
     *     responses:
     *       200:
     *         description: Returns an object with status and matching IPv4 CIDR.
     *         type: object
     *         schema:
     *           $ref: '#/definitions/AkamaiIPv4CheckResponse'
     *       400:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     */
    router.route('/akamai/ip_check')
        .get(function (req, res) {

            if (!is_valid_strings(req.query)) {
                res.status(400).json({ 'message': 'Multiple query parameters are not allowed.' });
                return;
            }

            if (!(req.query.hasOwnProperty('ip'))) {
                res.status(400).json({ 'message': 'An IP must be provided' });
                return;
            }

            let promise = akamaiIPs.getAkamaiIpZonesPromise();
            promise.then(function (results) {
                if (!results) {
                    res.status(500).json({
                        'message': 'Error fetching Akamai information!',
                    });
                    return;
                }
                let matcher = new CIDRMatcher();
                for (let i = 0; i < results[0]['ranges'].length; i++) {
                    matcher.addNetworkClass(results[0]['ranges'][i]['cidr']);
                }

                if (matcher.contains(req.query.ip)) {
                    res.status(200).json({ 'result': true });
                    return;
                }
                res.status(200).json({ 'result': false });
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
     *   - name: Akamai - IPv6 check
     *     description: Check whether the provided IPv4 address is known to belong in Akamai.
     *
     * definitions:
     *   AkamaiIPv6CheckResponse:
     *     type: object
     *     properties:
     *       status:
     *         type: boolean
     *         example: true
     *         description: A boolean indicating whether the IPv6 belongs to Akamai
     *       record:
     *         type: string
     *         example: 2600:1400::/24
     *         description: The matching Akamai CIDR range.
     *
     * /api/v1.0/akamai/ipv6_check:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Determines whether an IPv6 address belongs to Akamai.
     *     tags: [Akamai - IPv6 check]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: ip
     *         type: string
     *         required: true
     *         description: The IPv6 address to check.
     *         in: query
     *     responses:
     *       200:
     *         description: Returns an object with status and matching IPv6 CIDR.
     *         type: object
     *         schema:
     *           $ref: '#/definitions/AkamaiIPv6CheckResponse'
     *       400:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     */
    router.route('/akamai/ipv6_check')
        .get(function (req, res) {

            if (!is_valid_strings(req.query)) {
                res.status(400).json({ 'message': 'Multiple query parameters are not allowed.' });
                return;
            }

            if (!(req.query.hasOwnProperty('ip'))) {
                res.status(400).json({ 'message': 'An IP must be provided' });
                return;
            }

            let promise = akamaiIPs.getAkamaiIpv6ZonesPromise();
            promise.then(function (results) {
                if (!results) {
                    res.status(500).json({
                        'message': 'Error fetching Akamai information!',
                    });
                    return;
                }
                for (let i = 0; i < results[0]['ipv6_ranges'].length; i++) {
                    if (rangeCheck.inRange(req.query.ip, results[0]['ipv6_ranges'][i]['cidr'])) {
                        res.status(200).json({ 'result': true });
                        return;
                    }
                }
                res.status(200).json({ 'result': false });
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
     *   - name: Azure - IP check
     *     description: Check whether the provided IPv4 address is known to belong in Azure.
     *
     * definitions:
     *   AzureIPv4CheckResponse:
     *     type: object
     *     properties:
     *       status:
     *         type: boolean
     *         example: true
     *         description: A boolean indicating whether the IP belongs to Azure
     *       record:
     *         type: string
     *         example: 1.2.3.0/24
     *         description: The matching Azure CIDR range.
     *
     * /api/v1.0/azure/ip_check:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Determines whether an IPv4 address belongs to Azure. It does not check whether the IP is assigned to your organization within Azure.
     *     tags: [Azure - IP check]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: ip
     *         type: string
     *         required: true
     *         description: The IPv4 address to check.
     *         in: query
     *     responses:
     *       200:
     *         description: Returns an object with status and matching IPv4 CIDR.
     *         type: object
     *         schema:
     *           $ref: '#/definitions/AzureIPv4CheckResponse'
     *       400:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     */
    router.route('/azure/ip_check')
        .get(function (req, res) {

            if (!is_valid_strings(req.query)) {
                res.status(400).json({ 'message': 'Multiple query parameters are not allowed.' });
                return;
            }

            if (!(req.query.hasOwnProperty('ip'))) {
                res.status(400).json({
                    'message': 'An IP must be provided',
                });
                return;
            }

            let promise = azureiIPs.getAzureIpZonesPromise();
            promise.then(function (results) {
                if (!results) {
                    res.status(500).json({
                        'message': 'Error fetching Azure information!',
                    });
                    return;
                }
                let matcher;
                for (let i = 0; i < results[0]['prefixes'].length; i++) {
                    /**
                     * This is inefficient since you could add all the prefixes
                     * to a single CIDRMatcher, and then check once.
                     * However, then you would not know which record was matched.
                     */
                    matcher = new CIDRMatcher();
                    matcher.addNetworkClass(results[0]['prefixes'][i]['ip_prefix']);
                    if (matcher.contains(req.query.ip)) {
                        res.status(200).json({
                            'result': true,
                            'record': results[0]['prefixes'][i],
                        });
                        return;
                    }
                }
                res.status(200).json({ 'result': false });
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
     *   - name: GCP - IP check
     *     description: Check whether the provided IPv4 address is known to belong in GCP.
     *
     * definitions:
     *   GCPIPv4CheckResponse:
     *     type: object
     *     properties:
     *       status:
     *         type: boolean
     *         example: true
     *         description: A boolean indicating whether the IP belongs to GCP
     *       record:
     *         type: string
     *         example: 1.2.3.0/24
     *         description: The matching GCP CIDR range.
     *
     * /api/v1.0/gcp/ip_check:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Determines whether an IPv4 address belongs to GCP in general. This does not check whether the IP is assigned to your organization within GCP.
     *     tags: [GCP - IP check]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: ip
     *         type: string
     *         required: true
     *         description: The IPv4 address to check.
     *         in: query
     *     responses:
     *       200:
     *         description: Returns an object with status and the matching GCP IPv4 CIDR.
     *         type: object
     *         schema:
     *           $ref: '#/definitions/GCPIPv4CheckResponse'
     *       400:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     */
    router.route('/gcp/ip_check')
        .get(function (req, res) {

            if (!is_valid_strings(req.query)) {
                res.status(400).json({ 'message': 'Multiple query parameters are not allowed.' });
                return;
            }

            if (!(req.query.hasOwnProperty('ip'))) {
                res.status(400).json({
                    'message': 'An IP must be provided',
                });
                return;
            }

            let promise = gcpIPs.getGCPIpZonesPromise();
            promise.then(function (results) {
                if (!results) {
                    res.status(500).json({
                        'message': 'Error fetching GCP information!',
                    });
                    return;
                }
                let matcher;
                for (let i = 0; i < results[0]['prefixes'].length; i++) {
                    /**
                     * This is inefficient since you could add all the prefixes
                     * to a single CIDRMatcher, and then check once.
                     * However, then you would not know which record was matched.
                     */
                    matcher = new CIDRMatcher();
                    matcher.addNetworkClass(results[0]['prefixes'][i]['ip_prefix']);
                    if (matcher.contains(req.query.ip)) {
                        res.status(200).json({
                            'result': true,
                            'record': results[0]['prefixes'][i],
                        });
                        return;
                    }
                }

                res.status(200).json({ 'result': false });
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
     *   - name: GCP - IPv6 check
     *     description: Check whether the provided IPv6 address is known to belong in GCP.
     *
     * definitions:
     *   GCPIPv6CheckResponse:
     *     type: object
     *     properties:
     *       status:
     *         type: boolean
     *         example: true
     *         description: A boolean indicating whether the IPv6 belongs to GCP
     *       record:
     *         type: string
     *         example: 2a05:d07c:2000::/40
     *         description: The matching AWS CIDR range.
     *
     * /api/v1.0/gcp/ipv6_check:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Determines whether an IPv6 address belongs to GCP.
     *     tags: [GCP - IPv6 check]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: ip
     *         type: string
     *         required: true
     *         description: The IPv6 address to check.
     *         in: query
     *     responses:
     *       200:
     *         description: Returns an object with status and matching IPv6 CIDR.
     *         type: object
     *         schema:
     *           $ref: '#/definitions/GCPIPv6CheckResponse'
     *       400:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     */
    router.route('/gcp/ipv6_check')
        .get(function (req, res) {

            if (!is_valid_strings(req.query)) {
                res.status(400).json({ 'message': 'Multiple query parameters are not allowed.' });
                return;
            }

            if (!(req.query.hasOwnProperty('ip'))) {
                res.status(400).json({
                    'message': 'An IPv6 IP must be provided',
                });
                return;
            }

            let promise = gcpIPs.getGCPIpv6ZonesPromise();
            promise.then(function (results) {
                if (!results) {
                    res.status(500).json({
                        'message': 'Error fetching GCP information!',
                    });
                    return;
                }

                for (let i = 0; i < results[0]['ipv6_prefixes'].length; i++) {
                    /**
                     * This is inefficient since you could add all the prefixes
                     * to a single rangecheck call.
                     * However, then you would not know which record was matched.
                     */
                    if (rangeCheck.inRange(req.query.ip, results[0]['ipv6_prefixes'][i]['ipv6_prefix'])) {
                        res.status(200).json({
                            'result': true,
                            'record': results[0]['ipv6_prefixes'][i],
                        });
                        return;
                    }
                }

                res.status(200).json({ 'result': false });
                return;
            });
        });


    return (router);
};
