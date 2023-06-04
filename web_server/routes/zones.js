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
const zones = require('../config/models/zone');
const ipZones = require('../config/models/ip_zone');
const ipv6Zones = require('../config/models/ipv6_zone');
const CIDRMatcher = require('cidr-matcher');
const rangeCheck = require('range_check');

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
 *   ZoneModel:
 *     type: object
 *     definitions: A zone is what people conceptually consider the domain to be ("example.org", "example.org.br", "example.com")
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
 *       reporting_sources:
 *         type: array
 *         items:
 *           type: object
 *           properties:
 *             created:
 *               type: string
 *               example: 2016-06-22T02:08:46.893Z
 *             updated:
 *               type: string
 *               example: 2016-06-22T02:08:46.893Z
 *             status:
 *               type: string
 *               example: 2016-06-22T02:08:46.893Z
 *             source:
 *               type: string
 *               example: "Infoblox"
 *       sub_zones:
 *         type: array
 *         items:
 *           type: object
 *           properties:
 *             created:
 *               type: string
 *               example: 2016-06-22T02:08:46.893Z
 *             updated:
 *               type: string
 *               example: 2016-06-22T02:08:46.893Z
 *             status:
 *               type: string
 *               example: 2016-06-22T02:08:46.893Z
 *             source:
 *               type: string
 *               example: "Infoblox"
 *             sub_zone:
 *               type: string
 *               example: stage2.example.org
 *       notes:
 *         type: array
 *         items:
 *           type: string
 *
 *   IPZoneModel:
 *     type: object
 *     definitions: An IP zone is a CIDR (e.g. "19.5.2.0/24") that is being manually tracked.
 *     properties:
 *       zone:
 *         type: string
 *         example: 19.5.2.0/24
 *       status:
 *         type: string
 *         example: "unconfirmed"
 *       created:
 *         type: string
 *         example: 2016-06-22T02:08:46.893Z
 *       updated:
 *         type: string
 *         example: 2016-06-22T02:08:46.893Z
 *       source:
 *         type: string
 *         example: manual
 *       notes:
 *         type: array
 *         items:
 *           type: string
 *
 *   IPv6ZoneModel:
 *     type: object
 *     definitions: An IPv6 zone is a CIDR (e.g. "2610:110:1020::/44") that is being manually tracked.
 *     properties:
 *       zone:
 *         type: string
 *         example: 2620:113:1000::/44
 *       status:
 *         type: string
 *         example: "unconfirmed"
 *       created:
 *         type: string
 *         example: 2016-06-22T02:08:46.893Z
 *       updated:
 *         type: string
 *         example: 2016-06-22T02:08:46.893Z
 *       source:
 *         type: string
 *         example: manual
 *       notes:
 *         type: array
 *         items:
 *           type: string
 *
 *   IPZoneCheckResponse:
 *     type: object
 *     definitions: The result status. If the result status is true, then it returns the additional fields.
 *     properties:
 *       result:
 *         type: boolean
 *         example: true
 *       zone:
 *         type: string
 *         example: 19.5.2.0/24
 *       notes:
 *         type: array
 *         items:
 *           type: string
 *
 *   IPv6ZoneCheckResponse:
 *     type: object
 *     definitions: The result status. If the result status is true, then it returns the additional fields.
 *     properties:
 *       result:
 *         type: boolean
 *         example: true
 *       zone:
 *         type: string
 *         example: 2620:113:1000::/44
 *       notes:
 *         type: array
 *         items:
 *           type: string
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
     *   - name: Zones - Zone Stats
     *     description: Count zone records based on various properties.
     *
     * /api/v1.0/zones/stats:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Finds records based on different properties.
     *     tags: [Zones - Zone Stats]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: source
     *         type: string
     *         required: false
     *         description: Count only records from this source.
     *         enum: [Infoblox, PassiveTotal, Infoblox-Retired, manual, RiskIQ, UltraDNS]
     *         in: query
     *       - name: status
     *         type: string
     *         required: false
     *         description: Limit the response to the provided status. Defaults to != [expired, false_positive]
     *         enum: [unconfirmed, false_postive, expired, confirmed]
     *         in: query
     *     responses:
     *       200:
     *         description: Returns the count based on the optional source and status.
     *         type: object
     *         schema:
     *           $ref: '#/definitions/CountResponse'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     */
    router.route('/zones/stats')
        .get(function (req, res) {
            let source = '';
            let status = '';

            if (!is_valid_strings(req.query)) {
                res.status(400).json({ 'message': 'Multiple query parameters are not allowed.' });
                return;
            }

            if (req.query.hasOwnProperty('source')) {
                source = req.query.source;
            }
            if (req.query.hasOwnProperty('status')) {
                status = req.query.status;
            }
            let zonePromise = zones.getZoneCount(source, status);
            zonePromise.then(
                function (stats) {
                    if (!stats) {
                        res.status(500).json({
                            'message': 'Error retrieving zone stats',
                        });
                        return;
                    }
                    res.status(200).json({ 'count': stats });
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
     *   - name: Zones - Fetch zone
     *     description: Returns a single zone record.
     *
     * /api/v1.0/zones/zone/{zone}:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Retrieve an individual zone record for the provided domain (e.g. "example.org")
     *     tags: [Zones - Fetch zone]
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
     *         description: Returns the relevant zone.
     *         type: object
     *         schema:
     *           $ref: '#/definitions/ZoneModel'
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
    router.route('/zones/zone/:zone')
        .get(function (req, res) {
            if (!(req.params.hasOwnProperty('zone'))) {
                res.status(400).json({ 'message': 'A zone must be provided.' });
                return;
            }
            let zonePromise = zones.getZoneByNamePromise(req.params.zone);
            zonePromise.then(function (zone) {
                if (!zone) {
                    res.status(404).json({ 'message': 'Zone not found' });
                    return;
                }
                res.status(200).json(zone);
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
     *   - name: Zones - Zone list
     *     description: Returns all known zones.
     *
     * /api/v1.0/zones/list:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Retrieves all known domain zones (e.g. "example.org", "example.com", "example.net", etc.).
     *     tags: [Zones - Zone list]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: include_all
     *         type: string
     *         required: false
     *         description: Set to 1 in order to include false positives and expired in the response.
     *         in: query
     *       - name: pattern
     *         type: string
     *         required: false
     *         description: Retrieve zone names that include the provided pattern.
     *         in: query
     *     responses:
     *       200:
     *         description: Returns the array of zones.
     *         type: array
     *         items:
     *           $ref: '#/definitions/ZoneModel'
     *       404:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/ResultsNotFound'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     */
    router.route('/zones/list')
        .get(function (req, res) {
            let includeAll = false;

            if (!is_valid_strings(req.query)) {
                res.status(400).json({ 'message': 'Multiple query parameters are not allowed.' });
                return;
            }

            if (req.query.hasOwnProperty('include_all')
                && req.query.include_all === '1') {
                includeAll = true;
            }
            let pattern = null;
            if (req.query.hasOwnProperty('pattern')
                && req.query.pattern.length > 0) {
                pattern = req.query.pattern;
            }
            let zonePromise = zones.getAllZones(pattern, includeAll);
            zonePromise.then(function (zones) {
                if (!zones) {
                    res.status(404).json({ 'message': 'Zone not found' });
                    return;
                }
                res.status(200).json(zones);
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
     *   - name: Zones - Zone sources list
     *     description: Returns all known sources of zone information.
     *
     * /api/v1.0/zones/sources:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Retrieves all known sources of zone information for domains.
     *     tags: [Zones - Zone sources list]
     *     produces:
     *       - application/json
     *     responses:
     *       200:
     *         description: Returns the array of zone sources.
     *         type: array
     *         items:
     *           string
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     */
    router.route('/zones/sources')
        .get(function (req, res) {
            let zonePromise = zones.getUniqueSources();
            zonePromise.then(function (sources) {
                if (!sources) {
                    res.status(500).json({ 'message': 'Error retrieving sources' });
                    return;
                }
                let jsonRes = { 'sources': sources };
                res.status(200).json(jsonRes);
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
     *   - name: Zones - Fetch IP zone
     *     description: Returns a single IP zone record.
     *
     * /api/v1.0/zones/ipzone/{zone}:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Retrieve an individual manually tracked IP CIDR record.
     *     tags: [Zones - Fetch IP zone]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: zone
     *         type: string
     *         required: true
     *         description: The IP zone ("19.15.2.0/24", etc.) to fetch (escape the slash).
     *         in: path
     *     responses:
     *       200:
     *         description: Returns the relevant IP zone.
     *         type: object
     *         schema:
     *           $ref: '#/definitions/IPZoneModel'
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
    router.route('/zones/ipzone/:zone')
        .get(function (req, res) {
            if (!(req.params.hasOwnProperty('zone'))) {
                res.status(400).json({ 'message': 'An IP zone must be provided.' });
                return;
            }
            let zonePromise = ipZones.getZoneByNamePromise(req.params.zone);
            zonePromise.then(function (zone) {
                if (!zone) {
                    res.status(404).json({ 'message': 'IP zone not found' });
                    return;
                }
                res.status(200).json(zone);
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
     *   - name: Zones - Fetch IPv6 zone
     *     description: Returns a single IPv6 zone record.
     *
     * /api/v1.0/zones/ipv6zone/{zone}:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Retrieve an individual manually tracked IPv6 CIDR record
     *     tags: [Zones - Fetch IPv6 zone]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: zone
     *         type: string
     *         required: true
     *         description: The IPv6 zone ("2620:113:1000::/44", etc.) to fetch (escape the slash).
     *         in: path
     *     responses:
     *       200:
     *         description: Returns the relevant IPv6 zone.
     *         type: object
     *         schema:
     *           $ref: '#/definitions/IPv6ZoneModel'
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
    router.route('/zones/ipv6zone/:zone')
        .get(function (req, res) {
            if (!(req.params.hasOwnProperty('zone'))) {
                res.status(400).json({ 'message': 'An IPv6 zone must be provided.' });
                return;
            }
            let zonePromise = ipv6Zones.getZoneByNamePromise(req.params.zone);
            zonePromise.then(function (zone) {
                if (!zone) {
                    res.status(404).json({ 'message': 'IPv6 zone not found' });
                    return;
                }
                res.status(200).json(zone);
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
     *   - name: Zones - IPv4 zone list
     *     description: Returns all known manually tracked IPv4 CIDRs.
     *
     * /api/v1.0/zones/ip_list:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Retrieves all known manually tracked IPv4 CIDRs. This does not include resources rented from third-parties
     *                  such as AWS and Azure.
     *     tags: [Zones - IPv4 zone list]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: include_fp
     *         type: string
     *         required: false
     *         description: Set to 1 in order to include false positives in the response. Default is 0.
     *         in: query
     *     responses:
     *       200:
     *         description: Returns the array of zones.
     *         type: array
     *         items:
     *           $ref: '#/definitions/IPZoneModel'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     */
    router.route('/zones/ip_list')
        .get(function (req, res) {
            let includeFalsePositives = false;

            if (!is_valid_strings(req.query)) {
                res.status(400).json({ 'message': 'Multiple query parameters are not allowed.' });
                return;
            }

            if (req.query.hasOwnProperty('include_fp')
                && req.query.include_fp === '1') {
                includeFalsePositives = true;
            }
            let zonePromise = ipZones.getAllZones(includeFalsePositives);
            zonePromise.then(function (ipzones) {
                if (!ipzones) {
                    res.status(500).json({ 'message': 'Error retrieving IP zones' });
                    return;
                }
                res.status(200).json(ipzones);
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
     *   - name: Zones - IPv6 zone list
     *     description: Returns all known manually tracked IPv6 CIDRs.
     *
     * /api/v1.0/zones/ipv6_list:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Retrieves all known manually tracked IPv6 CIDRs. This does not include resources provided by third-parties
     *                  such as AWS and Azure.
     *     tags: [Zones - IPv6 zone list]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: include_fp
     *         type: string
     *         required: false
     *         description: Set to 1 in order to include false positives in the response. Default is 0.
     *         in: query
     *     responses:
     *       200:
     *         description: Returns the array of zones.
     *         type: array
     *         items:
     *           $ref: '#/definitions/IPv6ZoneModel'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     */
    router.route('/zones/ipv6_list')
        .get(function (req, res) {
            let includeFalsePositives = false;
            if (req.query.hasOwnProperty('include_fp')
                && req.query.include_fp === '1') {
                includeFalsePositives = true;
            }
            let zonePromise = ipv6Zones.getAllZones(includeFalsePositives);
            zonePromise.then(function (ipzones) {
                if (!ipzones) {
                    res.status(500).json({ 'message': 'Error retrieving IPv6 zones' });
                    return;
                }
                res.status(200).json(ipzones);
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
     *   - name: Zones - IP ownership check
     *     description: Determines whether the provided IP is within an manually tracked CIDR.
     *
     * /api/v1.0/zones/ip_zone_check:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Determines whether the provided IP is within an manually tracked IP zone. This only checks against CIDRs
     *                  that is being manually tracked. It will return false for resources in AWS, Azure, or other third-parties.
     *     tags: [Zones - IP ownership check]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: ip
     *         type: string
     *         required: true
     *         description: The IP to check against manually tracked CIDRs.
     *         in: query
     *     responses:
     *       200:
     *         description: Returns an object indicating whether the IP belongs to a known IP zone.
     *         type: object
     *         schema:
     *           $ref: '#/definitions/IPZoneCheckResponse'
     *       400:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     */
    router.route('/zones/ip_zone_check')
        .get(function (req, res) {

            if (!is_valid_strings(req.query)) {
                res.status(400).json({ 'message': 'Multiple query parameters are not allowed.' });
                return;
            }

            if (!(req.query.hasOwnProperty('ip'))) {
                res.status(400).json({ 'message': 'An IP must be provided.' });
                return;
            }
            let includeFalsePositives = false;
            if (req.query.hasOwnProperty('include_fp')
                && req.query.include_fp === '1') {
                includeFalsePositives = true;
            }
            let zonePromise = ipZones.getAllZones(includeFalsePositives);
            zonePromise.then(function (ipzones) {
                if (!ipzones) {
                    res.status(500).json({ 'message': 'Error retrieving sources' });
                    return;
                }
                for (let i = 0; i < ipzones.length; i++) {
                    let matcher = new CIDRMatcher();
                    matcher.addNetworkClass(ipzones[i]['zone']);

                    if (matcher.contains(req.query.ip)) {
                        res.status(200).json({
                            'result': true,
                            'zone': ipzones[i]['zone'],
                            'notes': ipzones[i]['notes']
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
     *   - name: Zones - IPv6 ownership check
     *     description: Determines whether the provided IPv6 is within an manually tracked IPv6 CIDR.
     *
     * /api/v1.0/zones/ipv6_zone_check:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Determines whether the provided IPv6 is within an manually tracked IPv6 zone. This only checks against CIDRs
     *                  that are manually tracked. It will return false for resources in AWS, Azure, or other third-parties.
     *     tags: [Zones - IPv6 ownership check]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: ip
     *         type: string
     *         required: true
     *         description: The IPv6 to check against manually tracked IPv6 CIDRs.
     *         in: query
     *     responses:
     *       200:
     *         description: Returns an object indicating whether the IPv6 address belongs to a known IPv6 zone.
     *         type: object
     *         schema:
     *           $ref: '#/definitions/IPv6ZoneCheckResponse'
     *       400:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     */
    router.route('/zones/ipv6_zone_check')
        .get(function (req, res) {

            if (!is_valid_strings(req.query)) {
                res.status(400).json({ 'message': 'Multiple query parameters are not allowed.' });
                return;
            }

            if (!(req.query.hasOwnProperty('ip'))) {
                res.status(400).json({ 'message': 'An IPv6 address must be provided.' });
                return;
            }
            let includeFalsePositives = false;
            if (req.query.hasOwnProperty('include_fp')
                && req.query.include_fp === '1') {
                includeFalsePositives = true;
            }
            let zonePromise = ipv6Zones.getAllZones(includeFalsePositives);
            zonePromise.then(function (ipzones) {
                if (!ipzones) {
                    res.status(500).json({ 'message': 'Error retrieving sources' });
                    return;
                }
                for (let i = 0; i < ipzones.length; i++) {
                    if (rangeCheck.inRange(req.query.ip, ipzones[i]['zone'])) {
                        res.status(200).json({
                            'result': true,
                            'zone': ipzones[i]['zone'],
                            'notes': ipzones[i]['notes']
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
     *   - name: Zones - IP Zone Stats
     *     description: Count IP zone records based on various properties.
     *
     * /api/v1.0/zones/ip_stats:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Finds records based on different properties.
     *     tags: [Zones - IP Zone Stats]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: source
     *         type: string
     *         required: false
     *         description: Count only records from this source.
     *         enum: [Infoblox, PassiveTotal, Infoblox-Retired, manual, RiskIQ, UltraDNS]
     *         in: query
     *       - name: status
     *         type: string
     *         required: false
     *         description: Limit the response to the provided status. Defaults to non false_positive entries.
     *         enum: [unconfirmed, false_postive, expired, confirmed]
     *         in: query
     *     responses:
     *       200:
     *         description: Returns the count based on the optional source and status.
     *         type: object
     *         schema:
     *           $ref: '#/definitions/CountResponse'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     */
    router.route('/zones/ip_stats')
        .get(function (req, res) {
            let source = '';
            let status = '';

            if (!is_valid_strings(req.query)) {
                res.status(400).json({ 'message': 'Multiple query parameters are not allowed.' });
                return;
            }

            if (req.query.hasOwnProperty('source')) {
                source = req.query.source;
            }
            if (req.query.hasOwnProperty('status')) {
                status = req.query.status;
            }
            let zonePromise = ipZones.getZoneCount(source, status);
            zonePromise.then(
                function (stats) {
                    if (!stats) {
                        res.status(500).json({
                            'message': 'Error retrieving zone stats',
                        });
                        return;
                    }
                    res.status(200).json({ 'count': stats });
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
     *   - name: Zones - IPv6 Zone Stats
     *     description: Count IPv6 records based on various properties.
     *
     * /api/v1.0/zones/ipv6_stats:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Finds IPv6 records based on different properties.
     *     tags: [Zones - IPv6 Zone Stats]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: source
     *         type: string
     *         required: false
     *         description: Count only records from this source.
     *         enum: [Infoblox, PassiveTotal, Infoblox-Retired, manual, RiskIQ, UltraDNS]
     *         in: query
     *       - name: status
     *         type: string
     *         required: false
     *         description: Limit the response to the provided status. Defaults to non false_positive entries.
     *         enum: [unconfirmed, false_postive, expired, confirmed]
     *         in: query
     *     responses:
     *       200:
     *         description: Returns the count based on the optional source and status.
     *         type: object
     *         schema:
     *           $ref: '#/definitions/CountResponse'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     */
    router.route('/zones/ipv6_stats')
        .get(function (req, res) {
            let source = '';
            let status = '';

            if (!is_valid_strings(req.query)) {
                res.status(400).json({ 'message': 'Multiple query parameters are not allowed.' });
                return;
            }

            if (req.query.hasOwnProperty('source')) {
                source = req.query.source;
            }
            if (req.query.hasOwnProperty('status')) {
                status = req.query.status;
            }
            let zonePromise = ipv6Zones.getZoneCount(source, status);
            zonePromise.then(
                function (stats) {
                    if (!stats) {
                        res.status(500).json({
                            'message': 'Error retrieving IPv6 zone stats',
                        });
                        return;
                    }
                    res.status(200).json({ 'count': stats });
                    return;
                });
        });

    return (router);
};
