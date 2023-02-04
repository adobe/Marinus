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

const ipRecs = require('../config/models/ip');


/**
 * @swagger
 *
 * definitions:
 *   AllIPRecord:
 *     type: object
 *     properties:
 *       created:
 *         type: string
 *         example: 2016-06-22T02:08:46.893Z
 *       updated:
 *         type: string
 *         example: 2016-06-23T02:08:46.893Z
 *       ip:
 *         type: string
 *         example: 4.4.4.4
 *       version:
 *         type: integer
 *         example: 4
 *       reverse_dns:
 *         type: string
 *         example: 4.4.4.4.in-addr.arpa
 *       zones:
 *         type: array
 *         example: [example.org, example.net]
 *       domains:
 *         type: array
 *         example: [www.example.org, www.example.net]
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
 *       host:
 *         type: object
 *         properties:
 *           hosting_partner:
 *             type: string
 *             example: AWS
 *           host_cidr:
 *             type: string
 *             example: 4.4.4.0/24
 *           notes:
 *             type: string
 *             example: us-east-1
 *           splunk:
 *             type: array
 *             example: ["The raw splunk records for the associated host"]
 */

module.exports = function (envConfig) {
    /**
     * @swagger
     *
     * security:
     *   - APIKeyHeader: []
     *
     * tags:
     *   - name: IP - General query
     *     description: Find records based on various mutually exclusive properties.
     *   - name: IP - General count query
     *     description: Count records based on various mutually exclusive properties.
     *
     * /api/v1.0/ips:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Find records based on various mutually exclusive properties. If no parameters are provided, then all IPs are returned. Use limit+page to paginate the results.
     *     tags: [IP - General query]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: ip
     *         type: string
     *         required: false
     *         description: The IPv4 or IPv6 record to retrieve
     *         in: query
     *       - name: domain
     *         type: string
     *         required: false
     *         description: Retrieve IP information for the specified domain
     *         in: query
     *       - name: zone
     *         type: string
     *         required: false
     *         description: Retrieve IP information for the specified zone
     *         in: query
     *       - name: host_cidr
     *         type: string
     *         required: false
     *         description: Retrieve IP information for specified host (TRACKED, AWS, AZURE) CIDR
     *         in: query
     *       - name: ip_version
     *         type: string
     *         required: false
     *         description: Retrieve IP information for either IPv4 or IPv6. Please specify either '4' or '6'
     *         in: query
     *       - name: partner
     *         type: string
     *         required: false
     *         description: A specific hosting partner
     *         enum: ["AWS", "AZURE", "TRACKED"]
     *         in: query
     *       - name: managed_hosts
     *         type: string
     *         required: false
     *         description: Retrieve only the IP addresses that Marinus is certain that within a controlled data center or cloud provider. Set to 1.
     *         in: query
     *       - name: data_center
     *         type: string
     *         required: false
     *         description: Retrieve only the IP addresses that Marinus is certain that exist in a tracked data center. Set to 1.
     *         in: query
     *       - name: limit
     *         type: number
     *         required: false
     *         description: Limit the number of IPs per page when requesting all IPs, ip_version, host_partner, or managed_hosts IPs. Default 1,000.
     *         in: query
     *       - name: page
     *         type: number
     *         required: false
     *         description: The page to request. This must be set in conjunction with the limit parameter. The default is 1.
     *         in: query
     *     responses:
     *       200:
     *         description: Returns an array of IP Records matching the response.
     *         type: array
     *         items:
     *           $ref: '#/definitions/AllIPRecord'
     *       400:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     * 
     * /api/v1.0/ips?count=1:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Count records based on various mutually exclusive properties.
     *     tags: [IP - General count query]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: domain
     *         type: string
     *         required: false
     *         description: Retrieve IP information for the specified domain
     *         in: query
     *       - name: zone
     *         type: string
     *         required: false
     *         description: Retrieve IP information for the specified zone
     *         in: query
     *       - name: host_cidr
     *         type: string
     *         required: false
     *         description: Retrieve IP information for specified host (TRACKED, AWS, AZURE) CIDR
     *         in: query
     *       - name: ip_version
     *         type: string
     *         required: false
     *         description: Retrieve IP information for either IPv4 or IPv6. Please specify either '4' or '6'
     *         in: query
     *       - name: partner
     *         type: string
     *         required: false
     *         description: A specific hosting partner
     *         enum: ["AWS", "AZURE", "TRACKED"]
     *         in: query
     *       - name: managed_hosts
     *         type: string
     *         required: false
     *         description: Retrieve only the IP addresses that Marinus is certain that within a controlled data center or cloud provider. Set to 1.
     *         in: query
     *       - name: data_center
     *         type: string
     *         required: false
     *         description: Retrieve only the IP addresses that Marinus is certain that exist in a tracked data center. Set to 1.
     *         in: query
     *     responses:
     *       200:
     *         description: Returns an array of IP Records matching the response.
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
    router.route('/ips')
        .get(function (req, res) {
            let promise;
            let count = false;

            if (req.query.hasOwnProperty('count') && req.query.count == "1") {
                count = true;
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

            if (req.query.hasOwnProperty('partner')) {
                let partner = req.query.partner;
                if (partner != "AWS" && partner != "AZURE" && partner != "TRACKED") {
                    res.status(400).json({ 'message': 'Unknown hosting partner' });
                    return;
                }
                promise = ipRecs.getIPRecordsByHostPartnerPromise(partner, count, limit, page);
            } else if (req.query.hasOwnProperty('ip')) {
                promise = ipRecs.getIPRecordsByIPPromise(req.query.ip);
            } else if (req.query.hasOwnProperty('zone')) {
                promise = ipRecs.getIPRecordsByZonePromise(req.query.zone, count);
            } else if (req.query.hasOwnProperty('domain')) {
                promise = ipRecs.getIPRecordsByDomainPromise(req.query.domain, count);
            } else if (req.query.hasOwnProperty('host_cidr')) {
                promise = ipRecs.getIPRecordsByHostCIDRPromise(req.query.host_cidr, count);
            } else if (req.query.hasOwnProperty('ip_version')) {
                if (req.query.ip_version != "4" && req.query.ip_version != "6") {
                    res.status(400).json({ 'message': 'Acceptable values are either "4" or "6"' });
                    return;
                }
                promise = ipRecs.getIPRecordsByIPVersionPromise(req.query.ip_version, count, limit, page);
            } else if (req.query.hasOwnProperty('managed_hosts')) {
                promise = ipRecs.getAllManagedIPRecordsPromise(count, limit, page);
            } else if (req.query.hasOwnProperty('data_center')) {
                promise = ipRecs.getAllTrackedIPRecordsPromise(count, limit, page);
            } else if (count) {
                promise = ipRecs.getAllIPRecordsCountPromise();
            } else {
                promise = ipRecs.getAllIPRecordsPromise(limit, page);
            }

            promise.then(function (data) {
                if (!data || data.length === 0) {
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

    return (router);
}
