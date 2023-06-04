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
const tpdRecs = require('../config/models/tpds');

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
 *   TPDModel:
 *     type: object
 *     properties:
 *       total:
 *         type: integer
 *         example: 45
 *         description: The overall number of records associated with this TPD.
 *       tld:
 *         type: string
 *         example: "fastly.net"
 *         description: The third-party domain.
 *       zones:
 *         type: array
 *         items:
 *           type: object
 *           properties:
 *             zone:
 *               type: string
 *               example: "example.com"
 *               description: The manually tracked domain.
 *             records:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   host:
 *                     type: string
 *                     example: "static.example.com"
 *                     description: The corresponding DNS record.
 *                   target:
 *                     type: string
 *                     example: "o.shared.global.fastly.net"
 *                     description: The third-party DNS record.
 *
 *   TPDListOnlyModel:
 *     type: object
 *     properties:
 *       tld:
 *         type: string
 *         example: "fastly.net"
 *         description: The third-party domain.
 *       zones:
 *         type: array
 *         items:
 *           type: object
 *           properties:
 *             zone:
 *               type: string
 *               example: "example.org"
 *               description: The tracked domain.
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
     *   - name: TPDs - Zone search
     *     description: Searches for third-party domains associated with the provided zone.
     *   - name: TPDs - TPD search
     *     description: Searches for records that are associated with the provided third-party domain.
     *   - name: TPDs - Wildcard search
     *     description: Searches for third-party domains that end with the provided string.
     *   - name: TPDs - Fetch all
     *     description: Returns all third-party domain records.
     *
     * /api/v1.0/tpds/search?dataType=zone&value={zone}:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Retrieve all the TPDs associated with a specific zone
     *     tags: [TPDs - Zone search]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: dataType
     *         type: string
     *         required: true
     *         description: Set to "zone" for this type of search.
     *         in: path
     *       - name: value
     *         type: string
     *         required: true
     *         description: The tracked zone ("example.org", "example.com", etc.) to search for in the records.
     *         in: path
     *     responses:
     *       200:
     *         description: Returns the relevant records associated with the zone.
     *         type: array
     *         items:
     *           $ref: '#/definitions/TPDModel'
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
     * /api/v1.0/tpds/search?dataType=zone&listOnly=1&value={zone}:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Retrieve all the TPDs associated with a specific zone
     *     tags: [TPDs - Zone search]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: dataType
     *         type: string
     *         required: true
     *         description: Set to "zone" for this type of search.
     *         in: path
     *       - name: listOnly
     *         type: string
     *         required: true
     *         description: Set to 1 for this type of response.
     *         in: path
     *       - name: value
     *         type: string
     *         required: true
     *         description: The tracked zone ("example.org", "example.com", etc.) to search for in the records.
     *         in: path
     *     responses:
     *       200:
     *         description: Returns the relevant records associated with the zone.
     *         type: array
     *         items:
     *           $ref: '#/definitions/TPDListOnlyModel'
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
     * /api/v1.0/tpds/search?dataType=tpd&value={tpd_domain}:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Retrieve an individual third-party domain record
     *     tags: [TPDs - TPD search]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: dataType
     *         type: string
     *         required: true
     *         description: Set to "tpd" for this type of search.
     *         in: path
     *       - name: value
     *         type: string
     *         required: true
     *         description: The third-party zone ("fastly.net" etc.) to search for in the records.
     *         in: path
     *     responses:
     *       200:
     *         description: Returns the relevant TPD records.
     *         type: object
     *         schema:
     *           $ref: '#/definitions/TPDModel'
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
     * /api/v1.0/tpds/search?dataType=wildcard&value={zone}:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Retrieve all the TPDs that end with the provided string (e.g. All records that end in "amazonaws.com").
     *     tags: [TPDs - Wildcard search]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: dataType
     *         type: string
     *         required: true
     *         description: Set to "wildcard" for this type of search.
     *         in: path
     *       - name: value
     *         type: string
     *         required: true
     *         description: The ending of the third-party domain for the search (e.g. "amazonaws.com").
     *         in: path
     *     responses:
     *       200:
     *         description: Returns the relevant TPD records that end with the provided string.
     *         type: array
     *         items:
     *           $ref: '#/definitions/TPDModel'
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
     * /api/v1.0/tpds/search?dataType=wildcard&listOnly=1&value={zone}:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: List all the TPDs that end with the specified substring.
     *     tags: [TPDs - Wildcard search]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: dataType
     *         type: string
     *         required: true
     *         description: Set to "wildcard" for this type of search.
     *         in: path
     *       - name: listOnly
     *         type: string
     *         required: true
     *         description: Set to 1 for this type of response.
     *         in: path
     *       - name: value
     *         type: string
     *         required: true
     *         description: The ending of the third-party domain for the search (e.g. "amazonaws.com").
     *         in: path
     *     responses:
     *       200:
     *         description: Returns the relevant TPD records that end with the provided string.
     *         type: array
     *         items:
     *           $ref: '#/definitions/TPDListOnlyModel'
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
     *
     * /api/v1.0/tpds/search:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Returns all TPD records
     *     tags: [TPDs - Fetch all]
     *     produces:
     *       - application/json
     *     responses:
     *       200:
     *         description: Returns all TPD records.
     *         type: array
     *         items:
     *           $ref: '#/definitions/TPDModel'
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
    router.route('/tpds/search')
        .get(function (req, res) {
            let promise;

            if (!is_valid_strings(req.query)) {
                res.status(400).json({ 'message': 'Multiple query parameters are not allowed.' });
                return;
            }

            if ((req.query.hasOwnProperty('dataType'))) {
                if (!req.query.hasOwnProperty('value')) {
                    res.status(400).json({ 'message': 'A value must be provided.' });
                    return;
                }
                let listOnly = false;
                if (req.query.hasOwnProperty('listOnly')
                    && req.query.listOnly === '1') {
                    listOnly = true;
                }

                if (req.query.dataType === 'zone') {
                    promise = tpdRecs.getTPDsByZone(req.query.value, listOnly);
                } else if (req.query.dataType === 'tpd') {
                    promise = tpdRecs.getTPDsByTPD(req.query.value);
                } else if (req.query.dataType === 'wildcard') {
                    promise = tpdRecs.getTPDsByWildcard(req.query.value, listOnly);
                } else {
                    res.status(400).json({ 'message': 'An unknown data type was provided.' });
                    return;
                }
            } else {
                promise = tpdRecs.getAllTPDs();
            }

            promise.then(function (results) {
                if (!results) {
                    res.status(404).json({ 'message': 'Results not found.' });
                    return;
                }
                res.status(200).json(results);
                return;
            });
        });

    return (router);
};
