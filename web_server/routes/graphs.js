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

const graphRecs = require('../config/models/graphs');
const graphDataRecs = require('../config/models/graphs_data');
const graphLinksRecs = require('../config/models/graphs_links');
const graphDocsRecs = require('../config/models/graphs_docs');
const tpdGraphRecs = require('../config/models/tpd_graphs');
const cidrGraphRecs = require('../config/models/cidr_graphs');
const certGraphRecs = require('../config/models/cert_graphs');

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
 *   GraphConfig:
 *     type: object
 *     properties:
 *       config:
 *         type: object
 *         properties:
 *           constraints:
 *             type: array
 *             items:
 *               type: object
 *               properties:
 *                 x:
 *                   type: number
 *                   example: 0.5
 *                 type:
 *                   type: string
 *                   example: "position"
 *                 y:
 *                   type: number
 *                   example: 0.5
 *                 has:
 *                   type: object
 *                   additionalProperties:
 *                     type: string
 *           jsonUrl:
 *             type: string
 *             example: "/api/v1.0/graphs/robohelp.co.za"
 *           graph:
 *             type: object
 *             properties:
 *               height:
 *                 type: integer
 *                 example: 800
 *               charge:
 *                 type: integer
 *                 example: -400
 *               labelPadding:
 *                 type: object
 *                 properties:
 *                   top:
 *                     type: integer
 *                     example: 2
 *                   right:
 *                     type: integer
 *                     example: 3
 *                   bottom:
 *                     type: integer
 *                     example: 2
 *                   left:
 *                     type: integer
 *                     example: 3
 *               labelMargin:
 *                 type: object
 *                 properties:
 *                   top:
 *                     type: integer
 *                     example: 2
 *                   right:
 *                     type: integer
 *                     example: 3
 *                   bottom:
 *                     type: integer
 *                     example: 2
 *                   left:
 *                     type: integer
 *                     example: 3
 *               linkDistance:
 *                 type: integer
 *                 example: 150
 *               ticksWithoutCollisions:
 *                 type: integer
 *                 example: 50
 *               numColors:
 *                 type: integer
 *                 example: 1
 *           title:
 *             type: string
 *             example: "example.org Network Map"
 *           graph_type:
 *             type: string
 *             example: "tracked_domain"
 *           types:
 *             type: object
 *             additionalProperties:
 *               type: object
 *               properties:
 *                 long:
 *                   type: string
 *                   example: "A group from the network: example.org"
 *                 data_type:
 *                   type: string
 *                   example: "tracked_domain"
 *                 short:
 *                   type: string
 *                   example: "example.org"
 *
 *   GraphLink:
 *    type: object
 *    properties:
 *      value:
 *        type: integer
 *        example: 1
 *      target:
 *        type: string
 *        example: "robohelp.co.za"
 *      source:
 *        type: string
 *        example: "www"
 *
 *   GraphLinks:
 *     type: object
 *     properties:
 *       zone:
 *         type: string
 *         example: example.org
 *       directed:
 *         type: boolean
 *         example: false
 *       multigraph:
 *         type: boolean
 *         example: false
 *       created:
 *         type: string
 *         example: 2016-06-22T02:08:46.893Z
 *       errs:
 *         type: array
 *         items:
 *           type: string
 *       links:
 *         type: array
 *         items:
 *           $ref: '#/definitions/GraphLink'
 *
 *   GraphDocs:
 *     type: object
 *     properties:
 *       zone:
 *         type: string
 *         example: example.org
 *       created:
 *         type: string
 *         example: 2016-06-22T02:08:46.893Z
 *       docs:
 *         type: object
 *         additionalProperties:
 *           type: string
 *         example: 'docs{"www": ""<h3>www</h3><br/><b>Type:</b>..."}'
 *
 *
 *   GraphDataEntry:
 *     type: object
 *     properties:
 *       type:
 *         type: integer
 *         example: 0
 *       name:
 *         type: string
 *         example: "www"
 *       group:
 *         type: string
 *         example: "example!org"
 *       data_type:
 *         type: string
 *         example: "domain"
 *       id:
 *         type: string
 *         example: "www"
 *       depends:
 *         type: array
 *         items:
 *           type: string
 *       dependedOnBy:
 *         type: array
 *         items:
 *           type: string
 *
 *
 *   GraphData:
 *     type: object
 *     properties:
 *       zone:
 *         type: string
 *         example: example.org
 *       directed:
 *         type: boolean
 *         example: false
 *       multigraph:
 *         type: boolean
 *         example: false
 *       created:
 *         type: string
 *         example: 2016-06-22T02:08:46.893Z
 *       errs:
 *         type: array
 *         items:
 *           type: string
 *       data:
 *         type: object
 *         additionProperties:
 *           $ref: '#/definitions/GraphDataEntry'
 *
 *   SimpleGraphData:
 *     type: object
 *     properties:
 *       data:
 *         type: object
 *         additionalProperties:
 *           $ref: '#/definitions/GraphDataEntry'
 *       errs:
 *         type: array
 *         items:
 *           type: string
 *           example: "error message"
 *
 *   SimpleLinksData:
 *     type: object
 *     properties:
 *       links:
 *         type: array
 *         items:
 *           $ref: '#/definitions/GraphLink'
 *
 *   CertLink:
 *    type: object
 *    properties:
 *      type:
 *        type: string
 *        example: "uses"
 *      target:
 *        type: string
 *        example: "b95a96510dbad68ae5c3f651a356695b01173dc69c70b25d42101ea035d6240a"
 *      source:
 *        type: string
 *        example: "www.example.org"
 *
 *   CertGraph:
 *     type: object
 *     properties:
 *       nodes:
 *         type: array
 *         items:
 *           type: object
 *           properties:
 *             status:
 *               type: string
 *               example: "No Host"
 *             root:
 *               type: string
 *               example: "false"
 *             type:
 *               type: string
 *               example: "domain"
 *             id:
 *               type: string
 *               example: "download.example.org"
 *             sources:
 *               type: array
 *               items:
 *                 type: string
 *                 example: "ct_logs"
 *       links:
 *         type: array
 *         items:
 *           $ref: '#/definitions/CertLink'
 *       zone:
 *         type: string
 *         example: "example.org"
 *       created:
 *         type: string
 *         example: "2018-02-01T10:06:44.549Z"
 *
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
     *   - name: Graphs - Fetch zone links
     *     description: Fetch the d3.js links component of the zone's graph.
     *   - name: Graphs - Fetch zone config
     *     description: Fetch the d3.js config component of the zone's graph.
     *   - name: Graphs - Fetch zone docs
     *     description: Fetch the d3.js docs component of the zone's graph.
     *   - name: Graphs - Fetch zone count
     *     description: Fetch the count of the graphs for the zone.
     *   - name: Graphs - Fetch zone data
     *     description: Fetch the d3.js data component of the zone's graph.
     *
     * /api/v1.0/graphs/{zone}?dataType=links:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Returns the d3.js links for the provided zone. This is just one part of making a complete graph.
     *     tags: [Graphs - Fetch zone links]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: zone
     *         type: string
     *         required: true
     *         description: The zone ("example.org", "example.com", etc.) to fetch.
     *         in: path
     *       - name: dataType
     *         type: string
     *         required: true
     *         description: Set to "links" for this type of query.
     *         in: query
     *     responses:
     *       200:
     *         description: Returns the links for the relevant zone.
     *         type: object
     *         schema:
     *           $ref: '#/definitions/GraphLinks'
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
     * /api/v1.0/graphs/{zone}?dataType=config:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Returns the d3.js config for the provided zone. This is just one part of making a complete graph.
     *     tags: [Graphs - Fetch zone config]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: zone
     *         type: string
     *         required: true
     *         description: The zone ("example.org", "example.com", etc.) to fetch.
     *         in: path
     *       - name: dataType
     *         type: string
     *         required: true
     *         description: Set to "config" for this type of query.
     *         in: query
     *     responses:
     *       200:
     *         description: Returns the d3.js config for the relevant zone. The additionalProp# keys are domain names.
     *         type: object
     *         schema:
     *           $ref: '#/definitions/GraphConfig'
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
     * /api/v1.0/graphs/{zone}?dataType=docs:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Returns the d3.js documentation for the provided zone. This is the documentation that is shown for each node.
     *     tags: [Graphs - Fetch zone docs]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: zone
     *         type: string
     *         required: true
     *         description: The zone ("example.org", "example.com", etc.) to fetch.
     *         in: path
     *       - name: dataType
     *         type: string
     *         required: true
     *         description: Set to "docs" for this type of query.
     *         in: query
     *     responses:
     *       200:
     *         description: Returns the documentation for each node within the relevant zone. The additionalProp# keys are domain names.
     *         type: object
     *         schema:
     *           $ref: '#/definitions/GraphDocs'
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
     * /api/v1.0/graphs/{zone}?count=1:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: This is just to confirm that the graph exists without sending the entire response body.
     *     tags: [Graphs - Fetch zone count]
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
     *         description: Must be set to "1" to get the count.
     *         in: path
     *     responses:
     *       200:
     *         description: Returns a count of 1 if the graph record exists.
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
     * /api/v1.0/graphs/{zone}:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Returns the d3.js data for the provided zone.
     *     tags: [Graphs - Fetch zone data]
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
     *         description: Returns the graph data for the relevant zone.
     *         type: object
     *         schema:
     *           $ref: '#/definitions/GraphData'
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
    router.route('/graphs/:zone')
        .get(function (req, res) {
            if (!(req.params.hasOwnProperty('zone'))) {
                res.status(400).json({ 'message': 'A zone must be provided.' });
                return;
            }

            if (!is_valid_strings(req.query)) {
                res.status(400).json({ 'message': 'Multiple query parameters are not allowed.' });
                return;
            }

            let graphPromise;
            let count = false;
            if (req.query.hasOwnProperty('dataType') &&
                req.query.dataType === 'links') {
                graphPromise = graphLinksRecs.getGraphLinksByZone(req.params.zone);
            } else if (req.query.hasOwnProperty('dataType') &&
                req.query.dataType === 'config') {
                graphPromise = graphRecs.getGraphConfigByZone(req.params.zone);
            } else if (req.query.hasOwnProperty('dataType') &&
                req.query.dataType === 'docs') {
                graphPromise = graphDocsRecs.getGraphDocsByZone(req.params.zone);
            } else if (req.query.hasOwnProperty('count') && req.query.count == "1") {
                count = true;
                graphPromise = graphDataRecs.getGraphCountByZone(req.params.zone)
            } else {
                graphPromise = graphDataRecs.getGraphDataByZone(req.params.zone);
            }

            graphPromise.then(function (data) {
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
     *   - name: TPD Graphs - Fetch TPD links
     *     description: Fetch the d3.js links component of the TPD's graph.
     *   - name: TPD Graphs - Fetch TPD config
     *     description: Fetch the d3.js config component of the TPD's graph.
     *   - name: TPD Graphs - Fetch TPD data
     *     description: Fetch the d3.js data component of the TPD's graph.
     *
     * /api/v1.0/tpd_graphs/{tpd}?dataType=links:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Returns the d3.js links for the provided TPD. This is just one part of making a complete graph.
     *     tags: [TPD Graphs - Fetch TPD links]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: tpd
     *         type: string
     *         required: true
     *         description: The TPD zone ("fastly.net", "akamai.net", etc.) to fetch.
     *         in: path
     *       - name: dataType
     *         type: string
     *         required: true
     *         description: Set to "links" for this type of query.
     *         in: query
     *     responses:
     *       200:
     *         description: Returns the links for the relevant TPD.
     *         type: object
     *         schema:
     *           $ref: '#/definitions/SimpleLinksData'
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
     * /api/v1.0/tpd_graphs/{tpd}?dataType=config:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Returns the d3.js config for the provided TPD. This is just one part of making a complete graph.
     *     tags: [TPD Graphs - Fetch TPD config]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: tpd
     *         type: string
     *         required: true
     *         description: The TPD zone ("fastly.net", "akamai.net", etc.) to fetch.
     *         in: path
     *       - name: dataType
     *         type: string
     *         required: true
     *         description: Set to "config" for this type of query.
     *         in: query
     *     responses:
     *       200:
     *         description: Returns the d3.js config for the provided TPD. The additionalProp# keys are domain names.
     *         type: object
     *         schema:
     *           $ref: '#/definitions/GraphConfig'
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
     * /api/v1.0/tpd_graphs/{tpd}:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Returns the d3.js data for the provided TPD zone.
     *     tags: [TPD Graphs - Fetch TPD data]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: tpd
     *         type: string
     *         required: true
     *         description: The TPD zone ("fastly.net", "akamai.net", etc.) to fetch.
     *         in: path
     *     responses:
     *       200:
     *         description: Returns the graph data for the relevant TPD zone.
     *         type: object
     *         schema:
     *           $ref: '#/definitions/SimpleGraphData'
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
    router.route('/tpd_graphs/:tpd')
        .get(function (req, res) {

            if (!is_valid_strings(req.query)) {
                res.status(400).json({ 'message': 'Multiple query parameters are not allowed.' });
                return;
            }

            if (!(req.params.hasOwnProperty('tpd'))) {
                res.status(400).json({ 'message': 'A TPD TLD must be provided.' });
                return;
            }

            let graphPromise;
            if (req.query.hasOwnProperty('dataType') &&
                req.query.dataType === 'links') {
                graphPromise = tpdGraphRecs.getTPDGraphLinksByTPD(req.params.tpd);
            } else if (req.query.hasOwnProperty('dataType') &&
                req.query.dataType === 'config') {
                graphPromise = tpdGraphRecs.getTPDGraphConfigByTPD(req.params.tpd);
            } else {
                graphPromise = tpdGraphRecs.getTPDGraphDataByTPD(req.params.tpd);
            }

            graphPromise.then(function (data) {
                if (!data) {
                    res.status(404).json({ 'message': 'TPD TLD not found' });
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
         *   - name: CIDR Graphs - Fetch CIDR links
         *     description: Fetch the d3.js links component of the CIDR's graph.
         *   - name: CIDR Graphs - Fetch CIDR config
         *     description: Fetch the d3.js config component of the CIDR's graph.
         *   - name: CIDR Graphs - Fetch CIDR data
         *     description: Fetch the d3.js data component of the CIDR's graph.
         *
         * /api/v1.0/cidr_graphs/{cidr}?dataType=links:
         *   get:
         *   # Operation-specific security:
         *     security:
         *       - APIKeyHeader: []
         *     description: Returns the d3.js links for the provided Class C (e.g. "8.8.8"). This is just one part of making a complete graph.
         *     tags: [CIDR Graphs - Fetch CIDR links]
         *     produces:
         *       - application/json
         *     parameters:
         *       - name: cidr
         *         type: string
         *         required: true
         *         description: The Class C zone (e.g. "8.8.8") to fetch.
         *         in: path
         *       - name: dataType
         *         type: string
         *         required: true
         *         description: Set to "links" for this type of query.
         *         in: query
         *     responses:
         *       200:
         *         description: Returns the links for the relevant CIDR.
         *         type: object
         *         schema:
         *           $ref: '#/definitions/SimpleLinksData'
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
         * /api/v1.0/cidr_graphs/{cidr}?dataType=config:
         *   get:
         *   # Operation-specific security:
         *     security:
         *       - APIKeyHeader: []
         *     description: Returns the d3.js config for the provided Class 3 zone ("8.8.8"). This is just one part of making a complete graph.
         *     tags: [CIDR Graphs - Fetch CIDR config]
         *     produces:
         *       - application/json
         *     parameters:
         *       - name: cidr
         *         type: string
         *         required: true
         *         description: The Class C zone (e.g. "8.8.8") to fetch.
         *         in: path
         *       - name: dataType
         *         type: string
         *         required: true
         *         description: Set to "config" for this type of query.
         *         in: query
         *     responses:
         *       200:
         *         description: Returns the d3.js config for the provided Class C. The additionalProp# keys are domain names.
         *         type: object
         *         schema:
         *           $ref: '#/definitions/GraphConfig'
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
         * /api/v1.0/cidr_graphs/{cidr}:
         *   get:
         *   # Operation-specific security:
         *     security:
         *       - APIKeyHeader: []
         *     description: Returns the d3.js data for the provided Class C zone (e.g "8.8.8").
         *     tags: [CIDR Graphs - Fetch CIDR data]
         *     produces:
         *       - application/json
         *     parameters:
         *       - name: cidr
         *         type: string
         *         required: true
         *         description: The Class C zone ("8.8.8", etc.) to fetch.
         *         in: path
         *     responses:
         *       200:
         *         description: Returns the graph data for the relevant Class C.
         *         type: object
         *         schema:
         *           $ref: '#/definitions/SimpleGraphData'
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
    router.route('/cidr_graphs/:cidr')
        .get(function (req, res) {

            if (!is_valid_strings(req.query)) {
                res.status(400).json({ 'message': 'Multiple query parameters are not allowed.' });
                return;
            }

            if (!(req.params.hasOwnProperty('cidr'))) {
                res.status(400).json({ 'message': 'A Class 3 zone (e.g. "8.8.8") must be provided.' });
                return;
            }

            let graphPromise;
            if (req.query.hasOwnProperty('dataType') &&
                req.query.dataType === 'links') {
                graphPromise = cidrGraphRecs.getCIDRGraphLinksByZone(req.params.cidr);
            } else if (req.query.hasOwnProperty('dataType') &&
                req.query.dataType === 'config') {
                graphPromise = cidrGraphRecs.getCIDRGraphConfigByZone(req.params.cidr);
            } else {
                graphPromise = cidrGraphRecs.getCIDRGraphDataByZone(req.params.cidr);
            }

            graphPromise.then(function (data) {
                if (!data) {
                    res.status(404).json({ 'message': 'CIDR not found' });
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
     *   - name: Cert Graphs - Fetch certificate graph
     *     description: Fetch the certificate graph for the requested zone.
     *
     * /api/v1.0/cert_graphs/{zone}:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Returns the d3.js graph for the provided certificate zone.
     *     tags: [Cert Graphs - Fetch certificate graph]
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
     *         description: Returns the links for the relevant certificate zone.
     *         type: object
     *         schema:
     *           $ref: '#/definitions/CertGraph'
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

    router.route('/cert_graphs/:zone')
        .get(function (req, res) {
            if (!(req.params.hasOwnProperty('zone'))) {
                res.status(500).json({ 'message': 'A zone must be provided.' });
                return;
            }

            let graphPromise = certGraphRecs.getGraphDataByZone(req.params.zone);

            graphPromise.then(function (data) {
                if (!data) {
                    res.status(404).json({ 'message': 'Zone not found' });
                    return;
                }
                res.status(200).json(data);
                return;
            });
        });

    return (router);
};
