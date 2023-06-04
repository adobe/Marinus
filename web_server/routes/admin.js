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
const crypto = require('crypto');
const htmlEscape = require('secure-filters').html;

const user = require('../config/models/user');
const group = require('../config/models/group');
const zone = require('../config/models/zone');
const ipZone = require('../config/models/ip_zone');
const ipv6Zone = require('../config/models/ipv6_zone');
const jobs = require('../config/models/jobs');
const marinusConfig = require('../config/models/config.js')

const statusValues = ['confirmed', 'unconfirmed', 'false_positive', 'expired'];

/**
 * Generates a random string of hex characters that is len characters long.
 * It will have the security of a len/2 password
 *
 * @param {Number} len The length of the API key to generate.
 * @return {String} A string representing len # of random bytes.
 */
function createAPIKey(len) {
    return crypto.randomBytes(Math.ceil(len / 2))
        .toString('hex') // convert to hexadecimal format
        .slice(0, len); // return required number of characters
}

/**
 * Validates the user identified in the request session is an admin.
 * Ends the request and returns an error if they are not.
 * @param {Object} req The Express request object
 * @param {Object} res The Express response object
 */
function checkAdmin(req, res) {
    if (req.session && ((req.session.groups === undefined) ||
        (req.session.groups.indexOf('admin') === -1))) {
        res.status(401).json({
            'message': 'You do not appear to be an admin',
        });
    } else if (!req.session) {
        res.status(401).json({
            'message': 'You do not appear to have a session',
        });
    }
}

/**
 * Validates the user identified in the request session is a data admin.
 * Ends the request and returns an error if they are not.
 * @param {*} req The Express request object
 * @param {*} res The Express response object
 */
function checkDataAdmin(req, res) {
    if (req.session &&
        (req.session.groups === undefined) ||
        ((req.session.groups.indexOf('admin') === -1) &&
            (req.session.groups.indexOf('data_admin') === -1))) {
        res.status(401).json({
            'message': 'You do not appear to have modify permissions',
        });
    } else if (!req.session) {
        res.status(401).json({
            'message': 'You do not appear to have a session',
        });
    }
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
 *   UserRecord:
 *     type: object
 *     properties:
 *       userid:
 *         type: string
 *         example: "marinus"
 *       creation_date:
 *         type: string
 *         example: 2016-06-22T02:08:46.893Z
 *       updated:
 *         type: string
 *         example: 2016-06-22T02:08:46.893Z
 *       apiKey:
 *         type: string
 *         description: The apiKey for the user which is a 32 byte random string
 *       status:
 *         type: string
 *         example: "active"
 *         description: Whether the user account is currently active
 *
 *   GroupRecord:
 *     type: object
 *     properties:
 *       name:
 *         type: string
 *         example: "admin"
 *         description: The name of the group
 *       creation_date:
 *         type: string
 *         example: 2016-06-22T02:08:46.893Z
 *       updated:
 *         type: string
 *         example: 2016-06-22T02:08:46.893Z
 *       admins:
 *         type: array
 *         description: The array of people allowed to modify the group
 *         items:
 *           type: string
 *           example: admin
 *       status:
 *         type: string
 *         example: "active"
 *         description: Whether the user account is currently active
 *       members:
 *         type: array
 *         description: The array of people within the group
 *         items:
 *           type: string
 *           example: admin
 *
 *   JobRecord:
 *     type: object
 *     properties:
 *       job_name:
 *         type: string
 *         example: "common_crawl_graph"
 *         description: The name of the job
 *       updated:
 *         type: string
 *         example: 2016-06-22T02:08:46.893Z
 *       status:
 *         type: string
 *         example: "COMPLETED"
 *         description: The status of the job
 *
 *   ConfigRecord:
 *     type: object
 *     properties:
 *       updated:
 *         type: string
 *         example: 2016-06-22T02:08:46.893Z
 *       DNS_Admins:
 *         description: An array of the DNS Admins.
 *         type: array
 *         items:
 *           type: string
 *           example: "dns-admin@example.org"
 *       SSL_Orgs:
 *         description: An array of the TLS Organizations
 *         type: array
 *         items:
 *           type: string
 *           example: "Acme, Inc."
 *       Whois_Orgs:
 *         description: An array of the Whois Organizations
 *         type: array
 *         items:
 *           type: string
 *           example: "Acme, Inc."
 */

module.exports = function (envConfig) {
    /**
     * @swagger
     *
     * security:
     *   - APIKeyHeader: []
     *
     * tags:
     *   - name: Admin - Retrieve your own user record
     *     description: Retrieve the user record of the current user
     *
     * /api/v1.0/admin/self:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Retrieves the information of the currently logged in user. Admin privileges not required.
     *     tags: [Admin - Retrieve your own user record]
     *     produces:
     *       - application/json
     *     responses:
     *       200:
     *         description: An individual user record for the current user.
     *         type: object
     *         schema:
     *           $ref: '#/definitions/UserRecord'
     *       404:
     *         description: Results not found.
     *         schema:
     *           $ref: '#/definitions/ResultsNotFound'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     */
    router.route('/admin/self')
        .get(function (req, res) {
            let userPromise;
            if (typeof req.session.userid !== 'undefined') {
                userPromise = user.getUserIdPromise(req.session.userid, true);
            } else {
                userPromise = user.getUserIdPromise(req.session.passport.user.userid, true);
            }
            userPromise.then(
                function (userInDB) {
                    if (!userInDB) {
                        res.status(404).json({
                            'message': 'User not found!',
                        });
                        return;
                    }
                    res.status(200).json(userInDB);
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
     *   - name: Admin - Retrieve your own group
     *     description: Retrieve the group data of the current user
     *
     * /api/v1.0/admin/self_group:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: Retrieves the group information of the currently logged in user. Admin privileges not required.
     *     tags: [Admin - Retrieve your own group]
     *     produces:
     *       - application/json
     *     responses:
     *       200:
     *         description: An individual user record for the current user.
     *         type: object
     *         schema:
     *           $ref: '#/definitions/GroupRecord'
     *       404:
     *         description: Results not found.
     *         schema:
     *           $ref: '#/definitions/ResultsNotFound'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     */
    router.route('/admin/self_group')
        .get(function (req, res) {
            let groupPromise;
            if (typeof req.session.userid !== 'undefined') {
                groupPromise = group.getGroupsByUserPromise(req.session.userid, true);
            } else {
                groupPromise = group.getGroupsByUserPromise(req.session.passport.user.userid, true);
            }
            groupPromise.then(
                function (groups) {
                    if (!groups) {
                        res.status(404).json({
                            'message': 'Group not found!',
                        });
                        return;
                    }
                    res.status(200).json(groups);
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
     *   - name: Admin - Retrieve a given user record
     *     description: "[Admin-only] Retrieve the user record of the provided user."
     *
     * /api/v1.0/admin/users/{userid}:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: "[Admin-only] Retrieve the user record of the provided active user. This does not retrieve inactive users. You must be an admin to use this API."
     *     tags: [Admin - Retrieve a given user record]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: userid
     *         type: string
     *         required: true
     *         description: The userid to find in the database.
     *         in: path
     *     responses:
     *       200:
     *         description: An individual user record for the current user.
     *         type: object
     *         schema:
     *           $ref: '#/definitions/UserRecord'
     *       400:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       404:
     *         description: Results not found.
     *         schema:
     *           $ref: '#/definitions/ResultsNotFound'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     *   post:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: "[Admin-only] Change the status of a user. You must be an admin to use this API."
     *     tags: [Admin - Change a user's status]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: userid
     *         type: string
     *         required: true
     *         description: The userid to find in the database.
     *         in: path
     *       - name: status
     *         type: string
     *         required: true
     *         description: Must be 'active' or 'inactive'
     *         in: body
     *     responses:
     *       201:
     *         description: A message indicating whether the change succeeded.
     *         type: object
     *         properties:
     *           message:
     *             type: string
     *             example: "User updated!"
     *             description: A status message indicating success or failure
     *       400:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       404:
     *         description: Results not found.
     *         schema:
     *           $ref: '#/definitions/ResultsNotFound'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     */
    router.route('/admin/users/:userid')
        .get(function (req, res) {
            checkAdmin(req, res);

            if (!(req.params.hasOwnProperty('userid'))) {
                res.status(400).json({ 'message': 'A userid must be provided!' });
                return;
            }

            let userPromise = user.getUserIdPromise(req.params.userid, false);
            userPromise.then(
                function (userInDB) {
                    if (!userInDB) {
                        res.status(404).json({
                            'message': 'User not found!',
                        });
                        return;
                    }
                    res.status(200).json(userInDB);
                    return;
                });
        })
        .post(function (req, res) {
            checkAdmin(req, res);
            if (!(req.params.hasOwnProperty('userid'))) {
                res.status(400).json({ 'message': 'A userid must be provided!' });
                return;
            }
            if (!('status' in req.body)) {
                res.status(400).json({ 'message': 'A status must be provided!' });
                return;
            }

            if (req.body.status != 'active' && req.body.status != 'inactive') {
                res.status(400).json({ 'message': 'A status can only be "active" or "inactive"!' });
                return;
            }

            let userPromise = user.getUserIdPromise(req.params.userid, false);
            userPromise.then(function (user) {
                if (!user) {
                    res.status(404).json({
                        'message': 'User not found!',
                    });
                    return;
                }
                user.updated = Date.now();
                user.status = req.body.status;
                user.save(function (err) {
                    if (err) {
                        res.status(500).send(err);
                        return;
                    }

                    res.status(201).json({
                        message: 'User updated!',
                    });
                });
            });
        });

    /**
     * @swagger
     *
     * security:
     *   - APIKeyHeader: []
     *
     * tags:
     *   - name: Admin - Retrieve a list of current users
     *     description: "[Admin-only] Retrieve the list of user records."
     *   - name: Admin - Add a new user
     *     description: "[Admin-only] Adds a new user to the database."
     *
     * /api/v1.0/admin/users:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: "[Admin-only] Retrieves the list of users. This will not return their apiKeys in the response. You must be an admin to use this API."
     *     tags: [Admin - Retrieve a list of current users]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: active
     *         type: string
     *         required: false
     *         description: Whether to retrieve only active users
     *         in: query
     *     responses:
     *       200:
     *         description: An array of current users without their apiKeys.
     *         type: array
     *         items:
     *           $ref: '#/definitions/UserRecord'
     *       404:
     *         description: Results not found.
     *         schema:
     *           $ref: '#/definitions/ResultsNotFound'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     *   post:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: "[Admin-only] Adds a new user to Marinus. The user will automatically be set to active and have an apiKey created."
     *     tags: [Admin - Add a new user]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: userid
     *         type: string
     *         required: true
     *         description: The userid to create in the database.
     *         in: body
     *     responses:
     *       201:
     *         description: A message indicating whether the addition succeeded.
     *         type: object
     *         properties:
     *           message:
     *             type: string
     *             example: "User created!"
     *             description: A status message indicating success or failure
     *       400:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     */
    router.route('/admin/users')
        .get(function (req, res) {
            checkAdmin(req, res);
            let activeOnly = true;

            if (!is_valid_strings(req.query)) {
                res.status(400).json({ 'message': 'Multiple query parameters are not allowed.' });
                return;
            }

            if (req.query.hasOwnProperty('active')) {
                if (req.query.active === 'false') {
                    activeOnly = false;
                }
            }
            let userPromise = user.getUserListPromise(activeOnly);
            userPromise.then(
                function (userInDB) {
                    if (!userInDB) {
                        res.status(404).json({
                            'message': 'Users not found!',
                        });
                        return;
                    }
                    res.status(200).json(userInDB);
                    return;
                });
        })
        .post(function (req, res) {
            checkAdmin(req, res);
            if (!('userid' in req.body)) {
                res.status(400).json({ 'message': 'A userid must be provided!' });
                return;
            }
            let userPromise = user.getUserIdPromise(req.body.userid, false);
            userPromise.then(
                function (userInDB) {
                    if (!userInDB) {
                        let newUser = new user.UserModel();
                        newUser.userid = req.body.userid.replace(/ /g, '');
                        newUser.apiKey = createAPIKey(envConfig.api_key_length);
                        newUser.creation_date = Date.now();
                        newUser.updated = Date.now();
                        newUser.status = 'active';
                        // save the user and check for errors
                        newUser.save(function (err) {
                            if (err) {
                                res.status(500).send(err);
                                return;
                            }
                            res.status(201).json({
                                message: 'User created!',
                            });
                        });
                    } else {
                        res.status(400).json({
                            message: 'User ' + htmlEscape(userInDB.userid) + ' already exists!',
                        });
                    }
                }).catch(function (errorMsg) {
                    res.status(500).json({
                        'message': errorMsg.toString(),
                    });
                });
        });

    /**
     * @swagger
     *
     * security:
     *   - APIKeyHeader: []
     *
     * tags:
     *   - name: Admin - Retrieve a list of current groups
     *     description: "[Admin-only] Retrieve the list of group records."
     *   - name: Admin - Add a new group
     *     description: "[Admin-only] Adds a new group to the database."
     *
     * /api/v1.0/admin/groups:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: "[Admin-only] Retrieves the list of groups. You must be an admin to use this API."
     *     tags: [Admin - Retrieve a list of current groups]
     *     produces:
     *       - application/json
     *     responses:
     *       200:
     *         description: The list of current groups.
     *         type: array
     *         items:
     *           $ref: '#/definitions/GroupRecord'
     *       404:
     *         description: Results not found.
     *         schema:
     *           $ref: '#/definitions/ResultsNotFound'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     *   post:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: "[Admin-only] Adds a new group to Marinus."
     *     tags: [Admin - Add a new group]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: name
     *         type: string
     *         required: true
     *         description: The name of the new group to create in the database.
     *         in: body
     *     responses:
     *       201:
     *         description: A message indicating whether the group addition succeeded.
     *         type: object
     *         properties:
     *           message:
     *             type: string
     *             example: "Group created!"
     *             description: A status message indicating success or failure
     *       400:
     *         description: Bad request parameters.
     *         schema:
     *           $ref: '#/definitions/BadInputError'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     */
    router.route('/admin/groups')
        .get(function (req, res) {
            checkAdmin(req, res);
            let groupPromise = group.getAllGroups();
            groupPromise.then(function (groups) {
                if (!groups) {
                    res.status(404).json({
                        'message': 'Error in lookup!',
                    });
                    return;
                }
                res.json(groups);
                return;
            });
        })
        .post(function (req, res) {
            checkAdmin(req, res);
            if (!('name' in req.body)) {
                res.status(400).json({ 'message': 'A name must be provided!' });
                return;
            }
            let groupPromise = group.getGroupByNamePromise(req.body.name);
            groupPromise.then(function (groupInDB) {
                if (!groupInDB) {
                    let newGroup = new group.GroupModel();
                    if (req.session.passport && req.session.passport.user.userid) {
                        newGroup.creator = req.session.passport.user.userid;
                    } else if (req.session.userid) {
                        newGroup.creator = req.session.userid;
                    }
                    newGroup.groupID = 1;
                    newGroup.name = req.body.name.replace(/ /g, '');
                    newGroup.admins = [newGroup.creator];
                    newGroup.status = 'active';
                    newGroup.members = [newGroup.creator];
                    newGroup.creation_date = Date.now();
                    newGroup.updated = Date.now();

                    // save the domain and check for errors
                    newGroup.save(function (err) {
                        if (err) {
                            res.status(500).send(err);
                            return;
                        }

                        res.status(201).json({
                            message: 'Group created!',
                        });
                    });
                } else {
                    res.status(500).json({
                        'message': 'Group  ' + htmlEscape(groupInDB.name) + ' already exists!',
                    });
                }
            }).catch(function (errorMsg) {
                res.status(500).json({
                    'message': errorMsg.toString(),
                });
            });
        });

    /**
      * @swagger
      *
      * security:
      *   - APIKeyHeader: []
      *
      * tags:
      *   - name: Admin - Add a user to a group record
      *     description: "[Admin-only] Add the user to the provided group."
      *
      * /api/v1.0/admin/groups/{group}:
      *   patch:
      *   # Operation-specific security:
      *     security:
      *       - APIKeyHeader: []
      *     description: "[Admin-only] Add a new member to a group record."
      *     tags: [Admin - Add a user to a group record]
      *     produces:
      *       - application/json
      *     parameters:
      *       - name: group
      *         type: string
      *         required: true
      *         description: The group to modify in the database.
      *         in: path
      *       - name: member
      *         type: string
      *         required: true
      *         description: The new member to add to the group.
      *         in: body
      *     responses:
      *       201:
      *         description: A message indicating whether the group addition succeeded.
      *         type: object
      *         properties:
      *           message:
      *             type: string
      *             example: "Group updated!"
      *             description: A status message indicating success or failure
      *       400:
      *         description: Bad request parameters.
      *         schema:
      *           $ref: '#/definitions/BadInputError'
      *       404:
      *         description: Results not found.
      *         schema:
      *           $ref: '#/definitions/ResultsNotFound'
      *       500:
      *         description: Server error.
      *         schema:
      *           $ref: '#/definitions/ServerError'
      */
    router.route('/admin/groups/:group')
        .patch(function (req, res) {
            checkAdmin(req, res);
            if (!(req.params.hasOwnProperty('group'))) {
                res.status(400).json({ 'message': 'A group must be provided!' });
                return;
            }
            if (!('member' in req.body) ||
                req.body.member.length === 0) {
                res.status(400).json({ 'message': 'A member must be provided!' });
                return;
            }
            let groupPromise = group.getGroupByNamePromise(req.params.group);
            groupPromise.then(function (group) {
                if (!group) {
                    res.status(404).json({
                        'message': 'Group not found!',
                    });
                    return;
                }
                if ('member' in req.body) {
                    group['members'].push(req.body.member.replace(/ /g, ''));
                }
                group.updated = Date.now();
                group.save(function (err) {
                    if (err) {
                        res.status(500).send(err);
                        return;
                    }

                    res.status(201).json({
                        message: 'Group updated!',
                    });
                });
            });
        });

    /**
      * @swagger
      *
      * security:
      *   - APIKeyHeader: []
      *
      * tags:
      *   - name: Admin - Add a zone to Marinus
      *     description: "[Admin-only] Add a new zone to Marinus"
      *
      * /api/v1.0/admin/zones:
      *   post:
      *   # Operation-specific security:
      *     security:
      *       - APIKeyHeader: []
      *     description: "[Admin-only] Manually add a new zone for Marinus to track."
      *     tags: [Admin - Add a zone to Marinus]
      *     produces:
      *       - application/json
      *     parameters:
      *       - name: zone
      *         type: string
      *         required: true
      *         description: The new zone to add to Marinus.
      *         example: "example.org"
      *         in: body
      *     responses:
      *       201:
      *         description: A message indicating whether the zone addition succeeded.
      *         type: object
      *         properties:
      *           message:
      *             type: string
      *             example: "Zone created!"
      *             description: A status message indicating success or failure
      *       400:
      *         description: Bad request parameters.
      *         schema:
      *           $ref: '#/definitions/BadInputError'
      *       404:
      *         description: Results not found.
      *         schema:
      *           $ref: '#/definitions/ResultsNotFound'
      *       500:
      *         description: Server error.
      *         schema:
      *           $ref: '#/definitions/ServerError'
      */
    router.route('/admin/zones')
        .post(function (req, res) {
            checkAdmin(req, res);
            if (!('zone' in req.body) ||
                req.body.zone.length === 0) {
                res.status(400).json({ 'message': 'A zone must be provided!' });
                return;
            }
            let zonePromise = zone.getZoneByNamePromise(req.body.zone);
            zonePromise.then(function (zoneInDB) {
                if (!zoneInDB) {
                    let newZone = new zone.ZoneModel();
                    newZone.updated = Date.now();
                    newZone.created = Date.now();
                    newZone.status = 'unconfirmed';
                    newZone.reporting_sources = [];
                    let reporting_sources = {}
                    reporting_sources['created'] = Date.now();
                    reporting_sources['updated'] = Date.now();
                    reporting_sources['source'] = 'manual';
                    reporting_sources['status'] = 'unconfirmed';
                    newZone.reporting_sources.push(reporting_sources);
                    newZone.zone = req.body.zone;
                    newZone.save(function (err) {
                        if (err) {
                            res.status(500);
                            res.send(err);
                            return;
                        }

                        res.status(201);
                        res.json({
                            message: 'Zone created!',
                        });
                    });
                } else {
                    res.status(500).json({
                        'message': 'Zone ' + htmlEscape(zoneInDB.zone) + ' already exists!',
                    });
                }
            }).catch(function (errorMsg) {
                res.status(500).json({
                    'message': errorMsg.toString(),
                });
            });
        });


    /**
      * @swagger
      *
      * security:
      *   - APIKeyHeader: []
      *
      * tags:
      *   - name: Admin - Modify a zone in Marinus
      *     description: "[DataAdmin-only] Modify an existing zone in Marinus"
      *
      * /api/v1.0/admin/zones/{zone}:
      *   patch:
      *   # Operation-specific security:
      *     security:
      *       - APIKeyHeader: []
      *     description: "[DataAdmin-only] Change the notes or status of a zone in Marinus. You must be a DataAdmin to make this change."
      *     tags: [Admin - Modify a zone in Marinus]
      *     produces:
      *       - application/json
      *     parameters:
      *       - name: zone
      *         type: string
      *         required: true
      *         description: The zone to modify in Marinus
      *         example: "example.org"
      *         in: body
      *       - name: notes
      *         type: string
      *         required: false
      *         description: A short string to add to the collection of notes for the zone.
      *         example: "This zone belongs a new acquisition"
      *         in: body
      *       - name: status
      *         type: string
      *         required: false
      *         description: "The status for the zone. Must be either 'confirmed', 'unconfirmed', 'expired', or 'false_positive'."
      *         example: "false_positive"
      *         in: body
      *     responses:
      *       201:
      *         description: A message indicating whether the zone modification succeeded.
      *         type: object
      *         properties:
      *           message:
      *             type: string
      *             example: "Zone updated!"
      *             description: A status message indicating success or failure
      *       400:
      *         description: Bad request parameters.
      *         schema:
      *           $ref: '#/definitions/BadInputError'
      *       404:
      *         description: Results not found.
      *         schema:
      *           $ref: '#/definitions/ResultsNotFound'
      *       500:
      *         description: Server error.
      *         schema:
      *           $ref: '#/definitions/ServerError'
      */
    router.route('/admin/zones/:zone')
        .patch(function (req, res) {
            checkDataAdmin(req, res);
            if (!(req.params.hasOwnProperty('zone'))) {
                res.status(400).json({ 'message': 'A zone must be provided!' });
                return;
            }
            let zonePromise = zone.getZoneByIdPromise(req.params.zone);
            zonePromise.then(function (zoneInDB) {
                if (zoneInDB) {
                    if ('notes' in req.body) {
                        zoneInDB['notes'].push(req.body.notes);
                    }
                    if ('status' in req.body) {
                        if (statusValues.indexOf(req.body.status) === -1) {
                            res.status(400).json({
                                'message': 'A bad status_value was provided.',
                            });
                            return;
                        }
                        zoneInDB['status'] = req.body.status;
                    }
                    zoneInDB.updated = Date.now();
                    zoneInDB.save(function (err) {
                        if (err) {
                            res.status(500).send(err);
                            return;
                        }

                        res.status(201).json({
                            message: 'Zone updated!',
                        });
                    });
                } else {
                    res.status(500).json({
                        'message': 'Error updating ' + htmlEscape(zoneInDB.zone),
                    });
                }
            }).catch(function (errorMsg) {
                res.status(500).json({
                    'message': errorMsg.toString(),
                });
            });
        });

    /**
      * @swagger
      *
      * security:
      *   - APIKeyHeader: []
      *
      * tags:
      *   - name: Admin - Add an IPv4 zone to Marinus
      *     description: "[Admin-only] Add a new IPv4 zone to Marinus"
      *
      * /api/v1.0/admin/ip_zones:
      *   post:
      *   # Operation-specific security:
      *     security:
      *       - APIKeyHeader: []
      *     description: "[Admin-only] Manually add a new IPv4 zone for Marinus to track."
      *     tags: [Admin - Add an IPv4 zone to Marinus]
      *     produces:
      *       - application/json
      *     parameters:
      *       - name: zone
      *         type: string
      *         required: true
      *         description: The new IPv4 zone to add to Marinus.
      *         example: "example.org"
      *         in: body
      *     responses:
      *       201:
      *         description: A message indicating whether the IPv4 zone addition succeeded.
      *         type: object
      *         properties:
      *           message:
      *             type: string
      *             example: "IPv4 zone created!"
      *             description: A status message indicating success or failure
      *       400:
      *         description: Bad request parameters.
      *         schema:
      *           $ref: '#/definitions/BadInputError'
      *       404:
      *         description: Results not found.
      *         schema:
      *           $ref: '#/definitions/ResultsNotFound'
      *       500:
      *         description: Server error.
      *         schema:
      *           $ref: '#/definitions/ServerError'
      */
    router.route('/admin/ip_zones')
        .post(function (req, res) {
            checkAdmin(req, res);
            if (!('zone' in req.body)) {
                res.status(400).json({ 'message': 'An IPv4 zone must be provided!' });
                return;
            }
            let ipv4 = /^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/([0-9]|[1-2][0-9]|3[0-2]))$/;
            if (!(req.body.zone.match(ipv4))) {
                res.status(400).json({
                    'message': 'An invalid IPv4 zone has been provided',
                });
                return;
            }
            let zonePromise = ipZone.getZoneByNamePromise(req.body.zone);
            zonePromise.then(function (zoneInDB) {
                if (!zoneInDB) {
                    let newZone = new ipZone.IpZoneModel();
                    newZone.updated = Date.now();
                    newZone.created = Date.now();
                    newZone.status = 'confirmed';
                    newZone.sources = { "source": 'manual', "updated": Date.now() };
                    newZone.source = 'manual';
                    newZone.zone = req.body.zone;
                    newZone.notes = [];
                    newZone.save(function (err) {
                        if (err) {
                            res.status(500).send(err);
                            return;
                        }

                        res.status(201).json({
                            message: 'IPv4 zone created!',
                        });
                    });
                } else {
                    res.status(500).json({
                        'message': 'IPv4 Zone ' + htmlEscape(zoneInDB.zone) + ' already exists!',
                    });
                }
            }).catch(function (errorMsg) {
                res.status(500).json({
                    'message': errorMsg.toString(),
                });
            });
        });

    /**
      * @swagger
      *
      * security:
      *   - APIKeyHeader: []
      *
      * tags:
      *   - name: Admin - Modify an IPv4 zone in Marinus
      *     description: "[DataAdmin-only] Modify an existing IPv4 zone in Marinus"
      *
      * /api/v1.0/admin/ip_zones/{zone}:
      *   patch:
      *   # Operation-specific security:
      *     security:
      *       - APIKeyHeader: []
      *     description: "[DataAdmin-only] Change the notes or status of an IPv4 zone in Marinus. You must be a DataAdmin to make this change."
      *     tags: [Admin - Modify an IPv4 zone in Marinus]
      *     produces:
      *       - application/json
      *     parameters:
      *       - name: zone
      *         type: string
      *         required: true
      *         description: The IPv4 zone to modify in Marinus
      *         example: "12.34.56.78"
      *         in: body
      *       - name: notes
      *         type: string
      *         required: false
      *         description: A short string to add to the collection of notes for the IPv4 zone.
      *         example: "This zone represents the Oregon data center."
      *         in: body
      *       - name: status
      *         type: string
      *         required: false
      *         description: "The status for the IPv4 zone. Must be either 'confirmed', 'unconfirmed', 'expired', or 'false_positive'."
      *         example: "false_positive"
      *         in: body
      *     responses:
      *       201:
      *         description: A message indicating whether the IPv4 zone modification succeeded.
      *         type: object
      *         properties:
      *           message:
      *             type: string
      *             example: "IPv4 zone updated!"
      *             description: A status message indicating success or failure
      *       400:
      *         description: Bad request parameters.
      *         schema:
      *           $ref: '#/definitions/BadInputError'
      *       404:
      *         description: Results not found.
      *         schema:
      *           $ref: '#/definitions/ResultsNotFound'
      *       500:
      *         description: Server error.
      *         schema:
      *           $ref: '#/definitions/ServerError'
      */
    router.route('/admin/ip_zones/:id')
        .patch(function (req, res) {
            checkDataAdmin(req, res);
            if (!(req.params.hasOwnProperty('id'))) {
                res.status(400).json({ 'message': 'An IPv4 CIDR must be provided!' });
                return;
            }
            let zonePromise = ipZone.getZoneByIdPromise(req.params.id);
            zonePromise.then(function (zoneInDB) {
                if (zoneInDB) {
                    if ('notes' in req.body) {
                        zoneInDB['notes'].push(req.body.notes);
                    }
                    if ('status' in req.body) {
                        if (statusValues.indexOf(req.body.status) === -1) {
                            res.status(400).json({
                                'message': 'A bad status_value was provided.',
                            });
                            return;
                        }
                        zoneInDB['status'] = req.body.status;
                    }
                    zoneInDB.updated = Date.now();
                    zoneInDB.save(function (err) {
                        if (err) {
                            res.status(500).send(err);
                            return;
                        }

                        res.status(201).json({
                            message: 'IPv4 zone updated!',
                        });
                    });
                } else {
                    res.status(500).json({
                        'message': 'Error updating ' + htmlEscape(zoneInDB.zone),
                    });
                }
            }).catch(function (errorMsg) {
                res.status(500).json({
                    'message': errorMsg.toString(),
                });
            });
        });

    /**
      * @swagger
      *
      * security:
      *   - APIKeyHeader: []
      *
      * tags:
      *   - name: Admin - Add an IPv6 zone to Marinus
      *     description: "[Admin-only] Add a new IPv6 zone to Marinus"
      *
      * /api/v1.0/admin/ipv6_zones:
      *   post:
      *   # Operation-specific security:
      *     security:
      *       - APIKeyHeader: []
      *     description: "[Admin-only] Manually add a new IPv6 zone for Marinus to track."
      *     tags: [Admin - Add an IPv6 zone to Marinus]
      *     produces:
      *       - application/json
      *     parameters:
      *       - name: zone
      *         type: string
      *         required: true
      *         description: The new IPv6 zone to add to Marinus.
      *         example: "example.org"
      *         in: body
      *     responses:
      *       201:
      *         description: A message indicating whether the IPv6 zone addition succeeded.
      *         type: object
      *         properties:
      *           message:
      *             type: string
      *             example: "IPv6 zone created!"
      *             description: A status message indicating success or failure
      *       400:
      *         description: Bad request parameters.
      *         schema:
      *           $ref: '#/definitions/BadInputError'
      *       404:
      *         description: Results not found.
      *         schema:
      *           $ref: '#/definitions/ResultsNotFound'
      *       500:
      *         description: Server error.
      *         schema:
      *           $ref: '#/definitions/ServerError'
      */
    router.route('/admin/ipv6_zones')
        .post(function (req, res) {
            checkAdmin(req, res);
            if (!('zone' in req.body)) {
                res.status(400).json({ 'message': 'An IPv6 zone must be provided!' });
                return;
            }
            let ipv6 = /^[0-9a-zA-z\:]+(\/([0-9]|[1-5][0-9]|6[0-4]))$/;
            if (!(req.body.zone.match(ipv6))) {
                res.status(400).json({
                    'message': 'An invalid IPv6 zone has been provided',
                });
                return;
            }
            let zonePromise = ipv6Zone.getZoneByNamePromise(req.body.zone);
            zonePromise.then(function (zoneInDB) {
                if (!zoneInDB) {
                    let newZone = new ipv6Zone.Ipv6ZoneModel();
                    newZone.updated = Date.now();
                    newZone.created = Date.now();
                    newZone.status = 'confirmed';
                    newZone.sources = { "source": 'manual', "updated": Date.now() };
                    newZone.zone = req.body.zone;
                    newZone.notes = [];
                    newZone.save(function (err) {
                        if (err) {
                            res.status(500).send(err);
                            return;
                        }

                        res.status(201).json({
                            message: 'IPv6 zone created!',
                        });
                    });
                } else {
                    res.status(500).json({
                        'message': 'IPv6 Zone ' + htmlEscape(zoneInDB.zone) + ' already exists!',
                    });
                }
            }).catch(function (errorMsg) {
                res.status(500).json({
                    'message': errorMsg.toString(),
                });
            });
        });

    /**
      * @swagger
      *
      * security:
      *   - APIKeyHeader: []
      *
      * tags:
      *   - name: Admin - Modify an IPv6 zone in Marinus
      *     description: "[DataAdmin-only] Modify an existing IPv6 zone in Marinus"
      *
      * /api/v1.0/admin/ipv6_zones/{zone}:
      *   patch:
      *   # Operation-specific security:
      *     security:
      *       - APIKeyHeader: []
      *     description: "[DataAdmin-only] Change the notes or status of an IPv6 zone in Marinus. You must be a DataAdmin to make this change."
      *     tags: [Admin - Modify an IPv6 zone in Marinus]
      *     produces:
      *       - application/json
      *     parameters:
      *       - name: zone
      *         type: string
      *         required: true
      *         description: The IPv6 zone to modify in Marinus
      *         example: "12.34.56.78"
      *         in: body
      *       - name: notes
      *         type: string
      *         required: false
      *         description: A short string to add to the collection of notes for the IPv6 zone.
      *         example: "This zone represents the Oregon data center."
      *         in: body
      *       - name: status
      *         type: string
      *         required: false
      *         description: "The status for the IPv6 zone. Must be either 'confirmed', 'unconfirmed', 'expired', or 'false_positive'."
      *         example: "false_positive"
      *         in: body
      *     responses:
      *       201:
      *         description: A message indicating whether the IPv6 zone modification succeeded.
      *         type: object
      *         properties:
      *           message:
      *             type: string
      *             example: "IPv6 zone updated!"
      *             description: A status message indicating success or failure
      *       400:
      *         description: Bad request parameters.
      *         schema:
      *           $ref: '#/definitions/BadInputError'
      *       404:
      *         description: Results not found.
      *         schema:
      *           $ref: '#/definitions/ResultsNotFound'
      *       500:
      *         description: Server error.
      *         schema:
      *           $ref: '#/definitions/ServerError'
      */
    router.route('/admin/ipv6_zones/:id')
        .patch(function (req, res) {
            checkDataAdmin(req, res);
            if (!(req.params.hasOwnProperty('id'))) {
                res.status(400).json({ 'message': 'An IPv6 CIDR must be provided!' });
                return;
            }
            let zonePromise = ipv6Zone.getZoneByIdPromise(req.params.id);
            zonePromise.then(function (zoneInDB) {
                if (zoneInDB) {
                    if ('notes' in req.body) {
                        zoneInDB['notes'].push(req.body.notes);
                    }
                    if ('status' in req.body) {
                        if (statusValues.indexOf(req.body.status) === -1) {
                            res.status(400).json({
                                'message': 'A bad status_value was provided.',
                            });
                            return;
                        }
                        zoneInDB['status'] = req.body.status;
                    }
                    zoneInDB.updated = Date.now();
                    zoneInDB.save(function (err) {
                        if (err) {
                            res.status(500).send(err);
                            return;
                        }

                        res.status(201).json({
                            message: 'IPv6 zone updated!',
                        });
                    });
                } else {
                    res.status(500).json({
                        'message': 'Error updating ' + htmlEscape(zoneInDB.zone),
                    });
                }
            }).catch(function (errorMsg) {
                res.status(500).json({
                    'message': errorMsg.toString(),
                });
            });
        });

    /**
     * @swagger
     *
     * security:
     *   - APIKeyHeader: []
     *
     * tags:
     *   - name: Admin - Retrieve the list of jobs and their status
     *     description: "[Admin-only] Retrieve the list of Python cron jobs and their current status"
     *
     * /api/v1.0/admin/job_status:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: "[Admin-only] Retrieve the list of Python cron jobs and their current status"
     *     tags: [Admin - Retrieve the list of jobs and their status]
     *     produces:
     *       - application/json
     *     responses:
     *       200:
     *         description: An individual user record for the current user.
     *         type: array
     *         items:
     *           $ref: '#/definitions/JobRecord'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     */
    router.route('/admin/job_status')
        .get(function (req, res) {
            checkAdmin(req, res);
            let jobsPromise = jobs.getAllJobsPromise();
            jobsPromise.then(function (jobStatus) {
                if (!jobStatus) {
                    res.status(500).json({
                        'message': 'Unable to retrieve job status!',
                    });
                    return;
                }
                res.status(200).json(jobStatus);
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
     *   - name: Admin - Retrieve the DNS Admins from the Marinus configuration
     *     description: Retrieve the DNS Admin configuration information from Marinus
     *   - name: Admin - Retrieve the TLS Orgs from the Marinus configuration
     *     description: Retrieve the list of TLS Organizations from the Marinus configuration
     *   - name: Admin - Retrieve the Whois Orgs from the Marinus configuration
     *     description: Retrieve the list of Whois Organizations from the Marinus configuration
     *   - name: Admin - Retrieve the complete Marinus configuration. Admins only.
     *     description: "[Admin-only] Retrieve the complete configuration information from Marinus"
     *
     * /api/v1.0/admin/config?field=DNS_Admins:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: "[Admin-only] Retrieve the list of Python cron jobs and their current status"
     *     tags: [Admin - Retrieve the DNS Admins from the Marinus configuration]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: field
     *         type: string
     *         required: true
     *         description: Retrieve the list of DNS_Admins from the configuration.
     *         example: DNS_Admins
     *         in: query
     *     responses:
     *       200:
     *         description: An array of the DNS Admins.
     *         type: array
     *         items:
     *           type: string
     *           example: "dns-admin@example.org"
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     *
     * /api/v1.0/admin/config?field=SSL_Orgs:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: "Retrieve the list of TLS Organizations from the Marinus configuration"
     *     tags: [Admin - Retrieve the TLS Orgs from the Marinus configuration]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: field
     *         type: string
     *         required: true
     *         description: Retrieve the list of SSL_Orgs from the configuration.
     *         example: SSL_Orgs
     *         in: query
     *     responses:
     *       200:
     *         description: The array of configured TLS Organizations in Marinus.
     *         type: array
     *         items:
     *           type: string
     *           example: "Acme, Inc."
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     *
     * /api/v1.0/admin/config?field=Whois_Orgs:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: "Retrieve the list of Whois Organizations from the Marinus configuration"
     *     tags: [Admin - Retrieve the Whois Orgs from the Marinus configuration]
     *     produces:
     *       - application/json
     *     parameters:
     *       - name: field
     *         type: string
     *         required: true
     *         description: Retrieve the list of Whois_Orgs from the configuration.
     *         example: Whois_Orgs
     *         in: query
     *     responses:
     *       200:
     *         description: The list of configured Whois Organizations in Marinus.
     *         type: array
     *         items:
     *           type: string
     *           example: "Acme, Inc."
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     *
     * /api/v1.0/admin/config:
     *   get:
     *   # Operation-specific security:
     *     security:
     *       - APIKeyHeader: []
     *     description: "[Admin-only] Retrieve the complete Marinus configuration"
     *     tags: [Admin - Retrieve the complete Marinus configuration. Admins only.]
     *     produces:
     *       - application/json
     *     responses:
     *       200:
     *         description: The complete configuration record.
     *         schema:
     *           $ref: '#/definitions/ConfigRecord'
     *       500:
     *         description: Server error.
     *         schema:
     *           $ref: '#/definitions/ServerError'
     */
    router.route('/admin/config')
        .get(function (req, res) {
            let configField = '';

            if (!is_valid_strings(req.query)) {
                res.status(400).json({ 'message': 'Multiple query parameters are not allowed.' });
                return;
            }

            if (req.query.hasOwnProperty("field")) {
                configField = req.query.field;
            }
            let promise;
            if (configField === "DNS_Admins") {
                promise = marinusConfig.getDNSAdminsPromise();
            } else if (configField === "SSL_Orgs") {
                promise = marinusConfig.getSSLOrgsPromise();
            } else if (configField === "Whois_Orgs") {
                promise = marinusConfig.getSSLOrgsPromise();
            } else {
                // In the future, there may be config properties that shouldn't be public
                checkAdmin(req, res);
                promise = marinusConfig.getFullConfigPromise();
            }
            promise.then(function (results) {
                if (!results) {
                    res.status(500).json({
                        'message': 'Unable to retrieve config information!',
                    });
                    return;
                }
                res.status(200).json(results[0]);
                return;
            });
        });

    return (router);
};
