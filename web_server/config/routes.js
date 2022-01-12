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
const group = require('../config/models/group');
const user = require('../config/models/user');
const errors = require('celebrate').errors;

/**
 * Checks whether the request was sent with a valid API key
 * @param {string} apiKey The apiKey value
 * @param {Object} req The Express request object
 * @param {Object} res The Express response object
 * @param {function} next The Express next function
 */
function checkApiKey(apiKey, req, res, next) {
    if (!req.session) {
        req.session = {};
    }

    let params = {
        'req': req,
        'res': res,
        'next': next,
        'apiKey': apiKey,
    };

    let uPromise = user.getUserByApiKeyPromise(params.apiKey, true);
    uPromise.then(function (userResult) {
        if (!userResult) {
            res.status(401).json({
                'message': 'You do not appear to be a current user',
            });
            return;
        }
        req.session.userid = userResult.userid;
        this.userid = userResult.userid;
        let gPromise = group.getGroupsByUserPromise(userResult.userid, true);
        gPromise.then(function (groupResult) {
            req.session.groups = [];
            req.session.isAdmin = false;

            if (!groupResult) {
                next();
                return;
            }

            for (let i = 0; i < groupResult.length; i++) {
                req.session.groups.push(groupResult[i]['name']);
                if (groupResult[i]['name'] === 'admin') {
                    req.session.isAdmin = true;
                }
            }

            next();
            return;
        }.bind(this))
            .catch(function (err) {
                res.status(500).json({
                    'message': err.toString(),
                });
            });
    }.bind(params))
        .catch(function (err) {
            res.status(500).json({
                'message': err.toString(),
            });
            res.end();
        });
}

/**
 * Checks to see if the person has a valid session
 * @param {*} req The Express request object
 * @param {*} res The Express response object
 * @param {*} next The Express next function
 */
function checkAuthentication(req, res, next) {
    let apiKey = '';
    if (typeof req.query.apiKey !== 'undefined') {
        apiKey = req.query.apiKey;
    } else if (typeof req.params.apiKey !== 'undefined') {
        apiKey = req.params.apiKey;
    } else if (typeof req.body.apiKey !== 'undefined') {
        apiKey = req.body.apiKey;
    } else {
        apiKey = req.get("x-api-key");
        if (typeof apiKey === 'undefined') {
            apiKey = '';
        }
    }

    if (req.path.indexOf('/auth/') === 0
        || req.path === '/logout'
        || req.path === '/login'
        || /^\/docs/.test(req.path)
        || req.path === '/swagger.json') {
        next();
    } else if (req.isAuthenticated()) {
        next();
    } else if (apiKey !== '') {
        checkApiKey(apiKey, req, res, next);
    } else if (req.session && req.session.localAuth) {
        next();
    } else {
        res.redirect('/login?returnPath=' + encodeURIComponent(req.originalUrl));
    }
}

/**
 * Checks to see if the person's session is authorized to visit the page.
 * @param {*} req The Express request object
 * @param {*} res The Express response object
 * @param {*} next The Express next function
 */
function checkAuthorization(req, res, next) {
    if ((req.path.indexOf('/auth/') === 0  // No login requirements
        || req.path === '/logout'
        || req.path === '/login'
        || /^\/docs/.test(req.path)
        || req.path === '/swagger.json')
        || (req.session && req.session.localAuth) // local testing. Assumed to be authorized
        || (typeof req.session.isAdmin !== 'undefined')) // The API check already handles assigning isAdmin
    {
        next();
        return;
    } else if (req.session.isAdmin == null) {
        let gPromise = group.getGroupByNamePromise('admin');
        gPromise.then(function (adminGroup) {
            req.session.isAdmin = false;
            for (let i in adminGroup.admins) {
                if (adminGroup.admins[i] === req.session.passport.user.userid) {
                    req.session.isAdmin = true;
                    next();
                    return;
                }
            }
            next();
        })
            .catch(function (err) {
                res.status(500).json({
                    'message': err.toString(),
                });
            });
    } else {
        next();
    }
}

module.exports = function (app, envConfig, passport) {
    app.use(checkAuthentication);
    app.use(checkAuthorization);

    // register route controllers
    const indexRouter = require('../routes/core')(envConfig);
    app.use('/', indexRouter);

    const adminRouter = require('../routes/admin')(envConfig);
    app.use('/api/v1.0/', adminRouter);

    const authRouter = require('../routes/auth')(envConfig, passport);
    app.use('/auth/', authRouter);

    const censysRouter = require('../routes/censys')(envConfig);
    app.use('/api/v1.0/', censysRouter);

    const cloudServicesRouter = require('../routes/cloud_services')(envConfig);
    app.use('/api/v1.0/', cloudServicesRouter);

    const ctRouter = require('../routes/ct')(envConfig);
    app.use('/api/v1.0/', ctRouter);

    const dnsRouter = require('../routes/dns')(envConfig);
    app.use('/api/v1.0/', dnsRouter);

    const graphRouter = require('../routes/graphs')(envConfig);
    app.use('/api/v1.0/', graphRouter);

    const ibloxRouter = require('../routes/iblox')(envConfig);
    app.use('/api/v1.0/', ibloxRouter);

    const ipRouter = require('../routes/ip')(envConfig);
    app.use('/api/v1.0/', ipRouter);

    const sonarRouter = require('../routes/sonar')(envConfig);
    app.use('/api/v1.0/', sonarRouter);

    const tpdRouter = require('../routes/tpds')(envConfig);
    app.use('/api/v1.0/', tpdRouter);

    const trackedScansRouter = require('../routes/tracked_scans')(envConfig);
    app.use('/api/v1.0/', trackedScansRouter);

    const utilitiesRouter = require('../routes/utilities')(envConfig);
    app.use('/api/v1.0/', utilitiesRouter);

    const virustotalRouter = require('../routes/virustotal')(envConfig);
    app.use('/api/v1.0/', virustotalRouter);

    const whoisRouter = require('../routes/whois_db')(envConfig);
    app.use('/api/v1.0/', whoisRouter);

    const zoneRouter = require('../routes/zones')(envConfig);
    app.use('/api/v1.0/', zoneRouter);

    app.use(errors());
};
