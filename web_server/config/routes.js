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

//import express from 'express';
import { group } from '../config/models/group.js';
import { user } from '../config/models/user.js';
import { errors } from 'celebrate';

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

import coreRouter from '../routes/core.js';
import adminRouter from '../routes/admin.js';
import authRouter from '../routes/auth.js';
import censysRouter from '../routes/censys.js';
import cloudServicesRouter from '../routes/cloud_services.js';
import ctRouter from '../routes/ct.js';
import dnsRouter from '../routes/dns.js';
import graphsRouter from '../routes/graphs.js';
import ibloxRouter from '../routes/iblox.js';
import ipRouter from '../routes/ip.js';
import sonarRouter from '../routes/sonar.js';
import tpdRouter from '../routes/tpds.js';
import trackedScansRouter from '../routes/tracked_scans.js';
import utilitiesRouter from '../routes/utilities.js';
import virustotalRouter from '../routes/virustotal.js';
import whoisDBRouter from '../routes/whois_db.js';
import zonesRouter from '../routes/zones.js';

export default function routes(app, envConfig, passport) {
    app.use(checkAuthentication);
    app.use(checkAuthorization);

    // register route controllers
    const index_router = coreRouter(envConfig);
    app.use('/', index_router);

    const admin_router = adminRouter(envConfig);
    app.use('/api/v1.0/', admin_router);

    const auth_router = authRouter(envConfig, passport);
    app.use('/auth/', auth_router);

    const censys_router = censysRouter(envConfig);
    app.use('/api/v1.0/', censys_router);

    const cloud_services_router = cloudServicesRouter(envConfig);
    app.use('/api/v1.0/', cloud_services_router);

    const ct_router = ctRouter(envConfig);
    app.use('/api/v1.0/', ct_router);

    const dns_router = dnsRouter(envConfig);
    app.use('/api/v1.0/', dns_router);

    const graphs_router = graphsRouter(envConfig);
    app.use('/api/v1.0/', graphs_router);

    const iblox_router = ibloxRouter(envConfig);
    app.use('/api/v1.0/', iblox_router);

    const ip_router = ipRouter(envConfig);
    app.use('/api/v1.0/', ip_router);

    const sonar_router = sonarRouter(envConfig);
    app.use('/api/v1.0/', sonar_router);

    const tpd_router = tpdRouter(envConfig);
    app.use('/api/v1.0/', tpd_router);

    const tracked_scans_router = trackedScansRouter(envConfig);
    app.use('/api/v1.0/', tracked_scans_router);

    const utilities_router = utilitiesRouter(envConfig);
    app.use('/api/v1.0/', utilities_router);

    const virustotal_router = virustotalRouter(envConfig);
    app.use('/api/v1.0/', virustotal_router);

    const whois_router = whoisDBRouter(envConfig);
    app.use('/api/v1.0/', whois_router);

    const zones_router = zonesRouter(envConfig);
    app.use('/api/v1.0/', zones_router);

    app.use(errors());
};
