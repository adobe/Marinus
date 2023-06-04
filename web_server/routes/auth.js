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
const group = require('../config/models/group');
const user = require('../config/models/user');

module.exports = function (envConfig, passport) {
    router.route('/logout')
        .get(function (req, res) {
            if (req.session) {
                req.session.destroy();
            }
            res.writeHead(302, {
                'Location': '/logout',
            });
            res.end();
        });

    router.route('/login')
        /**
         * When in production mode, the "Sign In" button does a GET request to /auth/login.
         * The GET request includes a returnPath parameter which is saved in the session
         * in order to return the user to their original page after authentication is complete.
         */
        .get(function (req, res) {
            req.session.returnPath = req.query.returnPath;
            if (envConfig.state === 'development') {
                res.writeHead(302, {
                    'Location': '/login'
                });
            } else {
                res.writeHead(302, {
                    'Location': envConfig.sso_url,
                });
            }
            res.end();
        })
        /**
         * When in development mode, the "Sign In" button does a POST request with the username
         * and password to /auth/login. Therefore, the code assumes that a POST is an attempt to
         * authenticate against the local credentials set in the config parameters. In local mode,
         * the default user is given admin privileges. This code sets up the session in the same
         * manner as the passport workflow for consistency.
         */
        .post(function (req, res) {
            /*
             * This section only applies when run in development mode.
             */
            if (envConfig.state === 'production') {
                res.status(500).json({
                    'message': 'Not supported in production.',
                });
                return;
            }
            if (req.body.username === 'marinus' &&
                req.body.password === envConfig.localAdminPassword) {
                let sess = req.session;
                sess.passport = {
                    'user': {
                        'firstName': 'Administrator',
                        'userid': 'marinus',
                    },
                };
                sess.localAuth = true;
                sess.groups = ['admin'];
                if (req.body.returnPath && req.body.returnPath.length > 0) {
                    res.writeHead(302, {
                        'Location': '/' + req.body.returnPath.slice(1),
                    });
                } else {
                    res.writeHead(302, {
                        'Location': '/',
                    });
                }
                res.end();
                return;
            } else {
                res.writeHead(302, {
                    'Location': '/logout',
                });
            }
            res.end();
        });

    /**
     * Once the user is confirmed by the SSO provider, the SSO provider returns the user to this URL.
     * This code validates that the user that was authenticated by the SSO provider is also known to
     * Marinus. If the user is confirmed, then this code will fetch the user's group permissions
     * and store them in the session state. Lastly, it will return the user to the returnPath that was
     * saved during the GET request to /auth/login, assuming that one was provided.
     */
    router.route('/okta')
        .post(passport.authenticate('saml', {
            failureRedirect: '/login',
            failureFlash: true,
        }),
            function (req, res) {
                let promise = user.getUserIdPromise(req.session.passport.user.userid, true);
                promise.then(function (userData) {
                    if (!userData) {
                        res.redirect('/logout');
                    }
                    let groupPromise = group.getGroupsByUserPromise(req.session.passport.user.userid);
                    groupPromise.then(function (data) {
                        if (!data) {
                            req.session.groups = [];
                        } else {
                            req.session.groups = [];
                            for (let i = 0; i < data.length; i++) {
                                req.session.groups.push(data[i]['name']);
                            }
                            if (req.session.returnPath) {
                                res.redirect('/' + decodeURIComponent(req.session.returnPath).slice(1));
                            } else {
                                res.redirect('/');
                            }
                        }
                    });
                }.bind(this));
            });

    return (router);
};
