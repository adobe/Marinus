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

/**
 * Sets security headers on the response object
 * @param {Object} res The Express response objet
 */
function setHeaders(res) {
    res.set({
        'X-Frame-Options': 'deny',
        'X-Content-Type-Options': 'nosniff',
        'Content-Security-Policy': 'default-src \'none\'; script-src \'self\' use.typekit.net; connect-src \'self\' performance.typekit.net; img-src \'self\' data: p.typekit.net; style-src \'self\' \'unsafe-inline\' use.typekit.net; font-src \'self\' data: fonts.typekit.net use.typekit.net;',
        'X-XSS-Protection': '1; mode=block',
        'Strict-Transport-Security': 'max-age=16070400; includeSubDomains'
    });
}

/**
 * Extrapolates the session parameters associated with the user.
 * @param {Object} req The Express request object.
 * @return {Object} A dictionary containing the username and admin privileges.
 */
function getSessionParams(req) {
    let params = { 'username': null, 'isAdmin': false, 'isDataAdmin': false };
    if (!req.session) {
        return (params);
    }
    if (req.session.passport && req.session.passport.user.firstName) {
        params['username'] = req.session.passport.user.firstName;
    }

    if (req.session.groups && (req.session.groups.indexOf('admin') !== -1)) {
        params['isAdmin'] = true;
    }

    if (req.session.groups &&
        ((req.session.groups.indexOf('admin') !== -1) ||
            (req.session.groups.indexOf('data_admin') !== -1))) {
        params['isDataAdmin'] = true;
    }

    return (params);
}

module.exports = function (envConfig) {
    router.get('/', function (req, res) {
        setHeaders(res);
        let params = getSessionParams(req);
        res.render('pages/index', params);
    });

    router.get('/health', function (req, res) {
        res.status(200).json({ 'status': 'ok' });
        return
    });

    router.get('/cert', function (req, res) {
        setHeaders(res);
        let params = getSessionParams(req);
        res.render('pages/cert', params);
    });

    router.get('/cert_graph', function (req, res) {
        setHeaders(res);
        let params = getSessionParams(req);
        res.render('pages/cert_graph', params);
    });

    router.get('/domain', function (req, res) {
        setHeaders(res);
        let params = getSessionParams(req);
        res.render('pages/domain', params);
    });

    router.get('/graph', function (req, res) {
        setHeaders(res);
        let params = getSessionParams(req);
        res.render('pages/graph', params);
    });

    router.get('/help', function (req, res) {
        setHeaders(res);
        let params = getSessionParams(req);
        res.render('pages/help', params);
    });

    router.get('/ip', function (req, res) {
        setHeaders(res);
        let params = getSessionParams(req);
        res.render('pages/ip', params);
    });

    router.get('/ipv6', function (req, res) {
        setHeaders(res);
        let params = getSessionParams(req);
        res.render('pages/ipv6', params);
    });

    router.get('/ip_range', function (req, res) {
        setHeaders(res);
        let params = getSessionParams(req);
        res.render('pages/ip_range', params);
    });

    router.get('/login', function (req, res) {
        setHeaders(res);
        let params = getSessionParams(req);
        if (req.query.returnPath && req.query.returnPath.length > 0) {
            params['redirect'] = req.query.returnPath;
        } else {
            params['redirect'] = '/utilities';
        }
        params['state'] = envConfig.state;
        res.render('pages/login', params);
    });

    router.get('/logout', function (req, res) {
        setHeaders(res);
        let params = getSessionParams(req);
        res.render('pages/logout', params);
    });

    router.get('/zone', function (req, res) {
        setHeaders(res);
        let params = getSessionParams(req);
        res.render('pages/zone', params);
    });

    router.get('/admin/jobs', function (req, res) {
        setHeaders(res);
        let params = getSessionParams(req);
        res.render('pages/admin/jobs', params);
    });

    router.get('/admin/stats', function (req, res) {
        setHeaders(res);
        let params = getSessionParams(req);
        res.render('pages/admin/stats', params);
    });

    router.get('/admin/user', function (req, res) {
        setHeaders(res);
        let params = getSessionParams(req);
        res.render('pages/admin/user', params);
    });

    router.get('/admin/user_config', function (req, res) {
        setHeaders(res);
        let params = getSessionParams(req);
        res.render('pages/admin/user_config', params);
    });

    router.get('/admin/data_config', function (req, res) {
        setHeaders(res);
        let params = getSessionParams(req);
        res.render('pages/admin/data_config', params);
    });

    router.get('/meta/tpd_list', function (req, res) {
        setHeaders(res);
        let params = getSessionParams(req);
        res.render('pages/meta/tpd_list', params);
    });

    router.get('/meta/tpd_list_detail', function (req, res) {
        setHeaders(res);
        let params = getSessionParams(req);
        res.render('pages/meta/tpd_list_detail', params);
    });

    router.get('/meta/zone_list', function (req, res) {
        setHeaders(res);
        let params = getSessionParams(req);
        res.render('pages/meta/zone_list', params);
    });

    router.get('/meta/headers', function (req, res) {
        setHeaders(res);
        let params = getSessionParams(req);
        res.render('pages/meta/headers', params);
    });

    router.get('/meta/header_details', function (req, res) {
        setHeaders(res);
        let params = getSessionParams(req);
        res.render('pages/meta/header_details', params);
    });

    router.get('/meta/ip_zone_list', function (req, res) {
        setHeaders(res);
        let params = getSessionParams(req);
        res.render('pages/meta/ip_zone_list', params);
    });

    router.get('/meta/ipv6_zone_list', function (req, res) {
        setHeaders(res);
        let params = getSessionParams(req);
        res.render('pages/meta/ipv6_zone_list', params);
    });

    router.get('/meta/port_list', function (req, res) {
        setHeaders(res);
        let params = getSessionParams(req);
        res.render('pages/meta/port_list', params);
    });

    router.get('/meta/whois_dns_list', function (req, res) {
        setHeaders(res);
        let params = getSessionParams(req);
        res.render('pages/meta/whois_dns_list', params);
    });

    router.get('/reports/amazon', function (req, res) {
        setHeaders(res);
        let params = getSessionParams(req);
        res.render('pages/reports/amazon', params);
    });

    router.get('/reports/scan_corp_certs', function (req, res) {
        setHeaders(res);
        let params = getSessionParams(req);
        res.render('pages/reports/scan_corp_certs', params);
    });

    router.get('/reports/scan_algorithm_ssl', function (req, res) {
        setHeaders(res);
        let params = getSessionParams(req);
        res.render('pages/reports/scan_algorithm_ssl', params);
    });

    router.get('/reports/hosts_by_cas', function (req, res) {
        setHeaders(res);
        let params = getSessionParams(req);
        res.render('pages/reports/hosts_by_cas', params);
    });

    router.get('/reports/scan_expired_ssl', function (req, res) {
        setHeaders(res);
        let params = getSessionParams(req);
        res.render('pages/reports/scan_expired_ssl', params);
    });

    router.get('/reports/ct_corp_ssl', function (req, res) {
        setHeaders(res);
        let params = getSessionParams(req);
        res.render('pages/reports/ct_corp_ssl', params);
    });

    router.get('/reports/ct_issuers', function (req, res) {
        setHeaders(res);
        let params = getSessionParams(req);
        res.render('pages/reports/ct_issuers', params);
    });

    router.get('/reports/dead_dns', function (req, res) {
        setHeaders(res);
        let params = getSessionParams(req);
        res.render('pages/reports/dead_dns', params);
    });

    router.get('/reports/display_cert', function (req, res) {
        setHeaders(res);
        let params = getSessionParams(req);
        res.render('pages/reports/display_cert', params);
    });

    router.get('/reports/email', function (req, res) {
        setHeaders(res);
        let params = getSessionParams(req);
        res.render('pages/reports/email', params);
    });

    router.get('/reports/virustotal_threats', function (req, res) {
        setHeaders(res);
        let params = getSessionParams(req);
        res.render('pages/reports/virustotal_threats', params);
    });

    return (router);
};
