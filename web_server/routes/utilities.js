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
const dns = require('dns');
const htmlEscape = require('secure-filters').html;


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
  router.route('/utilities/whois')
    /**
     * Do a local Whois loookup.
     */
    .get(function (req, res) {
      res.setHeader('Content-Type', 'application/json');

      if (!is_valid_strings(req.query)) {
        res.status(400).json({ 'message': 'Multiple query parameters are not allowed.' });
        return;
      }

      let domain = req.query.domain;
      if (!domain) {
        res.status(400).send("{'Error': 'Please send a domain!'}");
        return;
      }

      const whois = require('whois');
      let whoisObject = {
        'server': '', // this can be a string ('host:port') or an object with host and port as its keys; leaving it empty makes lookup rely on servers.json
        'follow': 2, // number of times to follow redirects
        'timeout': 0, // socket timeout, excluding this doesn't override any default timeout value
        'verbose': false, // setting this to true returns an array of responses from all servers
      };

      whois.lookup(domain, whoisObject, function (err, data) {
        if (!err) {
          let myEscapedJSONString = data.replace(/[\\]/g, '\\\\')
            .replace(/[\"]/g, '\\\"')
            .replace(/[\/]/g, '\\/')
            .replace(/[\b]/g, '\\b')
            .replace(/[\f]/g, '\\f')
            .replace(/[\n]/g, '\\n')
            .replace(/[\r]/g, '\\r')
            .replace(/[\t]/g, '\\t');
          res.status(200).json({ 'result': myEscapedJSONString });
        } else {
          res.status(500).send(err);
        }
      });
    });

  router.route('/utilities/nslookup')
    /**
     * Do a local nslookup.
     * This should be upgraded to use Google DNS over HTTPS.
     */
    .get(function (req, res) {

      if (!is_valid_strings(req.query)) {
        res.status(400).json({ 'message': 'Multiple query parameters are not allowed.' });
        return;
      }

      let domain = req.query.target;
      if (!domain) {
        res.status(400).json({ 'Error': 'Please send a target!' });
        return;
      }

      if (req.query.hasOwnProperty('dnsServer')
        && req.query.dnsServer.length > 0) {
        let dnsServer = req.query.dnsServer;
        dns.setServers([dnsServer]);
      }

      if (req.query.hasOwnProperty('dnsType') && req.query.dnsType.length > 0) {
        dns.resolve(domain, recordType, function (err, hostnames) {
          if (err && err.code === dns.NOTFOUND) {
            res.status(404).json({ 'Error': htmlEscape(err) });
            return;
          } else if (err) {
            res.status(500).json({ 'Error': htmlEscape(err) });
            return;
          }
          res.status(200).json({ 'results': hostnames });
          return;
        }.bind(res));
      } else {
        let ipv4 = /^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$/;
        let ipv6 = /^[0-9a-zA-z\:]+$/;
        if (domain.match(ipv4) || domain.match(ipv6)) {
          try {
            dns.reverse(domain, function (err, hostnames) {
              if (err && err.code === dns.NOTFOUND) {
                res.status(404).json({ 'Error': htmlEscape(err) });
                return;
              } else if (err) {
                res.status(500).json({ 'Error': htmlEscape(err) });
                return;
              }
              res.status(200).json({ 'domains': hostnames });
              return;
            }.bind(res));
          } catch (err) {
            res.status(500).json({ 'Error': htmlEscape(err.message) });
            return;
          }
        } else {
          dns.lookup(domain, { all: true }, function (err, addresses) {
            if (err) {
              res.status(500).json({ 'Error': htmlEscape(err) });
              return;
            }
            res.status(200).json({ 'ips': addresses });
            return;
          }.bind(res));
        }
      }
    });

  return (router);
};
