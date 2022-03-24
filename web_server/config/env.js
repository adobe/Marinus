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

const path = require('path');
const rootPath = path.normalize(__dirname + '/../'); // normalizes to base path
const port = normalizePort(process.env.PORT) || 3005;

/**
 * Normalize a port into a number, string, or false.
 * @param {String} val The port as a string
 * @return {*} The port as a number, string, or false.
 */
function normalizePort(val) {
  let port = parseInt(val, 10);

  if (isNaN(port)) {
    // named pipe
    return val;
  }

  if (port >= 0) {
    // port number
    return port;
  }

  return false;
}


module.exports = {
  development: {
    version: '1.0.1',
    build: '1331',
    state: 'development',
    rootPath: rootPath,
    database: 'mongodb://DEV_DATABASE_USERNAME:DEV_DATABASE_PASSWORD@localhost:27017/DOMAINS',
    port: port,
    ip: '127.0.0.1',
    cookieSecret: 'DEV_COOKIE_SECRET',
    localAdminPassword: 'LOCAL_ADMIN_PASSWORD',
    pretty: true,
    sso_url: 'SSO_URL',
    swagger: {
      'hostname': process.env.DEVELOPMENT_HOST_NAME || '127.0.0.1:' + port
    },
    internalDomain: 'INTERNAL_DOMAIN_NAME',
    api_key_length: 32,
    zgrabVersion: 2,
  },
  production: {
    version: '1.0.1',
    build: '1331',
    state: 'production',
    rootPath: rootPath,
    database: 'mongodb://PROD_DATABASE_USERNAME:PROD_DATABASE_PASSWORD@localhost:27017/DOMAINS',
    port: port,
    ip: '127.0.0.1',
    cookieSecret: 'PROD_COOKIE_SECRET',
    pretty: false,
    sso_url: 'SSO_URL',
    swagger: {
      'hostname': process.env.PRODUCTION_HOST_NAME || '127.0.0.1'
    },
    internalDomain: 'INTERNAL_DOMAIN_NAME',
    api_key_length: 32,
    splunk_url: 'SPLUNK_PROD_URL',
    splunk_token: 'SPLUNK_PROD_TOKEN',
    splunk_index: 'SPLUNK_INDEX',
    new_relic_enabled: true,
    mongodbSSLCA: '',
    zgrabVersion: 2,
  }
}
