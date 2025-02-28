
/**
 * Copyright 2025 Adobe. All rights reserved.
 * This file is licensed to you under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under
 * the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR REPRESENTATIONS
 * OF ANY KIND, either express or implied. See the License for the specific language
 * governing permissions and limitations under the License.
 */

import express from 'express';
var app = express();

import debug from 'debug'
const logger = debug('ip_app:server');

// import { createSecureServer } from 'node:http2';
import { readFileSync } from 'node:fs';

const options = {
    key: readFileSync('config/keys/server.key'),
    cert: readFileSync('config/keys/server.crt')
};

let https;
try {
    https = await import('node:https');
} catch (err) {
    console.error('https support is disabled!');
}

import * as http from 'http';

//Swagger Controller
import swaggerController from './config/swagger_controller.js';

/**
 *  This determines whether Marinus is in production or development mode
 */
var env = process.env.NODE_ENV || 'production';

/**
 *  Initialize configuration parameters
 */
import envConfigurations from './config/env.js';
var envConfig = envConfigurations[env];

/**
 * New Relic support.
 */
if (envConfig.state === 'production' && envConfig.hasOwnProperty("new_relic_enabled") && envConfig.new_relic_enabled) {
    await import('newrelic');
}

// Express configuration returns the passport object
import config from './config/config.js';
var passport = config(app, envConfig);

// Database
import database from './config/database.js';
database(envConfig);

// Routes
import routes from './config/routes.js';
routes(app, envConfig, passport);

// Swagger
const controller = new swaggerController(envConfig);
controller.setup(app, express);

/**
 * Security
 */
app.disable("x-powered-by");

/**
 * Create HTTPS server.
 * Listens on the provided port, on all network interfaces.
 */

var server;
if (envConfig === 'production') {
    server = https.createServer(options, app).listen(envConfig.port);
} else {
    server = http.createServer(app).listen(envConfig.port);
}

// HTTP/2 is not yet supported
// server = createSecureServer(tls_options, app).listen(envConfig.port);

/**
 * Register event listeners to confirm a successful setup and catch errors.
 */
server.on('error', onError);
server.on('listening', onListening);

/**
 * Event listener for HTTP server "error" event.
 */

function onError(error) {
    if (error.syscall !== 'listen') {
        throw error;
    }

    var bind = typeof port === 'string' ? 'Pipe ' + envConfig.port : 'Port ' + envConfig.port;

    // handle specific listen errors with friendly messages
    switch (error.code) {
        case 'EACCES':
            console.error(bind + ' requires elevated privileges');
            process.exit(1);
            break;
        case 'EADDRINUSE':
            console.error(bind + ' is already in use');
            process.exit(1);
            break;
        default:
            throw error;
    }
}

/**
 * Event listener for HTTP server "listening" event.
 */

function onListening() {
    var addr = server.address();
    var bind = typeof addr === 'string' ? 'pipe ' + addr : 'port ' + addr.port;
    //debug('Listening on ' + bind);
    console.log('Listening on: ' + bind)
}
