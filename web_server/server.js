
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

var express = require('express');
var app = express();
var debug = require('debug')('ip_app:server');

const fs = require('fs');

const options = {
    key: fs.readFileSync('config/keys/server.key'),
    cert: fs.readFileSync('config/keys/server.crt')
};


//var http = require('http');
const https = require('https');

//Swagger Controller
const swaggerController = require('./config/swagger_controller');

// Would like to support HTTP2 but can't due to: https://github.com/molnarg/node-http2/issues/100
// const http2 = require('http2');

/**
 *  This determines whether Marinus is in production or development mode
 */
var env = process.env.NODE_ENV || 'production';
var envConfig = require('./config/env')[env];


/**
 * New Relic support.
 */
if (envConfig.state === 'production' && envConfig.hasOwnProperty("new_relic_enabled") && envConfig.new_relic_enabled) {
    require('newrelic');
}

// Express configuration
var passport = require('./config/config')(app, envConfig);

// Database
require('./config/database')(envConfig);

// Routes
require('./config/routes')(app, envConfig, passport);

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

//var server = http.createServer(app);
//var server = http2.createServer(options, app).listen(envConfig.port);
var server = https.createServer(options, app).listen(envConfig.port);

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
