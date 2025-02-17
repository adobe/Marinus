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

const mongoose = require('mongoose');
const fs = require('fs');

module.exports = function (envConfig) {
    const db_options = {};

    if (envConfig.hasOwnProperty('mongodbSSLCA') && envConfig.mongodbSSLCA !== "") {
        db_options['tlsCAFile'] = envConfig.mongodbSSLCA;
    }

    // connect to the database
    mongoose.connect(envConfig.database, db_options);

    // Use a better Promise provider
    mongoose.Promise = global.Promise;

    // Preparing for Mongoose 7.0
    mongoose.set('strictQuery', false);

    // Acknowledge a successful connection to the console
    mongoose.connection.on('connected', function () {
        console.log('Mongoose default connection open');
    });

    // Event handler for when the connection throws an error
    mongoose.connection.on('error', function (err) {
        console.log('Mongoose default connection error: ' + err);
    });

    // Event handler for when the connection is disconnected
    mongoose.connection.on('disconnected', function () {
        console.log('Mongoose default connection disconnected');
    });

    // If the Node process ends, close the Mongoose connection
    process.on('SIGINT', function () {
        mongoose.connection.close().then(function () {
            console.log('Mongoose default connection disconnected through app termination');
            process.exit(0);
        });
    });
};
