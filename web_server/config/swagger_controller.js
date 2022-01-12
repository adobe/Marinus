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

const swaggerJSDoc = require('swagger-jsdoc');

class SwaggerController {
    constructor(envConfig) {
        // swagger definition
        const swaggerDefinition = {
            info: {
                title: 'MARINUS REST API',
                version: '1.0.0',
                description: 'Marinus APIs. ' +
                    'Login to Marinus via /login or use a valid apiKey to ' +
                    'authenticate and authorise the API calls.'
            },
            host: envConfig.swagger.hostname,
            basePath: '/',
            schemes: ['https']
        };

        // options for the swagger docs
        const options = {
            // import swaggerDefinitions
            swaggerDefinition: swaggerDefinition,
            // path to the API docs
            // The following routes can be added if needed
            //    './routes/admin.js',
            //    './routes/censys.js',
            apis: [
                './routes/cloud_services.js',
                './routes/ct.js',
                './routes/dns.js',
                './routes/graphs.js',
                './routes/iblox.js',
                './routes/sonar.js',
                './routes/tpds.js',
                './routes/tracked_scans.js',
                './routes/virustotal.js',
                './routes/whois_db.js',
                './routes/zones.js',
            ],
        };

        // initialize swagger-jsdoc
        this._swaggerSpec = swaggerJSDoc(options);

        // Errors
        this._swaggerSpec.definitions.BadInputError = require("./swagger_defs/error_400.json");
        this._swaggerSpec.definitions.ResultsNotFound = require("./swagger_defs/error_404.json");
        this._swaggerSpec.definitions.ServerError = require("./swagger_defs/error_500.json");

        // Valid responses
        this._swaggerSpec.definitions.CountResponse = require("./swagger_defs/countResponse.json");

        // Common defintions
        this._swaggerSpec.securityDefinitions.APIKeyHeader = require("./swagger_defs/APIKeyHeader.json");
    }

    setup(app, express) {
        app.use('/docs/media', express.static('node_modules/swagger-ui-dist'));
        app.use('/docs/', express.static('views/swagger/'));

        app.get('/swagger.json', function (req, res) {
            res.setHeader('Content-Type', 'application/json');
            res.send(this._swaggerSpec);
        }.bind(this));
    }
}

module.exports = SwaggerController;
