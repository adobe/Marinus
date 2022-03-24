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

// Express config
const express = require('express');
const cookieParser = require('cookie-parser');
const expressSession = require('express-session');
const MongoDBStore = require('connect-mongodb-session')(expressSession);
const path = require('path');
const mlogger = require('morgan');
const sLogger = require("splunk-logging").Logger;
// var favicon = require('serve-favicon');
const bodyParser = require('body-parser');
const fs = require('fs');
const assert = require('assert');

function setUpLogger(app, envConfig) {

  if (envConfig.hasOwnProperty('splunk_token')) {
    let splunk_config = {
      token: envConfig.splunk_token,
      url: envConfig.splunk_url
    };

    var splunk_logger = new sLogger(splunk_config);

    splunk_logger.requestOptions.strictSSL = true;

    app.set('trust proxy', true);
    app.use(mlogger("combined", {
      "format": "combined",
      "stream": {
        write: function (message) {
          var payload = {
            message,
            metadata: {
              source: envConfig.splunk_index,
              sourcetype: 'marinus-ui'
            }
          };
          splunk_logger.send(payload);
        }
      }
    }));
  } else {
    app.use(mlogger('combined'));
  }
}

module.exports = function (app, envConfig) {
  const passport = require('passport');
  require('./passport_conf')(passport, envConfig);

  // view engine setup
  app.set('views', path.join(envConfig.rootPath, 'views'));
  app.set('view engine', 'ejs');

  // app.use(favicon(envConfig.rootPath + '/public/images/satyrusmarinus-small.ico'));
  app.use(bodyParser.json());
  app.use(bodyParser.urlencoded({ extended: false }));

  // Set up sessions
  app.use(cookieParser());

  if (envConfig.state === 'production') {

    setUpLogger(app, envConfig);

    const store = new MongoDBStore(
      {
        uri: envConfig.database,
        collection: 'sessions',
      });

    store.on('error', function (error) {
      assert.ifError(error);
      assert.ok(false);
    });

    app.use(expressSession({
      secret: envConfig.cookieSecret,
      cookie: {
        secure: true, sameSite: "None",
        maxAge: 1000 * 60 * 60 * 24 * 1
      },
      store: store,
      resave: false,
      saveUninitialized: false
    }));
  } else {
    /**
     * Begin development mode section
     */

    app.use(mlogger('combined'));

    app.use(expressSession({
      secret: envConfig.cookieSecret,
      cookie: {
        secure: true, sameSite: "None",
        maxAge: 1000 * 60 * 60 * 24 * 1
      },
      resave: false,
      saveUninitialized: false
    }));
  }

  // SSO initialization
  app.use(passport.initialize());
  app.use(passport.session());

  app.locals.pretty = envConfig.pretty;

  // Tell Express to serve static objects from the /public/ dir in /
  app.use('/', express.static(path.join(envConfig.rootPath, 'public')));

  app.use('/javascripts/jquery', express.static(path.join(envConfig.rootPath, 'node_modules/jquery/dist/')));
  app.use('/javascripts/bootstrap', express.static(path.join(envConfig.rootPath, 'node_modules/bootstrap/dist/js/')));
  app.use('/stylesheets/bootstrap', express.static(path.join(envConfig.rootPath, 'node_modules/bootstrap/dist/css/')));
  app.use('/stylesheets/octicons', express.static(path.join(envConfig.rootPath, 'node_modules/octicons/build/')));
  app.use('/javascripts/d3', express.static(path.join(envConfig.rootPath, 'node_modules/d3/dist')));
  app.use('/javascripts/d3-scale', express.static(path.join(envConfig.rootPath, 'node_modules/d3-scale-chromatic/dist')));
  app.use('/javascripts/URI.min.js', express.static(path.join(envConfig.rootPath, 'node_modules/urijs/src/URI.min.js')));

  // Necessary for cert_graph
  app.use("/bootstrap/dist", express.static(path.join(envConfig.rootPath, '/node_modules/bootstrap/dist')));
  app.use("/bootstrap/less", express.static(path.join(envConfig.rootPath, '/node_modules/bootstrap/less')));

  return (passport);
};
