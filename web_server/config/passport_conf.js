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

/**
 * The SAML SSO configuration for Passport.
 */

module.exports = function (passport, envConfig) {
   const SamlStrategy = require('passport-saml').Strategy;
   const user = require('../config/models/user');

   passport.serializeUser(function (user, done) {
      done(null, user);
   });

   passport.deserializeUser(function (user, done) {
      done(null, user);
   });

   const fs = require('fs');
   fs.readFile('config/keys/sso.cert', function (err, data) {
      passport.use(new SamlStrategy(
         {
            path: '/auth/okta',
            entryPoint: envConfig.sso_url,
            cert: data.toString(),
            issuer: 'passport-saml',
         },
         function (profile, done) {
            let promise = user.getUserIdPromise(profile.userid);
            promise.then(function (userData) {
               if (!userData) {
                  return done(null);
               }
               return done(null, {
                  userid: profile.userid,
                  email: profile.email,
                  firstName: profile.firstName,
                  lastName: profile.lastName,
               });
            });
         }
      ));
   }.bind(passport));
};
