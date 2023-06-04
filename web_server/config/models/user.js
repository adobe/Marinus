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
const Schema = mongoose.Schema;

// user model
const userSchema = new Schema({
    userid: String,
    creation_date: Date,
    updated: Date,
    apiKey: String,
    status: String,
}, {
    collection: 'users',
});

const userModel = mongoose.model('userModel', userSchema);

module.exports = {
    UserModel: userModel,
    getUserIdPromise: function (userid, onlyIsActive) {
        if (typeof onlyIsActive === 'undefined') {
            onlyIsActive = true;
        }
        let promise;
        if (onlyIsActive) {
            promise = userModel.findOne({
                'userid': userid,
                'status': 'active',
            }).exec();
        } else {
            promise = userModel.findOne({
                'userid': userid,
            }).exec();
        }
        return promise;
    },
    getUserByApiKeyPromise: function (apiKey, isActive) {
        if (typeof isActive === 'undefined') {
            isActive = true;
        }
        let promise;
        if (isActive) {
            promise = userModel.findOne({
                'apiKey': apiKey,
                'status': 'active',
            }).exec();
        } else {
            promise = userModel.findOne({
                'userid': userid,
            }).exec();
        }
        return promise;
    },
    getUserListPromise: function (isActive) {
        if (typeof isActive === 'undefined') {
            isActive = true;
        }
        let promise;
        if (isActive) {
            promise = userModel.find({
                'status': 'active',
            }).exec();
        } else {
            promise = userModel.find({}, { 'apiKey': 0 }).exec();
        }
        return promise;
    },
};
