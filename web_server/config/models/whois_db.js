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

const whoisSchema = new Schema({
    domain: String,
    domain_name: Schema.Types.Mixed,
    creation_date: [Date],
    updated: Number,
    updated_date: [Date],
    expiration_date: Number,
    status: [String],
    dnssec: String,
    name: String,
    org: String,
    address: String,
    city: String,
    state: String,
    country: String,
    zipcode: String,
    registrar: String,
    referral_url: String,
    whois_server: Schema.Types.Mixed,
    emails: [String],
    name_servers: [String],
    text: String,
}, { collection: 'whois' });


const whoisModel = mongoose.model('whoisModel', whoisSchema);

module.exports = {
    WhoisModel: whoisModel,
    getRecordByZonePromise: function (zone) {
        return whoisModel.findOne({
            'zone': zone,
        }).exec();
    },
    getWhoisDNSServerRecords: function (server, count) {
        let reServer = new RegExp('.*' + server + '.*', 'i');
        let promise;
        if (count) {
            promise = whoisModel.countDocuments({
                'name_servers': reServer,
            }).exec();
        } else {
            promise = whoisModel.find({ 'name_servers': reServer }).exec();
        }
        return promise;
    },
    getWhoisDNSServerNullRecords: function (count) {
        let promise;
        if (count) {
            promise = whoisModel.countDocuments({
                '$or': [{ 'name_servers': { '$exists': false } },
                { 'name_servers': [] },
                { 'name_servers': null }],
            }).exec();
        } else {
            promise = whoisModel.find({
                '$or': [{ 'name_servers': { '$exists': false } },
                { 'name_servers': [] },
                { 'name_servers': null }],
            }).exec();
        }
        return promise;
    },
    getWhoisDistinctDNSServerRecords: function () {
        return (whoisModel.distinct('name_servers').exec());
    },
    getWhoisDistinctDNSServerGroupRecords: function () {
        return (whoisModel.distinct('name_server_groups').exec());
    },
    getWhoisDNSSECRecords: function (type, count) {
        let query;
        if (type === 'signed') {
            query = 'signedDelegation';
        } else if (type === 'unsigned') {
            query = new RegExp('unsigned', 'i');
        } else if (type === 'inactive') {
            query = 'Inactive';
        }
        let promise;
        if (count) {
            promise = whoisModel.countDocuments({ 'dnssec': query }).exec();
        } else {
            promise = whoisModel.find({ 'dnssec': query }).exec();
        }
        return promise;
    },
    getWhoisDNSSECOtherRecords: function (count) {
        let promise;
        let query = new RegExp('^(n|no)$', 'i');
        if (count) {
            promise = whoisModel.countDocuments({
                '$or': [{ 'dnssec': { '$exists': false } },
                { 'dnssec': false },
                { 'dnssec': query },
                { 'dnssec': null }],
            }).exec();
        } else {
            promise = whoisModel.find({
                '$or': [{ 'dnssec': { '$exists': false } },
                { 'dnssec': false },
                { 'dnssec': query },
                { 'dnssec': null }],
            }).exec();
        }
        return promise;
    },
    getWhoisEmailRecords: function (email, count) {
        let promise;
        if (count) {
            promise = whoisModel.countDocuments({ 'emails': email }).exec();
        } else {
            promise = whoisModel.find({ 'emails': email }).exec();
        }
        return promise;
    },
    getWhoisEmailNullRecords: function (count) {
        let promise;
        if (count) {
            promise = whoisModel.countDocuments({
                '$or': [{ 'emails': { '$eq': null } },
                { 'emails': { '$eq': [] } },
                { 'emails': { '$exists': false } }],
            }).exec();
        } else {
            promise = whoisModel.find({
                '$or': [{ 'emails': { '$eq': null } },
                { 'emails': { '$eq': [] } },
                { 'emails': { '$exists': false } }],
            }).exec();
        }
        return promise;
    },
    getWhoisRecordCount: function () {
        return whoisModel.countDocuments({}).exec();
    },
};
