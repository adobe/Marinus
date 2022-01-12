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

const virustotalSchema = new Schema({
    'zone': String,
    'created': Date,
    'whois': String,
    'whois_timestamp': Number,
    'Alexa rank': Number,
    'Alexa category': String,
    'Alexa domain info': String,
    'categories': [String],
    'Forcepoint ThreatSeeker category': String,
    'domain_siblings': [String],
    'Webutation domain info': {
        'Safety score': Number,
        'Adult content': String,
        'Verdict': String,
    },
    'WOT domain info': {
        'Vendor reliability': String,
        'Child safety': String,
        'Trustworthiness': String,
        'Privacy': String,
    },
    'detected_referrer_samples': [
        {
            'positives': Number,
            'total': Number,
            'sha256': String,
        }],
    'undetected_referrer_samples': [
        {
            'positives': Number,
            'total': Number,
            'sha256': String,
        }],
    'detected_downloaded_samples': [
        {
            'date': Date,
            'positives': Number,
            'total': Number,
            'sha256': String,
        }],
    'undetected_downloaded_samples': [
        {
            'date': Date,
            'positives': Number,
            'total': Number,
            'sha256': String,
        }],
    'detected_communicating_samples': [
        {
            'date': Date,
            'positives': Number,
            'total': Number,
            'sha256': String,
        }],
    'undetected_communicating_samples': [{
        'date': Date,
        'positives': Number,
        'total': Number,
        'sha256': String,
    }],
    'detected_urls': [
        {
            'url': String,
            'positives': Number,
            'total': Number,
            'scan_date': Date,
        }],
    'pcaps': [String],
    'subdomains': [String],
    'resolutions': [
        {
            'last_resolved': Date,
            'ip_address': String,
        }],
    'BitDefender category': String,
    'TrendMicro category': String,
    'Websense ThreatSeeker category': String,
    'Dr Web category': String,
    'response_code': Number,
    'verbose_msg': String,
}, {
    collection: 'virustotal',
});

const virustotalModel = mongoose.model('virustotalModel', virustotalSchema);

module.exports = {
    VirustotalModel: virustotalModel,
    getRecordByZonePromise: function (zone) {
        return virustotalModel.findOne({
            'zone': zone,
        }).exec();
    },
    getDetectedReferrerSamplesPromise: function (count) {
        let promise;
        if (count) {
            promise = virustotalModel.find({
                'detected_referrer_samples': { '$ne': [] },
            }).exists('detected_referrer_samples').countDocuments().exec();
        } else {
            promise = virustotalModel.find({
                'detected_referrer_samples': { '$ne': [] },
            }, {
                'zone': 1,
                'detected_referrer_samples': 1,
            }).exists('detected_referrer_samples').exec();
        }
        return (promise);
    },
    getDetectedReferrerSamplesByZonePromise: function (zone, count) {
        let promise;
        if (count) {
            promise = virustotalModel.find({
                'zone': zone,
                'detected_referrer_samples': { '$ne': [] },
            }).exists('detected_referrer_samples').countDocuments().exec();
        } else {
            promise = virustotalModel.find({
                'zone': zone,
                'detected_referrer_samples': { '$ne': [] },
            }, {
                'zone': 1,
                'detected_referrer_samples': 1,
            }).exists('detected_referrer_samples').exec();
        }
        return (promise);
    },
    getDetectedCommunicatingSamplesPromise: function (count) {
        let promise;
        if (count) {
            promise = virustotalModel.find({
                'detected_communicating_samples': { '$ne': [] },
            }).exists('detected_communicating_samples').countDocuments().exec();
        } else {
            promise = virustotalModel.find({
                'detected_communicating_samples': { '$ne': [] },
            }, {
                'zone': 1,
                'detected_communicating_samples': 1,
            }).exists('detected_communicating_samples').exec();
        }
        return (promise);
    },
    getDetectedCommunicatingSamplesByZonePromise: function (zone, count) {
        let promise;
        if (count) {
            promise = virustotalModel.find({
                'zone': zone,
                'detected_communicating_samples': { '$ne': [] },
            }).exists('detected_communicating_samples').countDocuments().exec();
        } else {
            promise = virustotalModel.find({
                'zone': zone,
                'detected_communicating_samples': { '$ne': [] },
            }, {
                'zone': 1,
                'detected_communicating_samples': 1,
            }).exists('detected_communicating_samples').exec();
        }
        return (promise);
    },
    getDetectedDownloadedSamplesPromise: function (count) {
        let promise;
        if (count) {
            promise = virustotalModel.find({
                'detected_downloaded_samples': { '$ne': [] },
            }).exists('detected_downloaded_samples').countDocuments().exec();
        } else {
            promise = virustotalModel.find({
                'detected_downloaded_samples': { '$ne': [] },
            }, {
                'zone': 1,
                'detected_downloaded_samples': 1,
            }).exists('detected_downloaded_samples').exec();
        }
        return (promise);
    },
    getDetectedDownloadedSamplesByZonePromise: function (zone, count) {
        let promise;
        if (count) {
            promise = virustotalModel.find({
                'zone': zone,
                'detected_downloaded_samples': { '$ne': [] },
            }).exists('detected_downloaded_samples').countDocuments().exec();
        } else {
            promise = virustotalModel.find({
                'zone': zone,
                'detected_downloaded_samples': { '$ne': [] },
            }, {
                'zone': 1,
                'detected_downloaded_samples': 1,
            }).exists('detected_downloaded_samples').exec();
        }
        return (promise);
    },
    getDetectedURLsPromise: function (count) {
        let promise;
        if (count) {
            promise = virustotalModel.find({
                'detected_urls': { '$ne': [] },
            }).exists('detected_urls').countDocuments().exec();
        } else {
            promise = virustotalModel.find({
                'detected_urls': { '$ne': [] },
            }, {
                'zone': 1,
                'detected_urls': 1
            }).exists('detected_urls').exec();
        }
        return (promise);
    },
    getDetectedURLsByZonePromise: function (zone, count) {
        let promise;
        if (count) {
            promise = virustotalModel.find({
                'zone': zone,
                'detected_urls': { '$ne': [] },
            }).exists('detected_urls').countDocuments().exec();
        } else {
            promise = virustotalModel.find({
                'zone': zone,
                'detected_urls': { '$ne': [] },
            }, {
                'zone': 1,
                'detected_urls': 1
            }).exists('detected_urls').exec();
        }
        return (promise);
    },
    getSubDomainsByZonePromise: function (zone) {
        return virustotalModel.find({
            'zone': zone,
        }, {
            'zone': 1,
            'domain_siblings': 1,
            'subdomains': 1,
        }).exec();
    },
    getMetaInfoByZonePromise: function (zone) {
        return virustotalModel.find({
            'zone': zone,
        }, {
            'zone': 1,
            'categories': 1,
            'Webutation domain info': 1,
            'Websense ThreatSeeker category': 1,
            'Forcepoint ThreatSeeker category': 1,
            'BitDefender category': 1,
            'Alexa rank': 1,
            'TrendMicro category': 1,
            'Alexa domain info': 1,
            'Alexa category': 1,
            'WOT domain info': 1,
            'Dr Web category': 1,
        }).exec();
    },
    getIPInfoByZonePromise: function (zone) {
        return virustotalModel.find({
            'zone': zone,
        }, {
            'zone': 1,
            'resolutions': 1
        }).exec();
    },
    getAllPcapsPromise: function (count) {
        let promise;
        if (count) {
            promise = virustotalModel.find({
                'pcaps': { '$ne': [] },
            }).exists('pcaps').countDocuments().exec();
        } else {
            promise = virustotalModel.find({
                'pcaps': { '$ne': [] },
            }, {
                'pcaps': 1,
                'zone': 1,
            }).exists('pcaps').exec();
        }
        return (promise);
    },
    getPcapsByZonePromise: function (zone, count) {
        let promise;
        if (count) {
            promise = virustotalModel.countDocuments({ 'zone': zone }).exec();
        } else {
            promise = virustotalModel.find({
                'zone': zone,
            }, {
                'zone': 1,
                'pcaps': 1,
            }).exec();
        }
        return (promise);
    },
    getWhoisByZonePromise: function (zone) {
        return virustotalModel.find({
            'zone': zone,
        }, {
            'zone': 1,
            'whois': 1,
            'whois_timestamp': 1,
        }).exec();
    },
};
