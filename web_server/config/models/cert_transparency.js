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

const certTransparencySchema = new Schema({
  basic_constraint_ca: Boolean,
  extended_key_usages: [],
  isExpired: Boolean,
  isSelfSigned: Boolean,
  issuer_common_name: [],
  issuer_country_name: [],
  key_usages: [],
  not_after: Date,
  not_before: Date,
  marinus_createdate: Date,
  marinus_updated: Date,
  serial_number: String,
  signature_algorithm: String,
  subject_common_names: [],
  subject_dns_names: [],
  subject_ip_addresses: [],
  subject_locality_name: [],
  subject_organization_name: [],
  subject_organizational_unit_name: [],
  subject_postal_code: [],
  subject_state_or_province_name: [],
  subject_street_address: [],
  raw: String,
  full_certificate: String,
  sources: [],
  zones: [],
  fingerprint_sha1: String,
  fingerprint_sha256: String,
  scts: [{
    version: Number,
    log_id: String,
    log_name: String,
    timestamp: Date,
    hash_alg: Number,
    sig_alg: Number,
    sig_alg_name: String,
    signature: String,
    extensions: String
  }],
}, {
  collection: 'ct_certs',
});

const certTransModel = mongoose.model('certTransModel', certTransparencySchema);

module.exports = {
  CertTransModel: certTransModel,
  getCertTransOrgPromise: function (org) {
    return certTransModel.find({
      'subject_organization_name': { $in: org },
    }).exec();
  },
  getCertTransCNPromise: function (domain) {
    return certTransModel.find().or([{
      'subject_common_names': domain,
    }, {
      'subject_dns_names': domain,
    }]).exec();
  },
  getCertTransZonePromise: function (zone, count) {
    let promise;
    if (count) {
      promise = certTransModel.find({ 'zones': zone }).countDocuments().exec();
    } else {
      promise = certTransModel.find({ 'zones': zone }).exec();
    }
    return promise;
  },
  getCertTransCorpPromise: function (corp_domain, excludeExpired, count) {
    let reCorp = new RegExp('^.*\.' + corp_domain);
    let promise;
    if (excludeExpired != null && excludeExpired === true) {
      if (count) {
        promise = certTransModel.find({
          '$or': [{ 'subject_common_names': reCorp },
          { 'subject_dns_names': reCorp }],
          'isExpired': false
        }).countDocuments().exec();
      } else {
        promise = certTransModel.find({
          '$or': [{ 'subject_common_names': reCorp },
          { 'subject_dns_names': reCorp }],
          'isExpired': false
        }).exec();
      }
    } else {
      if (count) {
        promise = certTransModel.find({
          '$or': [{ 'subject_common_names': reCorp },
          { 'subject_dns_names': reCorp }]
        }).countDocuments().exec();
      } else {
        promise = certTransModel.find({
          '$or': [{ 'subject_common_names': reCorp },
          { 'subject_dns_names': reCorp }]
        }).exec();
      }
    }
    return promise;
  },
  getCertTransIPPromise: function (ip) {
    return certTransModel.find({
      'subject_ip_addresses': ip,
    }).exec();
  },
  getCertTransById: function (id) {
    return certTransModel.findById(id).exec();
  },
  getCertTransBySerialNumberPromise: function (serial_number, count) {
    if (serial_number.includes(":") == false) {
      serial_number = serial_number.replace(/..\B/g, '$&:');
    }

    if (count) {
      return certTransModel.countDocuments({ 'serial_number': serial_number.toLowerCase() }).exec();
    }

    return certTransModel.find({ 'serial_number': serial_number.toLowerCase() }).exec();
  },
  getCertTransIssuers: function (issuer, count, excludeExpired) {
    let promise;
    let query = { 'issuer_common_name': issuer }
    if (excludeExpired != null && excludeExpired === true) {
      query['isExpired'] = false;
    }
    if (count) {
      promise = certTransModel.countDocuments(query).exec();
    } else {
      promise = certTransModel.find(query).exec();
    }
    return promise;
  },
  getSSLOrgCountPromise: function (org) {
    let foo = [];
    foo.push(org);
    return certTransModel.countDocuments({
      'subject_organization_name': { '$in': foo },
      'isExpired': false,
    }).exec();
  },
  getUnexpiredSigAlg: function (algorithm, count) {
    let promise;
    if (count === true) {
      promise = certTransModel.countDocuments({
        'signature_algorithm': algorithm,
        'isExpired': false
      }).exec();
    } else {
      promise = certTransModel.find({
        'signature_algorithm': algorithm,
        'isExpired': false
      }).exec();
    }
    return promise;
  },
  getDistinctIssuers: function (excludeExpired) {
    let promise;
    if (excludeExpired != null && excludeExpired === true) {
      promise = certTransModel.distinct('issuer_common_name', { 'isExpired': false }).exec();
    } else {
      promise = certTransModel.distinct('issuer_common_name').exec();
    }
    return promise;
  },
  getCorpCount: function (corp_domain) {
    let reCorp = new RegExp('^.*\.' + corp_domain);
    return certTransModel.find({
      '$or': [{ 'subject_common_names': reCorp },
      { 'subject_dns_names': reCorp }],
    }).countDocuments().exec();
  },
  getCertCount: function () {
    return certTransModel.countDocuments({}).exec();
  },
  getCertByX509SCTRecord: function (name, count) {
    let logName;
    if (name === 'pilot') {
      logName = 'ct.googleapis.com/pilot';
    } else if (name === 'aviator') {
      logName = 'ct.googleapis.com/aviator';
    } else if (name === 'rocketeer') {
      logName = 'ct.googleapis.com/rocketeer';
    } else if (name === 'digicert') {
      logName = 'ct1.digicert-ct.com/log';
    } else if (name === 'symantec') {
      logName = 'ct.ws.symantec.com';
    }
    let promise;
    if (count === true) {
      promise = certTransModel.countDocuments({
        'scts.log_name': logName,
      }).exec();
    } else {
      promise = certTransModel.find({ 'scts.log_name': logName }).exec();
    }
    return promise;
  },
  getCertByCTLog: function (logName, count) {
    let promise;
    if (count === true) {
      promise = certTransModel.countDocuments({ 'sources': logName }).exec();
    } else {
      promise = certTransModel.find({ 'sources': logName }).exec();
    }
    return promise;
  },
  getCTCertByFingerprintSHA1: function (fingerprintSha1, count) {
    let promise;
    if (count === true) {
      promise = certTransModel.countDocuments({
        'fingerprint_sha1': fingerprintSha1,
      }).exec();
    } else {
      promise = certTransModel.findOne({
        'fingerprint_sha1': fingerprintSha1,
      }).exec();
    }
    return promise;
  },
  getCTCertByFingerprintSHA256: function (fingerprintSha256, count) {
    let promise;
    if (count === true) {
      promise = certTransModel.countDocuments({
        'fingerprint_sha256': fingerprintSha256,
      }).exec();
    } else {
      promise = certTransModel.findOne({
        'fingerprint_sha256': fingerprintSha256,
      }).exec();
    }
    return promise;
  },
  getCTCertByGTMarinusCreate: function (marinus_createdate, count) {
    let promise;
    if (count === true) {
      promise = certTransModel.countDocuments({
        'marinus_createdate': { "$gt": new Date(marinus_createdate) },
      }).exec();
    } else {
      promise = certTransModel.find({
        'marinus_createdate': { "$gt": new Date(marinus_createdate) },
      }).exec();
    }
    return promise;
  },
  getCTCertByLTMarinusCreate: function (marinus_createdate, count) {
    let promise;
    if (count === true) {
      promise = certTransModel.countDocuments({
        'marinus_createdate': { "$lt": new Date(marinus_createdate) },
      }).exec();
    } else {
      promise = certTransModel.find({
        'marinus_createdate': { "$lt": new Date(marinus_createdate) },
      }).exec();
    }
    return promise;
  },
  getCTCertByMarinusCreateRange: function (start_date, end_date, count) {
    let promise;
    if (count === true) {
      promise = certTransModel.countDocuments({
        'marinus_createdate': { "$gt": new Date(start_date), "$lt": new Date(end_date) },
      }).exec();
    } else {
      promise = certTransModel.find({
        'marinus_createdate': { "$gt": new Date(start_date), "$lt": new Date(end_date) },
      }).exec();
    }
    return promise;
  },
  getCTCertByGTMarinusUpdated: function (marinus_updated, count) {
    let promise;
    if (count === true) {
      promise = certTransModel.countDocuments({
        'marinus_updated': { "$gt": new Date(marinus_updated) },
      }).exec();
    } else {
      promise = certTransModel.find({
        'marinus_updated': { "$gt": new Date(marinus_updated) },
      }).exec();
    }
    return promise;
  },
  getCTCertByLTMarinusUpdated: function (marinus_updated, count) {
    let promise;
    if (count === true) {
      promise = certTransModel.countDocuments({
        'marinus_updated': { "$lt": new Date(marinus_updated) },
      }).exec();
    } else {
      promise = certTransModel.find({
        'marinus_updated': { "$lt": new Date(marinus_updated) },
      }).exec();
    }
    return promise;
  },
  getCTCertByMarinusUpdateRange: function (start_date, end_date, count) {
    let promise;
    if (count === true) {
      promise = certTransModel.countDocuments({
        'marinus_updated': { "$gt": new Date(start_date), "$lt": new Date(end_date) },
      }).exec();
    } else {
      promise = certTransModel.find({
        'marinus_updated': { "$gt": new Date(start_date), "$lt": new Date(end_date) },
      }).exec();
    }
    return promise;
  },
};
