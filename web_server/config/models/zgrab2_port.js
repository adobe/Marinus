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

const z2PortSchema = require('./zgrab2_port_schema.js');

// ZGrab 2.0 port scan module
module.exports = {
    zgrab2PortModel: z2PortSchema.zgrab2PortModel,
    getRecordByIPPromise: function (ip, port, count) {
        if (port === "22") {
            if (count) {
                return z2PortSchema.zgrab2PortModel.find({ 'ip': ip }).exists('data.ssh').exec();
            } else {
                return z2PortSchema.zgrab2PortModel.find({ 'ip': ip }, { 'ip': 1, 'data.ssh': 1 }).exec();
            }
        } else if (port === "25") {
            if (count) {
                return z2PortSchema.zgrab2PortModel.find({ 'ip': ip }).exists('data.smtp').exec();
            } else {
                return z2PortSchema.zgrab2PortModel.find({ 'ip': ip }, { 'ip': 1, 'data.smtp': 1 }).exec();
            }
        } else if (port === "443") {
            if (count) {
                return z2PortSchema.zgrab2PortModel.find({ 'ip': ip }).exists('data.tls').exec();
            } else {
                return z2PortSchema.zgrab2PortModel.find({ 'ip': ip }, { 'ip': 1, 'data.tls': 1 }).exec();
            }
        } else if (port === "465") {
            if (count) {
                return z2PortSchema.zgrab2PortModel.find({ 'ip': ip }).exists('data.smtps').exec();
            } else {
                return z2PortSchema.zgrab2PortModel.find({ 'ip': ip }, { 'ip': 1, 'data.smtps': 1 }).exec();
            }
        } else if (count) {
            return z2PortSchema.zgrab2PortModel.find({ 'ip': ip }).countDocuments().exec()
        }
        return z2PortSchema.zgrab2PortModel.find({ 'ip': ip }).exec();
    },
    getRecordByDomainPromise: function (domain, port, count) {
        if (port === "22") {
            if (count) {
                return z2PortSchema.zgrab2PortModel.find({ "domains": domain }).countDocuments().exec();
            } else {
                return z2PortSchema.zgrab2PortModel.find({ "domains": domain }).exec();
            }
        } else if (port === "25") {
            if (count) {
                return z2PortSchema.zgrab2PortModel.find({
                    '$or': [{ 'domains': domain },
                    { 'data.smtp.result.tls.handshake_log.server_certificates.certificate.parsed.subject.common_name': domain },
                    { 'data.smtp.result.tls.handshake_log.server_certificates.certificate.parsed.extensions.subject_alt_name.dns_names': domain }]
                }).countDocuments().exec();
            } else {
                return z2PortSchema.zgrab2PortModel.find({
                    '$or': [{ 'domains': domain },
                    { 'data.smtp.result.tls.handshake_log.server_certificates.certificate.parsed.subject.common_name': domain },
                    { 'data.smtp.result.tls.handshake_log.server_certificates.certificate.parsed.extensions.subject_alt_name.dns_names': domain }]
                }, { 'ip': 1, 'data.smtp': 1 }).exec();
            }
        } else if (port === "443") {
            if (count) {
                return z2PortSchema.zgrab2PortModel.find({
                    '$or': [{ 'domains': domain },
                    { 'data.tls.result.handshake_log.server_certificates.certificate.parsed.subject.common_name': domain },
                    { 'data.tls.result.handshake_log.server_certificates.certificate.parsed.extensions.subject_alt_name.dns_names': domain }]
                }).countDocuments().exec();
            } else {
                return z2PortSchema.zgrab2PortModel.find({
                    '$or': [{ 'domains': domain },
                    { 'data.tls.result.handshake_log.server_certificates.certificate.parsed.subject.common_name': domain },
                    { 'data.tls.result.handshake_log.server_certificates.certificate.parsed.extensions.subject_alt_name.dns_names': domain }]
                }, { 'ip': 1, 'data.tls': 1 }).exec();
            }
        } else if (port === "465") {
            if (count) {
                return z2PortSchema.zgrab2PortModel.find({
                    '$or': [{ 'domains': domain },
                    { 'data.smtps.result.tls.handshake_log.server_certificates.certificate.parsed.subject.common_name': domain },
                    { 'data.smtps.result.tls.handshake_log.server_certificates.certificate.parsed.extensions.subject_alt_name.dns_names': domain }]
                }).countDocuments().exec();
            } else {
                return z2PortSchema.zgrab2PortModel.find({
                    '$or': [{ 'domains': domain },
                    { 'data.smtps.result.tls.handshake_log.server_certificates.certificate.parsed.subject.common_name': domain },
                    { 'data.smtps.result.tls.handshake_log.server_certificates.certificate.parsed.extensions.subject_alt_name.dns_names': domain }]
                }, { 'ip': 1, 'data.smtps': 1 }).exec();
            }
        } else if (count) {
            return (z2PortSchema.zgrab2PortModel.find({ 'domains': domain }).countDocuments().exec());
        }
        return (z2PortSchema.zgrab2PortModel.find({ 'domains': domain }).exec());
    },
    getRecordByZonePromise: function (zone, port, count) {
        if (port === "22") {
            return z2PortSchema.zgrab2PortModel.find({ "zones": zone }).exists("data.ssh").exec();
        } else if (port === "25") {
            return z2PortSchema.zgrab2PortModel.find({ "zones": zone }).exists("data.smtp").exec();
        } else if (port === "443") {
            return z2PortSchema.zgrab2PortModel.find({ "zones": zone }).exists("data.tls").exec();
        } else if (port === "465") {
            return z2PortSchema.zgrab2PortModel.find({ "zones": zone }).exists("data.smtps").exec();
        } else if (count) {
            return z2PortSchema.zgrab2PortModel.find({ 'zones': zone }).countDocuments().exec();
        }
        return z2PortSchema.zgrab2PortModel.find({ 'zones': zone }).exec();
    },
    getTLSIPListPromise: function (count, limit, page) {
        if (count) {
            return z2PortSchema.zgrab2PortModel.find({}).exists('data.tls').countDocuments().exec();
        } else {
            if (limit > 0) {
                return z2PortSchema.zgrab2PortModel.find({}, { "ip": 1, "aws": 1, "azure": 1, "tracked": 1 }).exists('data.tls').skip(limit * (page - 1)).limit(limit).exec();
            } else {
                return z2PortSchema.zgrab2PortModel.find({}, { "ip": 1, "aws": 1, "azure": 1, "tracked": 1 }).exists('data.tls').exec();
            }
        }
    },
    getXSSHIPListPromise: function (count, limit, page) {
        if (count) {
            return z2PortSchema.zgrab2PortModel.find({}).exists('data.ssh').countDocuments().exec();
        } else {
            if (limit > 0) {
                return z2PortSchema.zgrab2PortModel.find({}, { "ip": 1, "aws": 1, "azure": 1, "tracked": 1 }).exists('data.ssh').skip(limit * (page - 1)).limit(limit).exec();
            } else {
                return z2PortSchema.zgrab2PortModel.find({}, { "ip": 1, "aws": 1, "azure": 1, "tracked": 1 }).exists('data.ssh').exec();
            }
        }
    },
    getSMTPIPListPromise: function (count, limit, page) {
        if (count) {
            return z2PortSchema.zgrab2PortModel.find({}).exists('data.smtp').countDocuments().exec();
        } else {
            if (limit > 0) {
                return z2PortSchema.zgrab2PortModel.find({}, { "ip": 1, "aws": 1, "azure": 1, "tracked": 1 }).exists('data.smtp').skip(limit * (page - 1)).limit(limit).exec();
            } else {
                return z2PortSchema.zgrab2PortModel.find({}, { "ip": 1, "aws": 1, "azure": 1, "tracked": 1 }).exists('data.smtp').exec();
            }
        }
    },
    getSMTPSIPListPromise: function (count, limit, page) {
        if (count) {
            return z2PortSchema.zgrab2PortModel.find({}).exists('data.smtps').countDocuments().exec();
        } else {
            if (limit > 0) {
                return z2PortSchema.zgrab2PortModel.find({}, { "ip": 1, "aws": 1, "azure": 1, "tracked": 1 }).exists('data.smtps').skip(limit * (page - 1)).limit(limit).exec();
            } else {
                return z2PortSchema.zgrab2PortModel.find({}, { "ip": 1, "aws": 1, "azure": 1, "tracked": 1 }).exists('data.smtps').exec();
            }
        }
    },
    getSSLByValidity2kPromise: function () {
        let isBefore2010 = new RegExp('^200.*');
        return z2PortSchema.zgrab2PortModel.find({ 'data.tls.result.handshake_log.server_certificates.certificate.parsed.validity.end': isBefore2010 },
            { 'domain': 1, 'ip': 1, 'data.tls': 1 }).exec();
    },
    getSSLByValidityYearPromise: function (year) {
        let thisDecade = new RegExp('^' + year + '.*');
        return z2PortSchema.zgrab2PortModel.find({ 'data.tls.result.handshake_log.server_certificates.certificate.parsed.validity.end': thisDecade },
            { 'domain': 1, 'ip': 1, 'data.tls': 1 }).exec();
    },
    getSSLByCorpNamePromise: function (internalDomain, count) {
        let reCorp = new RegExp('^.*\.' + internalDomain);
        if (count) {
            return z2PortSchema.zgrab2PortModel.find({
                '$or': [{ 'data.tls.result.handshake_log.server_certificates.certificate.parsed.subject.common_name': reCorp },
                { 'data.tls.result.handshake_log.server_certificates.certificate.parsed.extensions.subject_alt_name.dns_names': reCorp }],
            }, { 'ip': 1, 'data.tls': 1 }).countDocuments().exec();
        } else {
            return z2PortSchema.zgrab2PortModel.find({
                '$or': [{ 'data.tls.result.handshake_log.server_certificates.certificate.parsed.subject.common_name': reCorp },
                { 'data.tls.result.handshake_log.server_certificates.certificate.parsed.extensions.subject_alt_name.dns_names': reCorp }],
            }, { 'ip': 1, 'data.tls': 1 }).exec();
        }
    },
    getFullCountPromise: function () {
        return z2PortSchema.zgrab2PortModel.countDocuments({}).exec();
    }
}
