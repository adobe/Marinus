#!/usr/bin/python

# Copyright 2018 Adobe. All rights reserved.
# This file is licensed to you under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License. You may obtain a copy
# of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR REPRESENTATIONS
# OF ANY KIND, either express or implied. See the License for the specific language
# governing permissions and limitations under the License.

"""
This script runs after the download_*_certs scripts.
It scans through all of the downloaded certificates from each CT database.
It will add any newly identified certificates to the Mongo database.
It will also update the expiration setting on the existing certificates in the MongoDB.

Data is read from: /mnt/workspace/ct_{ct_log_name}/
The certificate transparency github project must be installed in
/mnt/workspace/certificate-transparency/
"""

import json
import calendar
import base64
import os
from datetime import datetime
import hashlib
import binascii
import struct
from OpenSSL import crypto

from libs2 import MongoConnector

import sys
sys.path.append("/mnt/workspace/certificate-transparency/python")

from ct.crypto import cert
from ct.crypto import error
from ct.crypto import pem
from ct.crypto.asn1 import print_util
from ct.crypto.error import ASN1IllegalCharacter

CERT_PATH = "/mnt/workspace/ct_"
CERT_SOURCES = ["pilot", "aviator", "digicert", "facebook"]

MC = MongoConnector.MongoConnector()

SCT_VERSION_V1 = 0
TLSEXT_hash_none =                               0
TLSEXT_hash_md5 =                                1
TLSEXT_hash_sha1 =                               2
TLSEXT_hash_sha224 =                             3
TLSEXT_hash_sha256 =                             4
TLSEXT_hash_sha384 =                             5
TLSEXT_hash_sha512 =                             6
TLSEXT_hash_gostr3411 =                          237
TLSEXT_hash_gostr34112012_256 =                  238
TLSEXT_hash_gostr34112012_512 =                  239

TLSEXT_signature_anonymous =                     0
TLSEXT_signature_rsa =                           1
TLSEXT_signature_dsa =                           2
TLSEXT_signature_ecdsa =                         3
TLSEXT_signature_gostr34102001 =                 237
TLSEXT_signature_gostr34102012_256 =             238
TLSEXT_signature_gostr34102012_512 =             239

CT_LOG_MAP =   {# Google
                'aPaY+B9kgr46jO65KB1M/HFRXWeT1ETRCmesu09P+8Q=': 'ct.googleapis.com/aviator',
                'KTxRllTIOWW6qlD8WAfUt2+/WHopctykwwz05UVH9Hg=': 'ct.googleapis.com/icarus',
                'pLkJkLQYWBSHuxOizGdwCjw1mAT5G9+443fNDsgN3BA=': 'ct.googleapis.com/pilot',
                '7ku9t3XOYLrhQmkfq+GeZqMPfl+wctiDAMR7iXqo/cs=': 'ct.googleapis.com/rocketeer',
                'u9nfvB+KcbWTlCOXqpJ7RzhXlQqrUugakJZkNo4e0YU=': 'ct.googleapis.com/skydiver',
                'pFASaQVaFVReYhGrN7wQP2KuVXakXksXFEU+GyIQaiU=': 'ct.googleapis.com/logs/argon2018',
                'Y/Lbzeg7zCzPC3KEJ1drM6SNYXePvXWmOLHHaFRL2I0=': 'ct.googleapis.com/logs/argon2019',
                'sh4FzIuizYogTodm+Su5iiUgZ2va+nDnsklTLe+LkF4=': 'ct.googleapis.com/logs/argon2020',
                '9lyUL9F3MCIUVBgIMJRWjuNNExkzv98MLyALzE7xZOM=': 'ct.googleapis.com/logs/argon2021',
                'sQzVWabWeEaBH335pRUyc5rEjXA76gMj2l04dVvArU4=': 'ct.googleapis.com/logs/xenon2018',
                'CEEUmABxUywWGQRgvPxH/cJlOvopLHKzf/hjrinMyfA=': 'ct.googleapis.com/logs/xenon2019',
                'B7dcG+V9aP/xsMYdIxXHuuZXfFeUt2ruvGE6GmnTohw=': 'ct.googleapis.com/logs/xenon2020',
                'fT7y+I//iFVoJMLAyp5SiXkrxQ54CX8uapdomX4i8Nc=': 'ct.googleapis.com/logs/xenon2021',
                'RqVV63X6kSAwtaKJafTzfREsQXS+/Um4havy/HD+bUc=': 'ct.googleapis.com/logs/xenon2022',
                # DigiCert
                'VhQGmi/XwuzT9eG9RLI+x0Z2ubyZEVzA75SYVdaJ0N0=': 'ct1.digicert-ct.com/log',
                'h3W/51l8+IxDmV+9827/Vo1HVjb/SrVgwbTq/16ggw8=': 'ct2.digicert-ct.com',
                'wRZK4Kdy0tQ5LcgKwQdw1PDEm96ZGkhAwfoHUWT2M2A=': 'yeti2018.ct.digicert.com/log',
                '4mlLribo6UAJ6IYbtjuD1D7n/nSI+6SPKJMBnd3x2/4=': 'yeti2019.ct.digicert.com/log',
                '8JWkWfIA0YJAEC0vk4iOrUv+HUfjmeHQNKawqKqOsnM=': 'yeti2020.ct.digicert.com/log',
                'XNxDkv7mq0VEsV6a1FbmEDf71fpH3KFzlLJe5vbHDso=': 'yeti2021.ct.digicert.com/log',
                'IkVFB1lVJFaWP6Ev8fdthuAjJmOtwEt/XcaDXG7iDwI=': 'yeti2022.ct.digicert.com/log',
                'b/FBtWR+QiL37wUs7658If1gjifSr1pun0uKN9ZjPuU=': 'nessie2018.ct.digicert.com/log',
                '/kRhCLHQGreKYsz+q2qysrq/86va2ApNizDfLQAIgww=': 'nessie2019.ct.digicert.com/log',
                'xlKg7EjOs/yrFwmSxDqHQTMJ6ABlomJSQBujNioXxWU=': 'nessie2020.ct.digicert.com/log',
                '7sCV7o1yZA+S48O5G8cSo2lqCXtLahoUOOZHssvtxfk=': 'nessie2021.ct.digicert.com/log',
                'UaOw9f0BeZxWbbg3eI8MpHrMGyfL956IQpoN/tSLBeU=': 'nessie2022.ct.digicert.com/log',
                # Symantec
                '3esdK3oNT6Ygi4GtgWhwfi6OnQHVXIiNPRHEzbbsvsw=': 'ct.ws.symantec.com',
                'p85KTmIH4K3e5f2qSx+GdodntdACpV1HMQ5+ZwqV6rI=': 'deneb.ws.symantec.com',
                'FZcEiNe5l6Bb61JRKt7o0ui0oxZSZBIan6v71fha2T8=': 'sirius.ws.symantec.com',
                'vHjh38X2PGhGSTNNoQ+hXwl5aSAJwIG08/aRfz7ZuKU=': 'vega.ws.symantec.com',
                # Comodo
                'b1N2rDHwMRnYmQCkURX/dxUcEdkCwQApBo2yCJo32RM=': 'mammoth.ct.comodo.com',
                'VYHUwhaQNgFK6gubVzxT8MDkOHhwJQgXL6OqHQcT0ww=': 'sabre.ct.comodo.com',
                # CloudFlare
                'H7w24ALt6X9AGZ6Gs1c7ikIX2AGHdGrQ2gOgYFTSDfQ=': 'ct.cloudflare.com/logs/nimbus2017',
                '23Sv7ssp7LH+yj5xbSzluaq7NveEcYPHXZ1PN7Yfv2Q=': 'ct.cloudflare.com/logs/nimbus2018',
                'dH7agzGtMxCRIZzOJU9CcMK//V5CIAjGNzV55hB7zFY=': 'ct.cloudflare.com/logs/nimbus2019',
                'Xqdz+d9WwOe1Nkh90EngMnqRmgyEoRIShBh1loFxRVg=': 'ct.cloudflare.com/logs/nimbus2020',
                'RJRlLrDuzq/EQAfYqP4owNrmgr7YyzG1P9MzlrW2gag=': 'ct.cloudflare.com/logs/nimbus2021',
                'QcjKsd8iRkoQxqE6CUKHXk4xixsD6+tLx2jwkGKWBvY=': 'ct.cloudflare.com/logs/nimbus2022',
                # Misc
                'rDua7X+pZ0dXFZ5tfVdWcvnZgQCUHpve/+yhMTt1eC0=': 'ctlog.api.venafi.com',
                'AwGd8/2FppqOvR+sxtqbpz5Gl3T+d/V5/FoIuDKMHWs=': 'ctlog-gen2.api.venafi.com',
                'pXesnO11SN2PAltnokEInfhuD0duwgPC7L7bGF8oJjg=': 'ctserver.cnnic.cn',
                'cX6nQgl1voSicjVT8Xd8Jt1Rr04QIUQJTZAZtGL7Zmg=': 'log.gdca.com.cn',
                'FDCNkMzQMBNQBcAcpSbYHoTodiTjm2JI4I9ySuo7tCo=': 'log2.gdca.com.cn',
                # No longer supported
                'Gjj3bo1vS9GxMAFS0XV1B88iKrHDdVZRF4sBbmGyY0o=': 'ct.gdca.com.cn',
                'kkow+Qkzb/Q11pk6EKx1osZBco5/wtZZrmGI/61AzgE=': 'ctlog.gdca.com.cn',
                'HQJLjrFJizRN/YfqPvwJlvdQbyNdHUlwYaR3PEOcJfs=': 'ct.googleapis.com/daedalus',
                'qJnYeAySkKr0YvMYgMz71SRR6XDQ+/WR73Ww2ZtkVoE=': 'ct.googleapis.com/submariner',
                'QbLcLonmPOSvG6e7Kb9oxt7m+fHMBH4w3/rjs7olkmM=': 'ctlog.wosign.com',
                'iUFEnHB0Lga5/JznsRa6ACSqNtWa9E8CBEBPAPfqhWY=': 'ct.izenpe.eus',
                'NLtq1sPfnAPuqKSZ/3iRSGydXlysktAfe/0bzhnbSO8=': 'ct.startssl.com',
               }

certFields = ['issuer_common_name',
              'issuer_country_name',
              'subject_common_names',
              'subject_organization_name',
              'subject_street_address',
              'subject_state_or_province_name',
              'subject_postal_code',
              'subject_organizational_unit_name',
              'subject_locality_name',
              'key_usages',
              'subject_dns_names',
              'subject_ip_addresses',
              'extended_key_usages']

def SCT_get_signature_nid(version, hash_alg, sig_alg):
    """
    Get the associated signature algorith string
    """
    if version == SCT_VERSION_V1 and hash_alg == TLSEXT_hash_sha256:
        # Formerly a switch (sig_alg) returning the mappings below:
        if sig_alg == TLSEXT_signature_ecdsa:
            #NID_ecdsa_with_SHA256
            return "ecdsa-with-SHA256"
        #case TLSEXT_signature_rsa:
        elif sig_alg == TLSEXT_signature_rsa:
            #NID_sha256WithRSAEncryption
            return "sha256WithRSAEncryption"
        #default:
        else:
            #NID_undef;
            return None

    return None


def _splitBytes(buf, count):
    """
    Split buf into two strings (part1, part2) where part1 has count bytes.
    @raises ValueError if buf is too short.
    """
    if len(buf) < count:
        raise ValueError(("Malformed structure encountered when parsing SCT, " +
                          "expected %d bytes, got only %d") % (count, len(buf)))

    return buf[:count], buf[count:]


def parse_sct(asn1_sctList):
    """
    Parse the SCT signature record.
    """
    data = asn1_sctList
    scts = []

    # This parsing is ugly, but we can't use pyasn1 -
    # the data is serialized according to RFC 5246.
    packed_len, data = _splitBytes(data, 2)
    total_len = struct.unpack("!H", packed_len)[0]
    if len(data) != total_len:
        raise ValueError("Malformed length of SCT list")
    bytes_read = 0

    while bytes_read < total_len:
        packed_len, data = _splitBytes(data, 2)
        sct_len = struct.unpack("!H", packed_len)[0]

        bytes_read += sct_len + 2
        sct_data, data = _splitBytes(data, sct_len)
        packed_vlt, sct_data = _splitBytes(sct_data, 41)
        version, logid, timestamp = struct.unpack("!B32sQ", packed_vlt)
        timestamp = datetime.fromtimestamp(timestamp/1000.0)

        packed_len, sct_data = _splitBytes(sct_data, 2)
        ext_len = struct.unpack("!H", packed_len)[0]
        extensions, sct_data = _splitBytes(sct_data, ext_len)

        hash_alg, sig_alg, sig_len = struct.unpack("!BBH", sct_data[:4])
        signature = sct_data[4:]
        if len(signature) != sig_len:
            raise ValueError(("SCT signature has incorrect length, " +
                              "expected %d, got %d") % (sig_len, len(signature)))

        scts.append({'log_name': CT_LOG_MAP[base64.b64encode(logid)],
                     'log_id': base64.b64encode(logid),
                     'version': version,
                     'timestamp': timestamp,
                     'hash_alg': hash_alg,
                     'sig_alg': sig_alg,
                     'sig_alg_name': SCT_get_signature_nid(version, hash_alg, sig_alg),
                     'signature': ":".join("{:02x}".format(ord(c)) for c in signature),
                     'extensions': extensions})

    return scts


def get_printable_string(entity):
    """
    Get a printable string representing the entity
    """
    entries = []

    for item in entity:
        entries.append(str(item))

    return entries


def get_hash(file_str):
    """
    Get a hash of the provided string reprsenting the file
    """
    SHAhash = hashlib.sha1()
    SHAhash.update(file_str)
    return SHAhash.hexdigest()


def parse_cert(cert_id, file, cert_source):
    """
    Parse the certificate provided in the file
    """
    der_failure = False
    try:
        der_cert = cert.Certificate.from_der(file, strict_der=False)
    except:
        der_failure = True

    if der_failure:
        try:
            der_cert = cert.Certificate.from_pem(file)
        except ASN1IllegalCharacter as asn_err:
            print "ID: " + cert_id + " Not DER or PEM!"
            print "ASN1Error: " + str(asn_err)
            exit(0)
        except:
            print "ID: " + cert_id + " Not DER or PEM!"
            print "Unexpected error:", sys.exc_info()[0]
            exit(0)

    parsed_der = {}

    for field in certFields:
        parsed_der[field] = get_printable_string(getattr(der_cert, field)())

    parsed_der['not_before'] = datetime.fromtimestamp(calendar.timegm(der_cert.not_before()))
    parsed_der['not_after'] = datetime.fromtimestamp(calendar.timegm(der_cert.not_after()))
    parsed_der['isExpired'] = der_cert.is_expired()
    parsed_der['isSelfSigned'] = der_cert.is_self_signed()
    parsed_der['fingerprint_sha1'] = binascii.hexlify(der_cert.fingerprint("sha1"))
    parsed_der['fingerprint_sha256'] = binascii.hexlify(der_cert.fingerprint("sha256"))
    parsed_der['basic_constraint_ca'] = bool(der_cert.basic_constraint_ca())

    parsed_der['signature_algorithm'] = der_cert.signature_algorithm()['algorithm'].short_name
    parsed_der['full_certificate'] = str(der_cert)

    parsed_der['sources'] = [cert_source]
    parsed_der['raw'] = base64.b64encode(file)

    scts = der_cert.embedded_sct_list()
    if scts != None:
        parsed_der['scts'] = parse_sct(scts)

    return parsed_der


def process_path(cert_source, mongo_ct_connection):
    """
    Find new certificates in the cert_source directory.
    """
    cert_fp = CERT_PATH + cert_source + "/"
    cids = mongo_ct_connection.find({}, {"fingerprint_sha1": 1})
    mongo_certs = []
    for row in cids:
        mongo_certs.append(row['fingerprint_sha1'])

    print "Identified "  + str(len(mongo_certs)) + " certs in MongoDB"

    files = os.listdir(cert_fp)

    for file_ref in files:
        cert_f = open(cert_fp + file_ref, "r")

        if cert_source == "facebook":
            #Convert PEM to DER for consistency
            temp = cert_f.read()
            cert_pem = crypto.load_certificate(crypto.FILETYPE_PEM, temp)
            f_str = crypto.dump_certificate(crypto.FILETYPE_ASN1, cert_pem)
        else:
            f_str = cert_f.read()

        cert_f.close()

        f_hash = get_hash(f_str)
        if f_hash not in mongo_certs:
            data = parse_cert(cert_fp + file_ref, f_str, cert_source)
            print "Adding " + file_ref
            mongo_certs.append(f_hash)
            mongo_ct_connection.insert(data)
        else:
            mongo_ct_connection.update_one({'fingerprint_sha1': f_hash},
                                           {"$addToSet": {"sources": cert_source}})


def main():
    """
    Begin Main()
    """

    now = datetime.now()
    print "Starting: " + str(now)

    jobs_collection = MC.get_jobs_connection()
    mongo_ct = MC.get_certificate_transparency_connection()

    for cert_path in CERT_SOURCES:
        process_path(cert_path, mongo_ct)

    #Set isExpired for any entries that have recently expired.
    mongo_ct.update({"not_after": {"$lt": datetime.utcnow()}, "isExpired": False},
                    {"$set": {"isExpired": True}}, multi=True)

    #Record status
    jobs_collection.update_one({'job_name': 'hash_based_upload'},
                               {'$currentDate': {"updated": True},
                                "$set": {'status': 'COMPLETE'}})

    now = datetime.now()
    print "Complete: " + str(now)


if __name__ == "__main__":
    main()
