#!/usr/bin/python3

# Copyright 2021 Adobe. All rights reserved.
# This file is licensed to you under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License. You may obtain a copy
# of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR REPRESENTATIONS
# OF ANY KIND, either express or implied. See the License for the specific language
# governing permissions and limitations under the License.


"""
This library is responsible for parsing X509 certificates identified from sources such
as CT Logs. It replaces functionality previously found in the hash_based_upload Python 2
script. This library uses a combination of the "cryptography" and "pyOpenSSL" modules.
The Python "cryptography" library is preferred but it does not provide complete parity
with "pyOpenSSL". Therefore, "cryptography" is used except in those places where
"cryptography" does not expose the necessary functionality.
"""

import base64
import binascii
import logging
import struct
import sys
from datetime import datetime

from cryptography import x509
from cryptography.hazmat._oid import _OID_NAMES
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.bindings.openssl import binding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import ExtensionNotFound
from cryptography.x509.oid import ExtensionOID, NameOID, SignatureAlgorithmOID
from OpenSSL import crypto


class X509Parser(object):
    """
    This class is responsible for parsing X509 certificates and returning an object that represents the relevant fields.
    The choice of formatting was originally defined, in part, on data structures returned by the Google Certificate
    Transparency project.

    This class supports both DER and PEM certificate formats.

    Certificates can be provided as a file location
    """

    _logger = None

    ## Constants for CT parsing
    SCT_VERSION_V1 = 0
    TLSEXT_hash_none = 0
    TLSEXT_hash_md5 = 1
    TLSEXT_hash_sha1 = 2
    TLSEXT_hash_sha224 = 3
    TLSEXT_hash_sha256 = 4
    TLSEXT_hash_sha384 = 5
    TLSEXT_hash_sha512 = 6
    TLSEXT_hash_gostr3411 = 237
    TLSEXT_hash_gostr34112012_256 = 238
    TLSEXT_hash_gostr34112012_512 = 239

    TLSEXT_signature_anonymous = 0
    TLSEXT_signature_rsa = 1
    TLSEXT_signature_dsa = 2
    TLSEXT_signature_ecdsa = 3
    TLSEXT_signature_gostr34102001 = 237
    TLSEXT_signature_gostr34102012_256 = 238
    TLSEXT_signature_gostr34102012_512 = 239

    ## This list needs to be periodically updated
    CT_LOG_MAP = {
        # Google - [ReadOnly]
        "aviator": {
            "id": "aPaY+B9kgr46jO65KB1M/HFRXWeT1ETRCmesu09P+8Q=",
            "url": "ct.googleapis.com/aviator",
        },
        # Google
        "icarus": {
            "id": "KTxRllTIOWW6qlD8WAfUt2+/WHopctykwwz05UVH9Hg=",
            "url": "ct.googleapis.com/icarus",
        },
        "pilot": {
            "id": "pLkJkLQYWBSHuxOizGdwCjw1mAT5G9+443fNDsgN3BA=",
            "url": "ct.googleapis.com/pilot",
        },
        "rocketeer": {
            "id": "7ku9t3XOYLrhQmkfq+GeZqMPfl+wctiDAMR7iXqo/cs=",
            "url": "ct.googleapis.com/rocketeer",
        },
        "skydiver": {
            "id": "u9nfvB+KcbWTlCOXqpJ7RzhXlQqrUugakJZkNo4e0YU=",
            "url": "ct.googleapis.com/skydiver",
        },
        "argon2018": {
            "id": "pFASaQVaFVReYhGrN7wQP2KuVXakXksXFEU+GyIQaiU=",
            "url": "ct.googleapis.com/logs/argon2018",
        },
        "argon2019": {
            "id": "Y/Lbzeg7zCzPC3KEJ1drM6SNYXePvXWmOLHHaFRL2I0=",
            "url": "ct.googleapis.com/logs/argon2019",
        },
        "argon2020": {
            "id": "sh4FzIuizYogTodm+Su5iiUgZ2va+nDnsklTLe+LkF4=",
            "url": "ct.googleapis.com/logs/argon2020",
        },
        "argon2021": {
            "id": "9lyUL9F3MCIUVBgIMJRWjuNNExkzv98MLyALzE7xZOM=",
            "url": "ct.googleapis.com/logs/argon2021",
        },
        "argon2022": {
            "id": "KXm+8J45OSHwVnOfY6V35b5XfZxgCvj5TV0mXCVdx4Q=",
            "url": "ct.googleapis.com/logs/argon2022",
        },
        "argon2023": {
            "id": "6D7Q2j71BjUy51covIlryQPTy9ERa+zraeF3fW0GvW4=",
            "url": "ct.googleapis.com/logs/argon2023",
        },
        "argon2024": {
            "id": "7s3QZNXbGs7FXLedtM0TojKHRny87N7DUUhZRnEftZs=",
            "url": "ct.googleapis.com/logs/us1/argon2024/",
        },
        "argon2025h1": {
            "id": "TnWjJ1yaEMM4W2zU3z9S6x3w4I4bjWnAsfpksWKaOd8=",
            "url": "ct.googleapis.com/logs/us1/argon2025h1/",
        },
        "argon2025h2": {
            "id": "EvFONL1TckyEBhnDjz96E/jntWKHiJxtMAWE6+WGJjo=",
            "url": "ct.googleapis.com/logs/us1/argon2025h2/",
        },
        "xenon2018": {
            "id": "sQzVWabWeEaBH335pRUyc5rEjXA76gMj2l04dVvArU4=",
            "url": "ct.googleapis.com/logs/xenon2018",
        },
        "xenon2019": {
            "id": "CEEUmABxUywWGQRgvPxH/cJlOvopLHKzf/hjrinMyfA=",
            "url": "ct.googleapis.com/logs/xenon2019",
        },
        "xenon2020": {
            "id": "B7dcG+V9aP/xsMYdIxXHuuZXfFeUt2ruvGE6GmnTohw=",
            "url": "ct.googleapis.com/logs/xenon2020",
        },
        "xenon2021": {
            "id": "fT7y+I//iFVoJMLAyp5SiXkrxQ54CX8uapdomX4i8Nc=",
            "url": "ct.googleapis.com/logs/xenon2021",
        },
        "xenon2022": {
            "id": "RqVV63X6kSAwtaKJafTzfREsQXS+/Um4havy/HD+bUc=",
            "url": "ct.googleapis.com/logs/xenon2022",
        },
        "xenon2023": {
            "id": "rfe++nz/EMiLnT2cHj4YarRnKV3PsQwkyoWGNOvcgoo=",
            "url": "ct.googleapis.com/logs/xenon2023",
        },
        "xenon2024": {
            "id": "dv+IPwq2+5VRwmHM9Ye6NLSkzbsp3GhCCp/mZ0xaOnQ=",
            "url": "ct.googleapis.com/logs/eu1/xenon2024/",
        },
        # DigiCert
        "digicert-ct1": {
            "id": "VhQGmi/XwuzT9eG9RLI+x0Z2ubyZEVzA75SYVdaJ0N0=",
            "url": "ct1.digicert-ct.com/log",
        },
        "digicert-ct2": {
            "id": "h3W/51l8+IxDmV+9827/Vo1HVjb/SrVgwbTq/16ggw8=",
            "url": "ct2.digicert-ct.com",
        },
        "yeti2018": {
            "id": "wRZK4Kdy0tQ5LcgKwQdw1PDEm96ZGkhAwfoHUWT2M2A=",
            "url": "yeti2018.ct.digicert.com/log",
        },
        "yeti2019": {
            "id": "4mlLribo6UAJ6IYbtjuD1D7n/nSI+6SPKJMBnd3x2/4=",
            "url": "yeti2019.ct.digicert.com/log",
        },
        "yeti2020": {
            "id": "8JWkWfIA0YJAEC0vk4iOrUv+HUfjmeHQNKawqKqOsnM=",
            "url": "yeti2020.ct.digicert.com/log",
        },
        "yeti2021": {
            "id": "XNxDkv7mq0VEsV6a1FbmEDf71fpH3KFzlLJe5vbHDso=",
            "url": "yeti2021.ct.digicert.com/log",
        },
        "yeti2022": {
            "id": "IkVFB1lVJFaWP6Ev8fdthuAjJmOtwEt/XcaDXG7iDwI=",
            "url": "yeti2022.ct.digicert.com/log",
        },
        "yeti2022-2": {
            "id": "BZwB0yDgB4QTlYBJjRF8kDJmr69yULWvO0akPhGEDUo=",
            "url": "yeti2022-2.ct.digicert.com/log",
        },
        "yeti2023": {
            "id": "Nc8ZG7+xbFe/D61MbULLu7YnICZR6j/hKu+oA8M71kw=",
            "url": "yeti2023.ct.digicert.com/log",
        },
        "yeti2024": {
            "id": "SLDja9qmRzQP5WoC+p0w6xxSActW3SyB2bu/qznYhHM=",
            "url": "yeti2024.ct.digicert.com/log",
        },
        "yeti2025": {
            "id": "fVkeEuF4KnscYWd8Xv340IdcFKBOlZ65Ay/ZDowuebg=",
            "url": "yeti2025.ct.digicert.com/log",
        },
        "nessie2018": {
            "id": "b/FBtWR+QiL37wUs7658If1gjifSr1pun0uKN9ZjPuU=",
            "url": "nessie2018.ct.digicert.com/log",
        },
        "nessie2019": {
            "id": "/kRhCLHQGreKYsz+q2qysrq/86va2ApNizDfLQAIgww=",
            "url": "nessie2019.ct.digicert.com/log",
        },
        "nessie2020": {
            "id": "xlKg7EjOs/yrFwmSxDqHQTMJ6ABlomJSQBujNioXxWU=",
            "url": "nessie2020.ct.digicert.com/log",
        },
        "nessie2021": {
            "id": "7sCV7o1yZA+S48O5G8cSo2lqCXtLahoUOOZHssvtxfk=",
            "url": "nessie2021.ct.digicert.com/log",
        },
        "nessie2022": {
            "id": "UaOw9f0BeZxWbbg3eI8MpHrMGyfL956IQpoN/tSLBeU=",
            "url": "nessie2022.ct.digicert.com/log",
        },
        "nessie2023": {
            "id": "s3N3B+GEUPhjhtYFqdwRCUp5LbFnDAuH3PADDnk2pZo=",
            "url": "nessie2023.ct.digicert.com/log",
        },
        "nessie2024": {
            "id": "c9meiRtMlnigIH1HneayxhzQUV5xGSqMa4AQesF3crU=",
            "url": "nessie2024.ct.digicert.com/log",
        },
        "nessie2025": {
            "id": "5tIxY0B3jMEQQQbXcbnOwdJA9paEhvu6hzId/R43jlA=",
            "url": "nessie2025.ct.digicert.com/log",
        },
        # Symantec [Retired]
        "symantec-ct": {
            "id": "3esdK3oNT6Ygi4GtgWhwfi6OnQHVXIiNPRHEzbbsvsw=",
            "url": "ct.ws.symantec.com",
        },
        "deneb": {
            "id": "p85KTmIH4K3e5f2qSx+GdodntdACpV1HMQ5+ZwqV6rI=",
            "url": "deneb.ws.symantec.com",
        },
        "sirius": {
            "id": "FZcEiNe5l6Bb61JRKt7o0ui0oxZSZBIan6v71fha2T8=",
            "url": "sirius.ws.symantec.com",
        },
        "vega": {
            "id": "vHjh38X2PGhGSTNNoQ+hXwl5aSAJwIG08/aRfz7ZuKU=",
            "url": "vega.ws.symantec.com",
        },
        # Comodo
        "mammoth": {
            "id": "b1N2rDHwMRnYmQCkURX/dxUcEdkCwQApBo2yCJo32RM=",
            "url": "mammoth.ct.comodo.com",
        },
        "sabre": {
            "id": "VYHUwhaQNgFK6gubVzxT8MDkOHhwJQgXL6OqHQcT0ww=",
            "url": "sabre.ct.comodo.com",
        },
        # CloudFlare [no longer in Chrome]
        "nimbus2017": {
            "id": "H7w24ALt6X9AGZ6Gs1c7ikIX2AGHdGrQ2gOgYFTSDfQ=",
            "url": "ct.cloudflare.com/logs/nimbus2017",
        },
        "nimbus2018": {
            "id": "23Sv7ssp7LH+yj5xbSzluaq7NveEcYPHXZ1PN7Yfv2Q=",
            "url": "ct.cloudflare.com/logs/nimbus2018",
        },
        "nimbus2019": {
            "id": "dH7agzGtMxCRIZzOJU9CcMK//V5CIAjGNzV55hB7zFY=",
            "url": "ct.cloudflare.com/logs/nimbus2019",
        },
        # CloudFlare [active]
        "nimbus2020": {
            "id": "Xqdz+d9WwOe1Nkh90EngMnqRmgyEoRIShBh1loFxRVg=",
            "url": "ct.cloudflare.com/logs/nimbus2020",
        },
        "nimbus2021": {
            "id": "RJRlLrDuzq/EQAfYqP4owNrmgr7YyzG1P9MzlrW2gag=",
            "url": "ct.cloudflare.com/logs/nimbus2021",
        },
        "nimbus2022": {
            "id": "QcjKsd8iRkoQxqE6CUKHXk4xixsD6+tLx2jwkGKWBvY=",
            "url": "ct.cloudflare.com/logs/nimbus2022",
        },
        "nimbus2023": {
            "id": "ejKMVNi3LbYg6jjgUh7phBZwMhOFTTvSK8E6V6NS61I=",
            "url": "ct.cloudflare.com/logs/nimbus2023",
        },
        "nimbus2024": {
            "id": "2ra/az+1tiKfm8K7XGvocJFxbLtRhIU0vaQ9MEjX+6s=",
            "url": "ct.cloudflare.com/logs/nimbus2024",
        },
        # Let's Encrypt
        "le-oak2021": {
            "id": "lCC8Ho7VjWyIcx+CiyIsDdHaTV5sT5Q9YdtOL1hNosI=",
            "url": "oak.ct.letsencrypt.org/2021",
        },
        "le-oak2022": {
            "id": "36Veq2iCTx9sre64X04+WurNohKkal6OOxLAIERcKnM=",
            "url": "oak.ct.letsencrypt.org/2022",
        },
        "le-oak2023": {
            "id": "tz77JN+cTbp18jnFulj0bF38Qs96nzXEnh0JgSXttJk=",
            "url": "oak.ct.letsencrypt.org/2023",
        },
        "le-oak2024h1": {
            "id": "O1N3dT4tuYBOizBbBv5AO2fYT8P0x70ADS1yb+H61Bc=",
            "url": "oak.ct.letsencrypt.org/2024h1",
        },
        "le-oak2024h2": {
            "id": "PxdLT9ciR1iUHWUchL4NEu2QN38fhWrrwb8ohez4ZG4=",
            "url": "oak.ct.letsencrypt.org/2024h2",
        },
        "le-oak2025h1": {
            "id": "ouMK5EXvva2bfjjtR2d3U9eCW4SU1yteGyzEuVCkR+c=",
            "url": "oak.ct.letsencrypt.org/2025h1/",
        },
        "le-oak2025h2": {
            "id": "DeHyMCvTDcFAYhIJ6lUu/Ed0fLHX6TDvDkIetH5OqjQ=",
            "url": "oak.ct.letsencrypt.org/2025h2/",
        },
        # Misc [Retired]
        "venafi-ctlog-gen2": {
            "id": "AwGd8/2FppqOvR+sxtqbpz5Gl3T+d/V5/FoIuDKMHWs=",
            "url": "ctlog-gen2.api.venafi.com",
        },
        "cnnic-ctserver": {
            "id": "pXesnO11SN2PAltnokEInfhuD0duwgPC7L7bGF8oJjg=",
            "url": "ctserver.cnnic.cn",
        },
        # Not in Chrome and/or supported.
        "gdca-log": {
            "id": "cX6nQgl1voSicjVT8Xd8Jt1Rr04QIUQJTZAZtGL7Zmg=",
            "url": "log.gdca.com.cn",
        },
        "gdca-log2": {
            "id": "FDCNkMzQMBNQBcAcpSbYHoTodiTjm2JI4I9ySuo7tCo=",
            "url": "log2.gdca.com.cn",
        },
        "venafi-ctlog": {
            "id": "rDua7X+pZ0dXFZ5tfVdWcvnZgQCUHpve/+yhMTt1eC0=",
            "url": "ctlog.api.venafi.com",
        },
        "gdca-ct": {
            "id": "Gjj3bo1vS9GxMAFS0XV1B88iKrHDdVZRF4sBbmGyY0o=",
            "url": "ct.gdca.com.cn",
        },
        "gdca-ctlog": {
            "id": "kkow+Qkzb/Q11pk6EKx1osZBco5/wtZZrmGI/61AzgE=",
            "url": "ctlog.gdca.com.cn",
        },
        "daedalus": {
            "id": "HQJLjrFJizRN/YfqPvwJlvdQbyNdHUlwYaR3PEOcJfs=",
            "url": "ct.googleapis.com/daedalus",
        },
        "submariner": {
            "id": "qJnYeAySkKr0YvMYgMz71SRR6XDQ+/WR73Ww2ZtkVoE=",
            "url": "ct.googleapis.com/submariner",
        },
        "wosign-ctlog": {
            "id": "QbLcLonmPOSvG6e7Kb9oxt7m+fHMBH4w3/rjs7olkmM=",
            "url": "ctlog.wosign.com",
        },
        "izenpe-ct": {
            "id": "iUFEnHB0Lga5/JznsRa6ACSqNtWa9E8CBEBPAPfqhWY=",
            "url": "ct.izenpe.eus",
        },
        "startssl-ct": {
            "id": "NLtq1sPfnAPuqKSZ/3iRSGydXlysktAfe/0bzhnbSO8=",
            "url": "ct.startssl.com",
        },
    }

    def _log(self):
        """
        Get the log
        """
        return logging.getLogger(__name__)

    def __init__(self, log_level=None):
        self._logger = self._log()
        if log_level is not None:
            self._logger.setLevel(log_level)

    def __find_ct_log_url_by_id(self, logid):
        for key in self.CT_LOG_MAP:
            if self.CT_LOG_MAP[key]["id"] == base64.b64encode(logid).decode("utf-8"):
                return self.CT_LOG_MAP[key]["url"]

    def __add_co_array_value(self, cert_object, name, value):
        """
        Helper function to dynamically add values to cert_object
        """
        if name in cert_object:
            cert_object[name].append(value)
        else:
            cert_object[name] = []
            cert_object[name].append(value)

    def __get_dn_values(self, cert_object, names, source):
        """
        This function enumerates the Name OIDs for the subject and the issuer.
        The results are added to the cert_object
        """
        oid_names = []
        for p in dir(NameOID):
            if not p.startswith("__"):
                oid_names.append(p)

        for entry in names:
            for oid in oid_names:
                if entry.oid == getattr(NameOID, oid):
                    self.__add_co_array_value(
                        cert_object, source + "_" + oid.lower(), entry.value
                    )
                    continue

    def __get_signature_algorithm(self, cert_object, sig_oid):
        """
        Get the signature algorithm as identified by the certificate
        The naming convention mirrors the original Python 2 Certificate Transparency library
        """
        for p in dir(SignatureAlgorithmOID):
            if not p.startswith("__"):
                if sig_oid == getattr(SignatureAlgorithmOID, p):
                    cert_object["signature_algorithm"] = p.replace("WITH_", "")
                    return

        self._logger.warning(
            "WARNING: Unrecognized Signature Alogrithm: " + str(sig_oid)
        )
        cert_object["signature_algorithm"] = ""

    def __get_alternative_names(self, cert_object, extensions):
        """
        Obtain subject alternative names from the Python cryptography extensions object.
        """
        cert_object["subject_dns_names"] = []
        cert_object["subject_ip_addresses"] = []
        try:
            alt_names = extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            new_names = alt_names.value.get_values_for_type(x509.DNSName)
            cert_object["subject_dns_names"] = new_names
            new_ips = alt_names.value.get_values_for_type(x509.IPAddress)
            for ip in new_ips:
                cert_object["subject_ip_addresses"].append(str(ip))
        except ExtensionNotFound:
            self._logger.debug("No alternative names")

    def __get_key_usages(self, cert_object, extensions):
        """
        This gets the key usages from the Python cryptography
        extensions object.
        """
        cert_object["key_usages"] = []
        try:
            key_usage = extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
            usages = key_usage.value
            if usages.digital_signature:
                cert_object["key_usages"].append("digital_signature")
            if usages.content_commitment:
                cert_object["key_usages"].append("content_commitment")
            if usages.key_encipherment:
                cert_object["key_usages"].append("key_encipherment")
            if usages.data_encipherment:
                cert_object["key_usages"].append("data_encipherment")
            if usages.key_agreement:
                cert_object["key_usages"].append("key_agreerment")
                if usages.encipher_only is not None:
                    cert_object["key_usages"].append("encipher_only")
                if usages.decipher_only is not None:
                    cert_object["key_usages"].append("decipher_only")
            if usages.key_cert_sign:
                cert_object["key_usages"].append("key_cert_sign")
            if usages.crl_sign:
                cert_object["key_usages"].append("crl_sign")
        except ExtensionNotFound:
            self._logger.debug("No key usages")

    def __get_extended_key_usages(self, cert_object, extensions):
        """
        Obtain the extended key usages from the Python cryptography extensions object.
        """
        cert_object["extended_key_usages"] = []
        try:
            ext_key_usage = extensions.get_extension_for_oid(
                ExtensionOID.EXTENDED_KEY_USAGE
            )
            for usage in ext_key_usage.value:
                if usage in _OID_NAMES:
                    cert_object["extended_key_usages"].append(_OID_NAMES[usage])
                else:
                    cert_object["extended_key_usages"].append(usage.dotted_string)
        except ExtensionNotFound:
            self._logger.debug("No extended key usage")

    def __get_basic_constraints(self, cert_object, extensions):
        """
        Obtain the basic_constraints from the Python cryptography extensions object.
        """
        try:
            constraints = extensions.get_extension_for_oid(
                ExtensionOID.BASIC_CONSTRAINTS
            )
            cert_object["basic_constraint_ca"] = constraints.value.ca
            cert_object["basic_constraint_path_length"] = constraints.value.path_length
        except ExtensionNotFound:
            self._logger.debug("No basic constraints")

    def __SCT_get_signature_nid(self, version, hash_alg, sig_alg):
        """
        Get the associated signature algorith string
        """
        if version == self.SCT_VERSION_V1 and hash_alg == self.TLSEXT_hash_sha256:
            # Formerly a switch (sig_alg) returning the mappings below:
            if sig_alg == self.TLSEXT_signature_ecdsa:
                # NID_ecdsa_with_SHA256
                return "ecdsa-with-SHA256"
            # case TLSEXT_signature_rsa:
            elif sig_alg == self.TLSEXT_signature_rsa:
                # NID_sha256WithRSAEncryption
                return "sha256WithRSAEncryption"
            # default:
            else:
                # NID_undef;
                return None

        return None

    def __splitBytes(self, buf, count):
        """
        Split buf into two strings (part1, part2) where part1 has count bytes.
        @raises ValueError if buf is too short.
        """
        if len(buf) < count:
            raise ValueError(
                (
                    "Malformed structure encountered when parsing SCT, "
                    + "expected %d bytes, got only %d"
                )
                % (count, len(buf))
            )

        return buf[:count], buf[count:]

    def __parse_sct(self, asn1_sctList, sct_type):
        """
        Parse the SCT signature record.

        The Python cryptography library provides some parsing functionality but
        it does not provide details on the signature itself. This method provides
        the complete details.
        """
        header, header_data = self.__splitBytes(asn1_sctList, 2)
        if header[1] ^ 0x80 == 1:
            _, data = self.__splitBytes(header_data, 1)
        elif header[1] ^ 0x80 == 2:
            _, data = self.__splitBytes(header_data, 2)
        else:
            self._logger.error("Unexpected SCTS header length")
            raise ValueError("Unexpected SCTS header length")
        scts = []

        # Length is an unsigned short
        packed_len, data = self.__splitBytes(data, 2)
        total_len = struct.unpack("!H", packed_len)[0]
        if len(data) != total_len:
            self._logger.error(
                "SCT ERROR: data length: "
                + str(len(data))
                + " Total length: "
                + str(total_len)
            )
            raise ValueError("Malformed length of SCT list")

        bytes_read = 0

        while bytes_read < total_len:
            packed_len, data = self.__splitBytes(data, 2)
            sct_len = struct.unpack("!H", packed_len)[0]

            bytes_read += sct_len + 2
            sct_data, data = self.__splitBytes(data, sct_len)
            packed_vlt, sct_data = self.__splitBytes(sct_data, 41)
            version, logid, timestamp = struct.unpack("!B32sQ", packed_vlt)
            timestamp = datetime.fromtimestamp(timestamp / 1000.0)

            packed_len, sct_data = self.__splitBytes(sct_data, 2)
            ext_len = struct.unpack("!H", packed_len)[0]
            extensions, sct_data = self.__splitBytes(sct_data, ext_len)

            hash_alg, sig_alg, sig_len = struct.unpack("!BBH", sct_data[:4])
            signature = sct_data[4:]
            if len(signature) != sig_len:
                raise ValueError(
                    ("SCT signature has incorrect length, " + "expected %d, got %d")
                    % (sig_len, len(signature))
                )

            scts.append(
                {
                    "log_name": self.__find_ct_log_url_by_id(logid),
                    "log_id": base64.b64encode(logid).decode("utf-8"),
                    "sct_type": sct_type,
                    "version": version,
                    "timestamp": timestamp,
                    "hash_alg": hash_alg,
                    "sig_alg": sig_alg,
                    "sig_alg_name": self.__SCT_get_signature_nid(
                        version, hash_alg, sig_alg
                    ),
                    "signature": ":".join("{:02x}".format(c) for c in signature),
                    "extensions": extensions.decode("utf-8"),
                }
            )

        return scts

    def __get_certificate_transparency(self, cert_object, openssl_cert):
        """
        Extract the SCTS extension records using pyOpenSSL and manual parsing.s
        """
        cert_object["scts"] = []
        for ext_index in range(openssl_cert.get_extension_count()):
            ext = openssl_cert.get_extension(ext_index)
            if ext.get_short_name().decode("utf-8") == "ct_precert_scts":
                cert_object["scts"] = self.__parse_sct(ext.get_data(), "precert")
            elif ext.get_short_name().decode("utf-8") == "ct_cert_scts":
                cert_object["scts"] = self.__parse_sct(ext.get_data(), "cert")

    def __get_extensions(self, cert_object, extensions, openssl_cert):
        """
        Process certificate extensions looking for CT extensions
        """

        self.__get_alternative_names(cert_object, extensions)
        self.__get_key_usages(cert_object, extensions)
        self.__get_extended_key_usages(cert_object, extensions)
        self.__get_basic_constraints(cert_object, extensions)
        self.__get_certificate_transparency(cert_object, openssl_cert)

    def __get_raw_version(self, cert):
        """
        The public_bytes version returns with the BEGIN/END headers.
        This function returns just the base64 encoded data
        """
        full_text = cert.public_bytes(Encoding.PEM).decode("utf-8")
        temp_string = full_text[full_text.index("\n") + 1 :]
        temp_string = temp_string[: temp_string.rfind("\n")]
        temp_string = temp_string[: temp_string.rfind("\n")]
        final_string = temp_string.replace("\n", "")
        return final_string

    def __check_self_signed(self, cert_object, cert):
        """
        Check to see whether the provided certificate is self signed.
        """
        cert_object["isSelfSigned"] = False
        if cert.subject == cert.issuer:
            cert_object["isSelfSigned"] = True

    def __create_mongodb_structure(self, cert, openssl_cert):
        """
        Create a cert_object in the same form as the legacy Python2 format
        used with the Google certificate transparency libraries.
        """
        cert_object = {}
        cert_object["fingerprint_sha1"] = binascii.hexlify(
            cert.fingerprint(hashes.SHA1())
        ).decode("utf-8")
        cert_object["fingerprint_sha256"] = binascii.hexlify(
            cert.fingerprint(hashes.SHA256())
        ).decode("utf-8")

        try:
            cert_object["not_before"] = cert.not_valid_before
        except ValueError:
            self._logger.warning("WARNING: Invalid not_before date")

        try:
            cert_object["not_after"] = cert.not_valid_after
        except ValueError:
            self._logger.warning("WARNING: Invalid not_after date")
            return None

        # MongoDB can only handle up to 8 byte ints which some serial numbers exceed.
        # Convert to hex instead which matches OpenSSL -text
        hex_serial_number = hex(cert.serial_number)[2:]
        if len(hex_serial_number) % 2 == 1:
            hex_serial_number = "0" + hex_serial_number
        cert_object["serial_number"] = ":".join(
            [
                hex_serial_number[start : start + 2]
                for start in range(0, len(hex_serial_number), 2)
            ]
        )

        cert_object["raw"] = self.__get_raw_version(cert)
        try:
            cert_object["isExpired"] = openssl_cert.has_expired()
        except RuntimeError:
            self._logger.warning(
                "WARNING: Could not determine if the certificate is expired"
            )

        try:
            cert_object["full_certificate"] = crypto.dump_certificate(
                crypto.FILETYPE_TEXT, openssl_cert
            ).decode("utf-8")
        except UnicodeDecodeError:
            self._logger.warning(
                "WARNING: Couldn't decode text as UTF-8 for: "
                + cert_object["fingerprint_sha256"]
            )
            cert_object["full_certificate"] = ""

        try:
            self.__get_dn_values(cert_object, cert.subject, "subject")
        except ValueError:
            # The X509 parser struggles with some certificate's subject
            # Without a subject, we can't do much with the cert
            self._logger.warning("WARNING: Could not parse subject for certificate")
            return None

        # This is for legacy compliance where the field was originally called
        # subject_common_names (plural)
        swap = cert_object.pop("subject_common_name", [])
        cert_object["subject_common_names"] = swap

        self.__get_dn_values(cert_object, cert.issuer, "issuer")
        self.__check_self_signed(cert_object, cert)
        self.__get_signature_algorithm(cert_object, cert.signature_algorithm_oid)

        try:
            self.__get_extensions(cert_object, cert.extensions, openssl_cert)
        except ValueError as ve:
            # The X509 parser struggles with some certificates
            # Python cryptography will throw an error if the path_length is not None when ca is False
            # There could also be an issue with parsing SCTS entries
            self._logger.warning(
                "WARNING: Could not parse extensions for certificate due to ValueError."
            )
            self._logger.warning("Value error: " + str(ve))
            return None
        except x509.DuplicateExtension:
            # Python cryptography will error out if it finds a duplicate extension
            self._logger.warning(
                "WARNING: Could not parse the extension due to Duplicate Extensions"
            )
            return None
        except AssertionError:
            # Python cryptography thinks that the certificate is not well formed.
            self._logger.warning(
                "WARNING: Python cryptography threw an Assertion Error"
            )
            return None

        return cert_object

    def __open_file(self, filename):
        """
        Read a certificate in from an OS file
        """
        bytes = None
        try:
            with open(filename, "rb") as f:
                bytes = f.read()
        except OSError as err:
            self._logger.error("OS error': {0}".format(err))
        except:
            self._logger.error("Unexpected error: " + str(sys.exc_info()[0]))

        return bytes

    def __parse(self, data, certSource):
        """
        Once the data is in a bytes format, transform it using cryptography and pyOpenSSL
        Then, create a cert_object to return to the original caller.
        """
        cert = None
        try:
            cert = x509.load_pem_x509_certificate(data, default_backend())
            openssl_cert = crypto.load_certificate(crypto.FILETYPE_PEM, data)
        except:
            self._logger.debug("WARNING: Could not parse certificate as a PEM file")

            try:
                cert = x509.load_der_x509_certificate(data, default_backend())
                openssl_cert = crypto.load_certificate(crypto.FILETYPE_ASN1, data)
            except Exception as e:
                self._logger.error(
                    "ERROR: Could not parse certificate as a PEM or DER file - "
                    + str(e)
                )
                return None

        cert_object = self.__create_mongodb_structure(cert, openssl_cert)
        if cert_object is None:
            return None

        cert_object["sources"] = []
        cert_object["sources"].append(certSource)

        cert_object["marinus_createdate"] = datetime.now()
        cert_object["marinus_updated"] = datetime.now()

        return cert_object

    def parse_file(self, file_name, certSource):
        """
        Parse the filename that is provided from the given certificate source
        Returns None if there is an error.
        """
        data = self.__open_file(file_name)
        if data == None:
            self._logger.error("ERROR Could not parse: " + file_name)
            return None

        cert_object = self.__parse(data, certSource)
        return cert_object

    def parse_data(self, cert_data, certSource, addHeaders=False):
        """
        Parse the provided base64 encoded string or DER encoded bytes.
        For PEM files, the parser assumes that the header and footer exists.
        If you have the PEM base64 without headers, addHeaders will add them for you.
        Returns None if there is an error.
        """
        if addHeaders:
            data = bytes(
                "-----BEGIN CERTIFICATE-----\n"
                + cert_data
                + "\n-----END CERTIFICATE-----",
                "UTF-8",
            )
        else:
            if type(cert_data) is str:
                data = bytes(cert_data, "utf-8")
            else:
                data = bytes(cert_data)

        cert_object = self.__parse(data, certSource)
        return cert_object
