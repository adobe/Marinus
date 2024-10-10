#!/usr/bin/python3

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
This class performs DNS requests via Google DNS over HTTPS

https://developers.google.com/speed/public-dns/docs/dns-over-https
"""

import json
import logging

import requests
from requests.adapters import HTTPAdapter
from urllib3.util import Retry


class GoogleDNS(object):
    DNS_TYPES = {
        "a": 1,
        "ns": 2,
        "cname": 5,
        "soa": 6,
        "ptr": 12,
        "hinfo": 13,
        "mx": 15,
        "txt": 16,
        "rp": 17,
        "key": 25,
        "aaaa": 28,
        "loc": 29,
        "srv": 33,
        "naptr": 35,
        "kx": 36,
        "dname": 39,
        "ds": 43,
        "sshfp": 44,
        "ipseckey": 45,
        "rrsig": 46,
        "nsec": 47,
        "dnskey": 48,
        "dhcid": 49,
        "nsec3": 50,
        "nsec3param": 51,
        "tlsa": 52,
        "smimea": 53,
        "hip": 55,
        "openpgpkey": 61,
        "svcb": 64,
        "https": 65,
        "spf": 99,
        "tkey": 249,
        "tsig": 250,
        "any": 255,
        "uri": 256,
        "caa": 257,
        "ta": 32768,
        "dlv": 32769,
        "apexalias": 65282,  # This is not an RFC specified DNS type. It is used to indicate the apex record by some DNS implementations.
    }

    @staticmethod
    def fetch_DNS_records(
        host, dns_type=None, alternative_search=False, log_level=None
    ):
        """
        Use Google DNS over HTTPS to lookup host
        DNS Type mappings: "a":1, "ns":2, "cname":5, "soa":6, "ptr":12, "hinfo": 13, "mx": 15, "txt":16, "aaaa":28, "srv":33,
                           "naptr": 35, "ds": 43, "rrsig": 46, "dnskey": 48, "spf": 99, "any": 255
        It should be noted, that a DNS query with a specified dns_type will return only the immediate answer.
        However, a request without a dns_type will be recursive for queries such as cname records.
        Therefore, you would get a result array such as:
        [{"fqdn": "cdn.example.org", "type": "cname", "value": "example.amazonaws.com"}, {"fqdn": "example.amazonaws.com", "type": "1", "value": "1.2.3.4"}]

        :param host: The host
        :param dns_type: Either a string (e.g. "AAAA") or the corresponding number for that type.
        :param alternative_search: If a search for the initial DNS type fails, then try to look up the host regardless of DNS type (Only for A, CNAME, and AAAA)
        :param log_level: The log level to use for logging
        :return: An array of results containing the "fqdn", type", and "value" parameters or [] if nothing matched
        """

        def _requests_retry_session(
            retries=5,
            backoff_factor=7,
            status_forcelist=[408, 500, 502, 503, 504],
            session=None,
        ):
            """
            A Closure method for this static method.
            """
            session = session or requests.Session()
            retry = Retry(
                total=retries,
                read=retries,
                connect=retries,
                backoff_factor=backoff_factor,
                status_forcelist=status_forcelist,
            )
            adapter = HTTPAdapter(max_retries=retry)
            session.mount("http://", adapter)
            session.mount("https://", adapter)
            return session

        if host is None or host == "":
            return []

        url = "https://dns.google.com/resolve?name=" + host

        if dns_type is not None:
            url = url + "&type=" + str(dns_type)

        logger = logging.getLogger(__name__)
        if log_level is not None:
            logger.setLevel(log_level)

        try:
            req = _requests_retry_session().get(url, timeout=120)
        except Exception as ex:
            logger.error("Google DNS request attempts failed for " + str(host) + "!")
            logger.error(str(ex))
            return None

        if req.status_code != 200:
            logger.debug("HTTP Error looking up: " + host)
            return None

        nslookup_results = json.loads(req.text)

        # Status 3 is NXDomain or non-existant domain.
        # This happens a lot with in.addr.arpa queries and dead DNS records.
        if nslookup_results["Status"] == 3:
            logger.debug("NXDomain status error looking up: " + host)
            return []
        elif nslookup_results["Status"] == 2:
            logger.warning("SERVFAIL status error looking up: " + host)
            return None
        elif nslookup_results["Status"] != 0:
            # All other status codes are defined here:
            # https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6
            logger.warning(
                "Status error "
                + str(nslookup_results["Status"])
                + " when looking up: "
                + host
            )
            return None

        if "Answer" not in nslookup_results:
            # This can happen when the DNS record is not found in a condition that is separate
            # from NXDomain. This sometimes occurs when a DNS record exists for the FQDN but
            # it exists as a separate type
            # Example response:
            # {"Status":0,"TC":false,"RD":true,"RA":true,"AD":false,"CD":false,"Question":[{"name":"foo.bar.org.","type":1}],
            # "Authority":[{...}]}, {"Comment": "Response from 1.2.3.4."}

            logger.warning("Could not find Answer in DNS result for " + host)
            # logger.warning("Answer not found in: " + str(req.text))

            # If alternative search is enabled, then try to look up the host with a different DNS type
            if (
                alternative_search
                and dns_type is not None
                and (dns_type == 1 or dns_type == 5 or dns_type == 28)
            ):
                results = GoogleDNS.fetch_DNS_records(host)
                return results

            return None

        results = []
        for answer in nslookup_results["Answer"]:
            if answer["type"] == 1:
                results.append(
                    {"fqdn": answer["name"][:-1], "type": "a", "value": answer["data"]}
                )
            elif answer["type"] == 2:
                results.append(
                    {
                        "fqdn": answer["name"][:-1],
                        "type": "ns",
                        "value": answer["data"][:-1],
                    }
                )
            elif answer["type"] == 5:
                results.append(
                    {
                        "fqdn": answer["name"][:-1],
                        "type": "cname",
                        "value": answer["data"][:-1],
                    }
                )
            elif answer["type"] == 6:
                results.append(
                    {
                        "fqdn": answer["name"][:-1],
                        "type": "soa",
                        "value": answer["data"],
                    }
                )
            elif answer["type"] == 12:
                results.append(
                    {
                        "fqdn": answer["name"][:-1],
                        "type": "ptr",
                        "value": answer["data"][:-1],
                    }
                )
            elif answer["type"] == 13:
                results.append(
                    {
                        "fqdn": answer["name"][:-1],
                        "type": "hinfo",
                        "value": answer["data"],
                    }
                )
            elif answer["type"] == 15:
                results.append(
                    {"fqdn": answer["name"][:-1], "type": "mx", "value": answer["data"]}
                )
            elif answer["type"] == 16:
                results.append(
                    {
                        "fqdn": answer["name"][:-1],
                        "type": "txt",
                        "value": answer["data"],
                    }
                )
            elif answer["type"] == 28:
                results.append(
                    {
                        "fqdn": answer["name"][:-1],
                        "type": "aaaa",
                        "value": answer["data"],
                    }
                )
            elif answer["type"] == 33:
                results.append(
                    {
                        "fqdn": answer["name"][:-1],
                        "type": "srv",
                        "value": answer["data"],
                    }
                )
            elif answer["type"] == 35:
                results.append(
                    {
                        "fqdn": answer["name"][:-1],
                        "type": "naptr",
                        "value": answer["data"],
                    }
                )
            elif answer["type"] == 43:
                results.append(
                    {"fqdn": answer["name"][:-1], "type": "ds", "value": answer["data"]}
                )
            elif answer["type"] == 46:
                results.append(
                    {
                        "fqdn": answer["name"][:-1],
                        "type": "rrsig",
                        "value": answer["data"],
                    }
                )
            else:
                logger.warning("Unrecognized type: " + str(answer["type"]))

        return results
