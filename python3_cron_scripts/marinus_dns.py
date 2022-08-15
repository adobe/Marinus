#!/usr/bin/python3

# Copyright 2019 Adobe. All rights reserved.
# This file is licensed to you under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License. You may obtain a copy
# of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR REPRESENTATIONS
# OF ANY KIND, either express or implied. See the License for the specific language
# governing permissions and limitations under the License.

"""
This script attempts to flush out additional records into two ways.
First, it performs searches for an expanded set of DNS types from the zone record.
Second, it attempts to find additional SOA delegations based on patterns in FQDNs.
Sonar records are not always complete since they are not as focused on a single company.
"""

import logging
import re
import time
from datetime import datetime

import requests
from libs3 import DNSManager, GoogleDNS, JobsManager, MongoConnector
from libs3.LoggingUtil import LoggingUtil
from libs3.ZoneManager import ZoneManager
from tld import get_fld


def get_fld_from_value(value, zone):
    """
    Get the root domain (FLD) for the provided value
    """
    res = get_fld(value, fix_protocol=True, fail_silently=True)
    if res is None:
        return zone

    return res


def find_sub_zones(all_dns):
    """
    Search for FQDNs that are two or more subdomains deep.
    For instance, the script would ignore images.example.org.
    However, it would pay attention to customer.images.example.org and bob.customer.images.example.org.
    The goal is to see if images.example.org or customer.images.example.org have different SOA records.
    """
    dns_regex = re.compile(r".+\\..+\\..+\\..+")

    sub_zone_results = all_dns.find({"fqdn": {"$regex": dns_regex}}, {"fqdn": 1})

    qualifiers = []
    for domain in sub_zone_results:
        parts = domain["fqdn"].split(".")
        result = ""
        for i in reversed(range(len(parts))):
            if i == len(parts) - 1:
                result = parts[i]
            elif i > len(parts) - 3:
                result = parts[i] + "." + result
            elif i != 0:
                result = parts[i] + "." + result
                if result not in qualifiers:
                    qualifiers.append(result)
    return qualifiers


def main(logger=None):
    """
    Begin Main...
    """
    if logger is None:
        logger = LoggingUtil.create_log(__name__)

    now = datetime.now()
    print("Starting: " + str(now))
    logger.info("Starting...")

    dns_types = {
        "a": 1,
        "ns": 2,
        "cname": 5,
        "soa": 6,
        "ptr": 12,
        "hinfo": 13,
        "mx": 15,
        "txt": 16,
        "aaaa": 28,
        "srv": 33,
        "naptr": 35,
        "ds": 43,
        "rrsig": 46,
        "dnskey": 48,
    }

    mongo_connector = MongoConnector.MongoConnector()
    all_dns_collection = mongo_connector.get_all_dns_connection()
    jobs_manager = JobsManager.JobsManager(mongo_connector, "marinus_dns")
    jobs_manager.record_job_start()

    dns_manager = DNSManager.DNSManager(mongo_connector)

    zones = ZoneManager.get_distinct_zones(mongo_connector)

    google_dns = GoogleDNS.GoogleDNS()

    for zone in zones:
        time.sleep(1)
        for dtype, dnum in dns_types.items():
            result = google_dns.fetch_DNS_records(zone, dnum)

            if result == []:
                logger.debug("No records found for " + zone)
            else:
                new_record = result[0]
                new_record["status"] = "confirmed"
                new_record["zone"] = zone
                new_record["created"] = datetime.now()
                logger.debug("Found " + dtype + " for: " + zone)
                dns_manager.insert_record(new_record, "marinus")

    logger.info("Starting SOA Search")

    soa_searches = find_sub_zones(all_dns_collection)
    for entry in soa_searches:
        time.sleep(1)
        result = google_dns.fetch_DNS_records(zone, dns_types["soa"])
        if result != []:
            new_record = result[0]
            new_record["status"] = "confirmed"
            new_record["zone"] = get_fld_from_value(entry, "")
            new_record["created"] = datetime.now()
            logger.debug("Found SOA: " + entry)
            if new_record["zone"] != "":
                dns_manager.insert_record(new_record, "marinus")

    jobs_manager.record_job_complete()

    now = datetime.now()
    print("Complete: " + str(now))
    logger.info("Complete.")


if __name__ == "__main__":
    logger = LoggingUtil.create_log(__name__)

    try:
        main(logger)
    except Exception as e:
        logger.error("FATAL: " + str(e), exc_info=True)
        exit(1)
