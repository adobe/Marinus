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
This script extracts domain names from all the MX records collected by Marinus.
The script will then use Google HTTPS over DNS to get their DNS records and store them.
"""

import json
import logging
import time
from datetime import datetime

import requests
from libs3 import DNSManager, GoogleDNS, JobsManager, MongoConnector
from libs3.LoggingUtil import LoggingUtil
from libs3.ZoneManager import ZoneManager


def add_to_list(str_to_add, dns_names):
    """
    This will add a string to the dns_names array if it does not exist.
    It will then return the index of the string within the Array
    """
    if str_to_add.lower() not in dns_names:
        dns_names.append(str_to_add.lower())
    return dns_names.index(str_to_add.lower())


def add_to_round_two(str_to_add, round_two):
    """
    This will add a string to the round_two array if it does not exist.
    It will then return the index of the string within the Array
    """
    if str_to_add.lower() not in round_two:
        round_two.append(str_to_add.lower())
    return round_two.index(str_to_add.lower())


def is_tracked_zone(cname, zones):
    """
    Is the root domain for the provided cname one of the known domains?
    """

    for zone in zones:
        if cname.endswith("." + zone) or cname == zone:
            return True
    return False


def get_tracked_zone(name, zones):
    """
    What is the tracked zone for the provided hostname?
    """
    for zone in zones:
        if name.endswith("." + zone) or name == zone:
            return zone
    return None


def extract_mx_names(dns_names, dns_manager):
    """
    Extract the domain names from MX DNS records.
    """

    res = dns_manager.find_multiple({"type": "mx"}, None)

    for result in res:
        name = result["value"]
        if " " in result["value"]:
            parts = result["value"].split(" ")
            name = parts[1]
            if name.endswith("."):
                name = name[:-1]

        add_to_list(name, dns_names)


def main(logger=None):
    """
    Begin Main...
    """
    if logger is None:
        logger = LoggingUtil.create_log(__name__)

    now = datetime.now()
    print("Starting: " + str(now))
    logger.info("Starting...")

    mongo_connector = MongoConnector.MongoConnector()
    dns_manager = DNSManager.DNSManager(mongo_connector)
    jobs_manager = JobsManager.JobsManager(mongo_connector, "extract_mx_domains")
    google_dns = GoogleDNS.GoogleDNS()

    jobs_manager.record_job_start()

    dns_names = []
    round_two = []

    zones = ZoneManager.get_distinct_zones(mongo_connector)

    # Collect the list of domains from the MX Records
    extract_mx_names(dns_names, dns_manager)

    input_list = []

    # Some MX records point to the third-party domains.
    # Therefore, we filter to only the root domains that belong to the tracked company.
    logger.info("Pre-filter list: " + str(len(dns_names)))
    for hostname in dns_names:
        zone = get_tracked_zone(hostname, zones)
        if zone != None:
            ips = google_dns.fetch_DNS_records(hostname)

            # Pause to prevent DoS-ing of Google's HTTPS DNS Service
            time.sleep(1)

            if ips != []:
                for ip_addr in ips:
                    temp_zone = get_tracked_zone(ip_addr["fqdn"], zones)
                    if temp_zone is not None:
                        record = {"fqdn": ip_addr["fqdn"]}
                        record["zone"] = temp_zone
                        record["created"] = datetime.now()
                        record["type"] = ip_addr["type"]
                        record["value"] = ip_addr["value"]
                        record["status"] = "unknown"
                        input_list.append(record)

                    if ip_addr["type"] == "cname" and is_tracked_zone(
                        ip_addr["value"], zones
                    ):
                        add_to_round_two(ip_addr["value"], round_two)
            else:
                logger.warning("Failed IP Lookup for: " + hostname)
        else:
            logger.warning("Failed match on zone for: " + hostname)

    dead_dns_collection = mongo_connector.get_dead_dns_connection()

    # Some DNS records will be CNAME records pointing to other tracked domains.
    # This is a single level recursion to lookup those domains.
    logger.info("Round Two list: " + str(len(round_two)))
    for hostname in round_two:
        zone = get_tracked_zone(hostname, zones)
        if zone != None:
            ips = google_dns.fetch_DNS_records(hostname)
            time.sleep(1)
            if ips != []:
                for ip_addr in ips:
                    temp_zone = get_tracked_zone(ip_addr["fqdn"], zones)
                    if temp_zone is not None:
                        record = {"fqdn": ip_addr["fqdn"]}
                        record["zone"] = temp_zone
                        record["created"] = datetime.now()
                        record["type"] = ip_addr["type"]
                        record["value"] = ip_addr["value"]
                        record["status"] = "unknown"
                        input_list.append(record)
            else:
                logger.warning("Failed IP Lookup for: " + hostname)
                original_record = dns_manager.find_one({"fqdn": hostname}, "mx")
                if original_record != None:
                    original_record.pop("_id")
                    mongo_connector.perform_insert(dead_dns_collection, original_record)
        else:
            logger.warning("Failed match on zone for: " + hostname)

    # Record all the results.
    dns_manager.remove_by_source("mx")
    logger.info("List length: " + str(len(input_list)))
    for final_result in input_list:
        dns_manager.insert_record(final_result, "mx")

    # Record status
    jobs_manager.record_job_complete()

    now = datetime.now()
    print("Ending: " + str(now))
    logger.info("Complete.")


if __name__ == "__main__":
    logger = LoggingUtil.create_log(__name__)

    try:
        main(logger)
    except Exception as e:
        logger.error("FATAL: " + str(e), exc_info=True)
        exit(1)
