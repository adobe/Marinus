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
This script mines the domains tracked by VirusTotal and creates DNS records for them.
This script assumes that the following scripts have been run:

- Core (Zone list)
- get_virustotal_data
"""

import json
import logging
import time
from datetime import datetime

import requests
from libs3 import DNSManager, GoogleDNS, JobsManager, MongoConnector
from libs3.LoggingUtil import LoggingUtil
from libs3.ZoneManager import ZoneManager


def add_to_list(str_to_add, round_two):
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
    jobs_manager = JobsManager.JobsManager(mongo_connector, "extract_vt_domains")

    google_dns = GoogleDNS.GoogleDNS()
    jobs_manager.record_job_start()

    round_two = []

    zones = ZoneManager.get_distinct_zones(mongo_connector)

    vt_collection = mongo_connector.get_virustotal_connection()
    vt_results = vt_collection.find(
        {"subdomains": {"$exists": True}}, {"zone": 1, "subdomains": 1}
    ).batch_size(20)

    input_list = []

    # For each result found in the first pass across VirusTotal
    for result in vt_results:
        # Pause to prevent DoS-ing of Google's HTTPS DNS Service
        time.sleep(1)

        for hostname in result["subdomains"]:
            ips = google_dns.fetch_DNS_records(hostname)

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
                        add_to_list(ip_addr["value"], round_two)
            else:
                logger.warning("Failed IP Lookup for: " + hostname)

    dead_dns_collection = mongo_connector.get_dead_dns_connection()

    # For each tracked CName result found in the first pass across VirusTotal
    logger.info("Round Two length: " + str(len(round_two)))
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
                original_record = dns_manager.find_one({"fqdn": hostname}, "virustotal")
                if original_record != None:
                    original_record.pop("_id")
                    mongo_connector.perform_insert(dead_dns_collection, original_record)
                logger.warning("Failed IP Lookup for: " + hostname)
        else:
            logger.warning("Failed match on zone for: " + hostname)

    # Update the database
    dns_manager.remove_by_source("virustotal")
    logger.info("List length: " + str(len(input_list)))

    for final_result in input_list:
        dns_manager.insert_record(final_result, "virustotal")

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
