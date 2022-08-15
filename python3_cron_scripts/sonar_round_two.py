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
This script iterates through Sonar records for CNames that might belong to the tracked organization.
If found, it will try to look them up and add them to the DNS list
"""

import json
import logging
import time
from datetime import datetime

import requests
from libs3 import DNSManager, GoogleDNS, JobsManager, MongoConnector
from libs3.LoggingUtil import LoggingUtil
from libs3.ZoneManager import ZoneManager
from tld import get_fld


def add_to_list(str_to_add, round_three):
    """
    Add new candidates to the queue
    """
    if str_to_add not in round_three:
        round_three.append(str_to_add)
    return round_three.index(str_to_add)


def get_fld_from_value(value, zone):
    """
    Get the First Level Domain (FLD) for the provided value
    """
    res = get_fld(value, fix_protocol=True, fail_silently=True)
    if res is None:
        return zone

    return res


def is_tracked_zone(cname, zones):
    """
    Does the CNAME belong to a tracked zone?
    """
    for zone in zones:
        if cname.endswith("." + zone) or cname == zone:
            return True
    return False


def lookup_hostname(logger, host, zones, round_three):
    """
    Use Google DNS over HTTPS to lookup host
    """
    try:
        req = requests.get("https://dns.google.com/resolve?name=" + host)
    except:
        logger.error("Requests attempt failed!")
        return []

    if req.status_code != 200:
        logger.error("Error looking up: " + host)
        return []

    nslookup_results = json.loads(req.text)

    if nslookup_results["Status"] != 0:
        logger.warning("Status error looking up: " + host)
        return []

    if "Answer" not in nslookup_results:
        logger.warning("Could not find Answer in DNS result for " + host)
        logger.warning(req.text)
        return []

    results = []
    for answer in nslookup_results["Answer"]:
        if answer["type"] == 5:
            results.append({"type": "cname", "value": answer["data"][:-1]})
            if is_tracked_zone(answer["data"][:-1], zones):
                add_to_list(answer["data"][:-1], round_three)
        elif answer["type"] == 1:
            results.append({"type": "a", "value": answer["data"]})
        elif answer["type"] == 28:
            results.append({"type": "aaaa", "value": answer["data"]})
        else:
            logger.warning("Unrecognized type: " + str(answer["type"]))

    return results


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
    jobs_manager = JobsManager.JobsManager(mongo_connector, "sonar_round_two")
    google_dns = GoogleDNS.GoogleDNS()
    jobs_manager.record_job_start()

    zones = ZoneManager.get_distinct_zones(mongo_connector)

    results = dns_manager.find_multiple({"type": "cname"}, "sonar_dns")

    round_two = []
    round_three = []

    # Get all the CNAME values from all_dns and append them to round_two
    for result in results:
        if is_tracked_zone(result["value"], zones):
            round_two.append(result["value"])

    logger.info("Round two pre-list: " + str(len(round_two)))

    dead_dns_collection = mongo_connector.get_dead_dns_connection()

    for value in round_two:
        is_present = dns_manager.find_count({"fqdn": value}, "sonar_dns")
        if is_present == 0:
            logger.debug(value + " not found")
            time.sleep(1)
            result = google_dns.fetch_DNS_records(value)
            if result == []:
                logger.debug("Unable to resolve")
                original_records = dns_manager.find_multiple(
                    {"value": value}, "sonar_dns"
                )
                for record in original_records:
                    check = dead_dns_collection.count_documents(
                        {"fqdn": record["fqdn"]}
                    )
                    if check == 0:
                        record.pop("_id")
                        mongo_connector.perform_insert(dead_dns_collection, record)
            else:
                for entry in result:
                    if is_tracked_zone(entry["fqdn"], zones):
                        new_record = entry
                        new_record["status"] = "unconfirmed"
                        new_record["zone"] = get_fld_from_value(value, "")
                        new_record["created"] = datetime.now()
                        if result[0]["type"] == "cname" and is_tracked_zone(
                            entry["value"], zones
                        ):
                            add_to_list(entry["value"], round_three)
                        logger.debug("Found: " + value)
                        if new_record["zone"] != "":
                            dns_manager.insert_record(new_record, "marinus")

    # For each tracked CName result found in the first pass across Sonar DNS
    logger.info("Round Three length: " + str(len(round_three)))
    for hostname in round_three:
        zone = get_fld_from_value(hostname, "")
        if zone != None and zone != "":
            ips = google_dns.fetch_DNS_records(hostname)
            time.sleep(1)
            if ips != []:
                for ip_addr in ips:
                    if is_tracked_zone(ip_addr["fqdn"], zones):
                        record = {"fqdn": ip_addr["fqdn"]}
                        record["zone"] = get_fld_from_value(ip_addr["fqdn"], "")
                        record["created"] = datetime.now()
                        record["type"] = ip_addr["type"]
                        record["value"] = ip_addr["value"]
                        record["status"] = "unconfirmed"
                        dns_manager.insert_record(new_record, "marinus")
            else:
                original_record = dns_manager.find_one({"fqdn": hostname}, "marinus")
                if original_record != None:
                    original_record.pop("_id")
                    mongo_connector.perform_insert(dead_dns_collection, original_record)
                logger.debug("Failed IP Lookup for: " + hostname)
        else:
            logger.debug("Failed match on zone for: " + hostname)

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
