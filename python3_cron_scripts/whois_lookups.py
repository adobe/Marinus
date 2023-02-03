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
Based on python-whois, not pywhois.

Every country and tld returns whois data differently with no standardization.
This results in "quirks" within the results that lead to inconsistencies.
For instance, the "name_servers" property is *usually* an array but not always.
In addition, some country codes like ".de", return a mostly empty object because
the parse does not yet support whois responses from that geography.

Old records are replaced via an upsert.

This script assumes that all the tracked zones have already been collected.
"""

import logging
import time
from datetime import datetime, timedelta

import whois
from libs3 import JobsManager, RemoteMongoConnector
from libs3.LoggingUtil import LoggingUtil
from libs3.ZoneManager import ZoneManager
from tld import get_fld


def get_zones(mongo_connector):
    """
    Get all the zones
    """
    zone_collection = mongo_connector.get_zone_connection()
    zone_results = zone_collection.distinct(
        "zone", {"status": {"$ne": ZoneManager.FALSE_POSITIVE}}
    )

    zones = []
    for zone in zone_results:
        if zone.find(".") >= 0:
            # The encode-decode is silly but necessary due to a Latin-1 Python quirk when printing.
            zones.append(zone.encode("utf-8").decode("utf-8"))

    return zones


def get_fld_from_value(value, zone):
    """
    Get the First Level Domain (FLD) for the provided value
    """
    res = get_fld(value, fix_protocol=True, fail_silently=True)
    if res is None:
        return zone

    return res


def correct_name_servers(logger, result, zone):
    """
    This is to deal with issues in the whois library where the response
    is a string instead of an array. Known variants include:
        - "Hostname:      dns-1.example.org\nHostname:     dns-2.example.org\nHostname..."
        - "No nameserver"
        - "dns-1.example.org   1.2.3.4"
        - "Organization_Name
    The problem with inconsistent types is that it makes database queries harder downstream.
    """
    if result["name_servers"].startswith("Hostname"):
        new_list = []
        parts = result["name_servers"].split("\n")
        for part in parts:
            if part.startswith("Hostname"):
                sub_parts = part.split()
                new_list.append(sub_parts[1])
        return new_list
    elif result["name_servers"] == "No nameserver":
        return []
    elif "." in result["name_servers"]:
        if " " in result["name_servers"]:
            new_list = []
            temp = result["name_servers"].split()
            new_list.append(temp[0])
            return new_list
        else:
            new_list = []
            new_list.append(result["name_servers"])
            return new_list
    else:
        logger.warning(
            "ERROR: "
            + zone
            + " had an unexpected name_servers response of "
            + result["name_servers"]
        )
        return []


def do_whois_lookup(logger, zone, whois_collection):
    """
    Perform the whois lookup and update the database with the results
    """
    try:
        result = whois.whois(zone)
    except Exception as exc:
        logger.warning("Whois Exception! " + repr(exc))
        result = None

    # If we successfully retrieved a result...
    # Unfortunately, the whois library is inconsistent with domains that are not found.
    # Sometimes it returns None if the domain is not found.
    # Sometimes it returns an object and the phrase "NOT FOUND" can be seen in the text field.
    # Therefore, we have to do convoluted logic to make sure the result exists and that the
    # text field does not say "NOT FOUND"
    if (result is not None and "text" not in result) or (
        result is not None and "text" in result and "NOT FOUND" not in result["text"]
    ):
        # Add the zone since the response doesn't include it.
        result["zone"] = zone
        # Record the full text of the response. A property is not the same as a key.
        result["text"] = result.text
        result["updated"] = datetime.now()

        if "name_servers" in result and isinstance(result["name_servers"], str):
            result["name_servers"] = correct_name_servers(logger, result, zone)

        name_server_groups = []
        if "name_servers" in result and result["name_servers"] is not None:
            for name_server in result["name_servers"]:
                fld = get_fld_from_value(name_server, None)
                if fld is not None and fld not in name_server_groups:
                    name_server_groups.append(fld)

        result["name_server_groups"] = name_server_groups

        # Try to update the record, or insert if it doesn't exist
        success = True
        try:
            whois_collection.replace_one({"zone": zone}, result, upsert=True)
        except Exception as exc:
            logger.warning("Insert exception for " + zone + ": " + repr(exc))
            success = False

        if success:
            logger.info("Successfully updated: " + zone + "!")
    else:
        logger.debug("Unable to to look up zone: " + zone)

    # Sleep so that we don't get blocked by whois servers for too many requests
    time.sleep(45)


def main(logger=None):
    """
    Begin Main...
    """
    if logger is None:
        logger = LoggingUtil.create_log(__name__)

    now = datetime.now()
    print("Starting: " + str(now))
    logger.info("Starting...")

    mongo_connector = RemoteMongoConnector.RemoteMongoConnector()
    jobs_manager = JobsManager.JobsManager(mongo_connector, "whois_lookups")
    jobs_manager.record_job_start()

    # Collect the tracked zones...
    zones = get_zones(mongo_connector)

    whois_collection = mongo_connector.get_whois_connection()

    for zone in zones:
        # Ensure the zone contains at least one dot. This is left over from an old bug.
        if zone.find(".") > 0:
            logger.debug(zone)
            zone_result = whois_collection.find_one({"zone": zone})

            # If we haven't done a lookup in the past, try to collect the data.
            # A limit exists on the number of whois lookups you can perform so limit to new domains.
            if zone_result is None:
                do_whois_lookup(logger, zone, whois_collection)

    # The cap on the number of old entries to be updated.
    MAX_OLD_ENTRIES = 400

    # Grab entries that haven't been updated in 3 months
    last_week = datetime.now() - timedelta(days=90, hours=1)
    zone_result = whois_collection.find({"updated": {"$lte": last_week}}).batch_size(10)

    i = 0
    for result in zone_result:
        do_whois_lookup(logger, result["zone"], whois_collection)
        i = i + 1

        # Chances are that a lot of the entries were inserted on the same day.
        # This helps break updating old entries across different runs.
        if i > MAX_OLD_ENTRIES:
            break

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
