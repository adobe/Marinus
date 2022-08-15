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
This script attempts to identify places where a tracked CNAME points to a 3rd-party service.

This script assumes that the following scripts have already been run:
- Core scripts (zones, infoblox, sonar)
- extract_ssl_names
- extract_vt_names

ERRATA:
  "TLD" in this case means root domain ("example.org") and not the traditional usage
of TLD which refers to ".net", ".com", ".co.uk", etc. The 0.7 versions of Python tld followed this convention
and therefore so did this script. After 0.7, the Python tld library started referring to "google.co.uk"
as a FLD.
"""

import logging
import time
from datetime import datetime

from libs3 import DNSManager, JobsManager, MongoConnector
from libs3.LoggingUtil import LoggingUtil
from libs3.ZoneManager import ZoneManager
from tld import get_fld


def is_tracked_zone(cname, zones):
    """
    Does the provided CName belong to a tracked TLD?
    """
    for zone in zones:
        if cname.endswith("." + zone) or cname == zone:
            return True
    return False


def add_to_list(str_to_add, host, target, zone, groups):
    """
    Add the provided string to the list of 3rd-party cnames
    The groups array is indexed by the TLD of the third-party
    We associate the 3rd-party TLD with the tracked zone.
    The tracked zone is associated with the host and target
    """
    recs = {"host": host, "target": target}
    new_data = {"zone": zone, "records": [recs]}

    # If this 3rd-party hasn't been seen before, create a new record.
    if str_to_add not in groups.keys():
        groups[str_to_add] = {}
        groups[str_to_add]["tld"] = str_to_add
        groups[str_to_add]["zones"] = []
        groups[str_to_add]["zones"].append(new_data)
        groups[str_to_add]["total"] = 1
        return
    else:
        # The 3rd-party exists.
        # Let's see if the zone has been associated with the 3rd-party before.
        index = -1
        for i in range(0, len(groups[str_to_add]["zones"])):
            if groups[str_to_add]["zones"][i]["zone"] == zone:
                index = i

        # The tracked zone has not been associated with the 3rd-party before.
        # Add the new zone data to the 3rd-party and return.
        if index == -1:
            groups[str_to_add]["zones"].append(new_data)
            groups[str_to_add]["total"] = groups[str_to_add]["total"] + 1
            return

        # The zone has been associated with the 3rd-party before.
        # Check to see if the host-target map has been added before.
        for j in range(0, len(groups[str_to_add]["zones"][index]["records"])):
            if (
                groups[str_to_add]["zones"][index]["records"][j]["host"] == host
                and groups[str_to_add]["zones"][index]["records"][j]["target"] == target
            ):
                return

        # The host & target have been associated with the tracked zone before.
        # Add the new host & target and return.
        groups[str_to_add]["zones"][index]["records"].append(recs)
        groups[str_to_add]["total"] = groups[str_to_add]["total"] + 1

    return


def get_fld_from_value(value, zone):
    """
    Get the First Level Domain (FLD) for the provided value
    """
    res = get_fld(value, fix_protocol=True, fail_silently=True)
    if res is None:
        return zone

    return res


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
    jobs_manager = JobsManager.JobsManager(mongo_connector, "get_external_cnames")
    jobs_manager.record_job_start()

    groups = {}

    # Collect zones
    zone_results = ZoneManager.get_distinct_zones(mongo_connector)

    zones = []
    for zone in zone_results:
        if zone.find(".") >= 0:
            zones.append(zone)

    # Collect the all_dns cnames.
    logger.info("Starting All DNS...")
    all_dns_recs = dns_manager.find_multiple({"type": "cname"}, None)

    for srec in all_dns_recs:
        if not is_tracked_zone(srec["value"], zones):
            add_to_list(
                get_fld_from_value(srec["value"], srec["zone"]),
                srec["fqdn"],
                srec["value"],
                srec["zone"],
                groups,
            )

    # Update the database
    tpds_collection = mongo_connector.get_tpds_connection()

    tpds_collection.delete_many({})
    for key in groups.keys():
        tpds_collection.insert_one(groups[key])

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
