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
This script attempts to identify root domains that have not been renewed by the owner.

It will also try to identify if any expired domains are re-registered.
If the expired domain is re-registered by an organization in the Whois_Orgs config, it will renable it.
If the expired domain is re-registered by someone else, then it will log an alert.

This script is dependent on the whois_lookups script having been run. It will also double check the
all_dns collection as a precaution.

At the moment, this is configured for traditional TLDs because the Python whois library is inconsistent
with international domains.
"""

import logging
from datetime import datetime, timedelta

from libs3 import JobsManager, MongoConnector
from libs3.LoggingUtil import LoggingUtil
from libs3.ZoneManager import ZoneManager
from tld import get_tld


def get_primary_zones(logger, zones):
    """
    The whois_lookups script is not reliable for international zones
    Therefore, we want to trim the list to ones that we know work.
    This is the more traditional (.com, .net, .org, etc.)
    This list of trust will be expanded over time.
    """
    supported_tld_list = ["com", "net", "org"]
    new_zones = []
    for zone in zones:
        try:
            tld = get_tld(zone, fix_protocol=True)
        except:
            logger.warning(zone + " was not compatible with TLD")
            continue

        if tld in supported_tld_list:
            new_zones.append(zone)

    return new_zones


def main(logger=None):
    """
    Begin Main...
    """
    if logger is None:
        logger = LoggingUtil.create_log(__name__)

    now = datetime.now()
    print("Starting: " + str(now))
    logger.info("Starting...")

    # Obtain the list of known email addresses from the config collection
    mongo_connector = MongoConnector.MongoConnector()
    whois_collection = mongo_connector.get_whois_connection()
    all_dns_collection = mongo_connector.get_all_dns_connection()
    zones_collection = mongo_connector.get_zone_connection()
    jobs_manager = JobsManager.JobsManager(mongo_connector, "mark_expired")
    jobs_manager.record_job_start()

    # Grab all zones that are not expired or false_positives
    # Also exclude any that were recently updated since they still resolve
    date_delta = datetime.today() - timedelta(days=90)
    zones = zones_collection.distinct(
        "zone",
        {
            "updated": {"$lt": date_delta},
            "status": {"$nin": [ZoneManager.EXPIRED, ZoneManager.FALSE_POSITIVE]},
        },
    )

    # The Python Whois library is hit and miss with some international zones.
    # For now, this script focuses on the most popular TLDs.
    new_zones = get_primary_zones(logger, zones)

    expired_list = []
    for zone in new_zones:
        if whois_collection.count_documents({"zone": zone}) == 0:
            # Assume it is expired if there is no longer a whois record present
            expired_list.append(zone)

    for zone in expired_list:
        if all_dns_collection.count_documents({"zone": zone}) > 0:
            # This may be a case where the Python Whois library failed
            # and the zone is still active.
            logger.debug("DNS records still exist for " + zone)
            expired_list.remove(zone)

    zone_manager = ZoneManager(mongo_connector)

    # Need to get this list before setting zones to expired in order to avoid a recursion problem.
    already_expired = zone_manager.get_zones_by_status(ZoneManager.EXPIRED)

    possibly_renewed = []
    for zone in already_expired:
        if whois_collection.count_documents({"zone": zone}) == 1:
            possibly_renewed.append(zone)

    for zone in expired_list:
        logger.debug("Expiring: " + zone)
        zone_manager.set_status(zone, ZoneManager.EXPIRED, "mark_expired.py")

    # Get the list of known registering entities.
    # This will only work for some whois lookups since Python Whois doesn't get
    # a valid org for all lookups and some have privacy enabled.
    config_collection = mongo_connector.get_config_connection()
    result = config_collection.find({}, {"Whois_Orgs": 1, "Whois_Name_Servers": 1})
    orgs = result[0]["Whois_Orgs"]
    name_servers = []
    if "Whois_Name_Servers" in result[0]:
        name_servers = result[0]["Whois_Name_Servers"]

    logger.debug(str(name_servers))

    for zone in possibly_renewed:
        # We need to be careful of automatically marking something renewed
        # since it could have been registered by someone else.
        if whois_collection.count_documents({"zone": zone, "org": {"$in": orgs}}) == 1:
            logger.warning("ATTENTION: " + zone + " has been renewed based on org")
            zone_manager.set_status(zone, ZoneManager.UNCONFIRMED, "mark_expired.py")
        else:
            result = whois_collection.find(
                {"zone": zone}, {"name_servers": 1, "_id": 0}
            )
            found = 0
            if (
                result is not None
                and "name_servers" in result[0]
                and result[0]["name_servers"] is not None
            ):
                for entry in result[0]["name_servers"]:
                    if entry.lower() in name_servers:
                        logger.warning(
                            "ATTENTION: "
                            + zone
                            + " has been renewed based on name servers"
                        )
                        zone_manager.set_status(
                            zone, ZoneManager.UNCONFIRMED, "mark_expired.py"
                        )
                        found = 1
                        break
            if found == 0:
                result = whois_collection.find(
                    {"zone": zone}, {"name_server_groups": 1, "_id": 0}
                )
                if (
                    result is not None
                    and "name_server_groups" in result[0]
                    and result[0]["name_server_groups"] is not None
                ):
                    for entry in result[0]["name_server_groups"]:
                        if entry.lower() in name_servers:
                            logger.warning(
                                "ATTENTION: "
                                + zone
                                + " has been renewed based on name server_groups"
                            )
                            zone_manager.set_status(
                                zone, ZoneManager.UNCONFIRMED, "mark_expired.py"
                            )
                            found = 1
                            break
            if found == 0:
                logger.warning(zone + " has been renewed by an unknown entity")

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
