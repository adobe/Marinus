#!/usr/bin/python3

# Copyright 2020 Adobe. All rights reserved.
# This file is licensed to you under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License. You may obtain a copy
# of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR REPRESENTATIONS
# OF ANY KIND, either express or implied. See the License for the specific language
# governing permissions and limitations under the License.

"""
This script will do searches against the Cisco Umbrella whois database
based on known email addresses. It is used to identify new root domains.

This script requires a Cisco Umbrella subscription.
"""

import json
import logging
import re
from datetime import datetime

from libs3 import JobsManager, MongoConnector, Umbrella, ZoneIngestor
from libs3.LoggingUtil import LoggingUtil


def search_umbrella_by_nameserver(
    logger, name_server, orgs, umbrella, zi, jobs_manager
):
    """
    Search Umbrella based on the name server.
    Double check the response with org and/or email since the zone may be owned by someone else.
    """
    logger.info("Searching: " + name_server)
    results = umbrella.search_by_name_server(name_server)

    if results is None:
        logger.error("Error querying nameserver: " + name_server)
        jobs_manager.record_job_error()
        exit(1)

    logger.info(
        "Results for " + name_server + ": " + str(results[name_server]["totalResults"])
    )

    for entry in results[name_server]["domains"]:
        domain = entry["domain"]
        logger.debug("Checking domain: " + domain)

        if re.match(r"^([0-9]{1,3}\.){3}[0-9]{1,3}\/\d\d$", domain):
            logger.debug("Matched IP address. Skipping...")
            continue

        if entry["current"] is False:
            continue

        whois_result = umbrella.search_by_domain(domain)

        if "errorMessage" in whois_result:
            logger.error(
                "Umbrella error message received when searching for domain: " + domain
            )
            continue

        if whois_result["registrantOrganization"] not in orgs:
            logger.warning(
                domain
                + " not registered by known org: "
                + str(whois_result["registrantOrganization"])
            )
            continue

        zi.add_zone(domain, "Umbrella")


def add_email_domains(logger, results, email, zi, jobs_manager):
    """
    Add the root domains identified by an email search.
    """

    for entry in results[email]["domains"]:
        domain = entry["domain"]
        logger.debug("Checking domain: " + domain)

        if entry["current"] == False:
            continue

        if re.match(r"^([0-9]{1,3}\.){3}[0-9]{1,3}\/\d\d$", domain):
            logger.debug("Matched IP address. Skipping...")
            continue

        zi.add_zone(domain, "Umbrella")


def search_umbrella_by_email(logger, email, umbrella, zi, jobs_manager):
    """
    Search Umbrella for records associated with the provided email address.
    """
    logger.info("Searching: " + email)

    results = umbrella.search_by_email(email)

    if results is None:
        logger.error("Error querying email: " + email)
        jobs_manager.record_job_error()
        exit(0)

    total_results = int(results[email]["totalResults"])
    logger.info("Results for " + email + ": " + str(total_results))

    limit = int(results[email]["limit"])

    offset = 0
    while offset < total_results:
        add_email_domains(logger, results, email, zi, jobs_manager)
        offset = offset + limit

        if offset < total_results:
            results = umbrella.search_umbrella_by_email(email, offset)


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
    umbrella = Umbrella.Umbrella()
    zi = ZoneIngestor.ZoneIngestor()

    # Obtain the list of known email addresses and name servers from the config collection
    config_collection = mongo_connector.get_config_connection()
    res = config_collection.find({})

    jobs_manager = JobsManager.JobsManager(mongo_connector, "get_umbrella_whois")
    jobs_manager.record_job_start()

    # Perform a search for each email address
    for i in range(0, len(res[0]["DNS_Admins"])):
        search_umbrella_by_email(
            logger, res[0]["DNS_Admins"][i], umbrella, zi, jobs_manager
        )

    # Perform a search based on each name server
    for i in range(0, len(res[0]["Whois_Name_Servers"])):
        search_umbrella_by_nameserver(
            logger,
            res[0]["Whois_Name_Servers"][i],
            res[0]["Whois_Orgs"],
            umbrella,
            zi,
            jobs_manager,
        )

    # Record status
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

exit(0)
