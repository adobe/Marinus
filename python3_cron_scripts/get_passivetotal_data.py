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
This script will do searches against the PassiveTotal whois database
based on known email addresses. It replaces the RiskIQ script that did
the same thing. This is one way to find out about new root domains.

PassiveTotal includes historical data for domains that have expired.
Unfortunately, the "expiresAt" property is often not accurate and
cannot be used to reliably identify whether a domain is currently
registered. Identification of expired records happens in a later script.

This script requires a PassiveTotal subscription.
"""

import json
import logging
import re
from datetime import datetime

from libs3 import JobsManager, MongoConnector, PassiveTotal, ZoneIngestor
from libs3.LoggingUtil import LoggingUtil


def search_pt_nameserver(logger, name_server, orgs, pt, zi, jobs_manager):
    """
    Search PassiveTotal based on the name server.
    Double check with org and/or email since the zone may be owned by someone else.
    """
    logger.info("Searching: " + name_server)
    results = pt.get_name_server(name_server)

    if results is None:
        logger.error("Error querying nameserver: " + name_server)
        jobs_manager.record_job_error()
        exit(0)

    logger.info("Results for " + name_server + ": " + str(len(results["results"])))

    for j in range(0, len(results["results"])):
        domain = results["results"][j]["domain"].encode("utf-8").decode("utf8")
        logger.debug("Checking domain: " + domain)

        if re.match(r"^([0-9]{1,3}\.){3}[0-9]{1,3}\/\d\d$", domain):
            logger.debug("Matched IP address. Skipping...")
            continue

        if results["results"][j]["organization"] not in orgs:
            logger.warning(
                domain
                + " not registered by known org: "
                + results["results"][j]["organization"]
            )
            logger.warning("Registrant: " + str(results["results"][j]["registrant"]))
            continue

        zi.add_zone(domain, "PassiveTotal")


def search_pt_email(logger, email, pt, zi, jobs_manager):
    """
    Search PassiveTotal for records associated with the provided email address.
    """
    logger.info("Searching: " + email)
    results = pt.get_email(email)

    if results is None:
        logger.error("Error querying email: " + email)
        jobs_manager.record_job_error()
        exit(0)

    logger.info("Results for " + email + ": " + str(len(results["results"])))

    for j in range(0, len(results["results"])):
        domain = results["results"][j]["domain"].encode("utf-8").decode("utf8")
        logger.debug("Checking domain: " + domain)

        if re.match(r"^([0-9]{1,3}\.){3}[0-9]{1,3}\/\d\d$", domain):
            logger.debug("Matched IP address. Skipping...")
            continue

        zi.add_zone(domain, "PassiveTotal")


def search_pt_org(logger, org, pt, zi, jobs_manager):
    """
    Search PassiveTotal for records associated with the provided organization.
    """
    logger.info("Searching: " + org)
    results = pt.get_organization(org)

    if results is None:
        logger.error("Error querying org: " + org)
        jobs_manager.record_job_error()
        exit(0)

    logger.info("Results for " + org + ": " + str(len(results["results"])))

    for j in range(0, len(results["results"])):
        domain = results["results"][j]["domain"].encode("utf-8").decode("utf8")
        logger.debug("Checking domain: " + domain)

        if re.match(r"^([0-9]{1,3}\.){3}[0-9]{1,3}\/\d\d$", domain) or re.match(
            r"^([0-9]{1,3}\.){3}[0-9]{1,3}$", domain
        ):
            logger.debug("Matched IP address. Skipping...")
            continue

        zi.add_zone(domain, "PassiveTotal")


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
    MC = MongoConnector.MongoConnector()
    PT = PassiveTotal.PassiveTotal()
    zi = ZoneIngestor.ZoneIngestor()
    config_collection = MC.get_config_connection()
    res = config_collection.find({})

    jobs_manager = JobsManager.JobsManager(MC, "get_passivetotal_data")
    jobs_manager.record_job_start()

    # Perform a search for each email address
    for i in range(0, len(res[0]["DNS_Admins"])):
        search_pt_email(logger, res[0]["DNS_Admins"][i], PT, zi, jobs_manager)

    for i in range(0, len(res[0]["Whois_Orgs"])):
        search_pt_org(logger, res[0]["Whois_Orgs"][i], PT, zi, jobs_manager)

    for i in range(0, len(res[0]["Whois_Name_Servers"])):
        search_pt_nameserver(
            logger,
            res[0]["Whois_Name_Servers"][i],
            res[0]["Whois_Orgs"],
            PT,
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
