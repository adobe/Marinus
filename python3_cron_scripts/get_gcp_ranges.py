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
Get the list of Google Cloud Compute public IP ranges from their DNS TXT records
https://cloud.google.com/compute/docs/faq#find_ip_range
"""

import logging
from datetime import datetime

from libs3 import GoogleDNS, JobsManager, MongoConnector
from libs3.LoggingUtil import LoggingUtil


def recursive_search(logger, target, google_dns):
    """
    The TXT records are recursive with references to other TXT records.
    This function recursively searches all references and returns the
    associated IPv4 and IPv6 addresses.
    """
    results = google_dns.fetch_DNS_records(target, google_dns.DNS_TYPES["txt"])

    ranges = []

    for result in results:
        values = result["value"].split(" ")
        for value in values:
            if "spf" in value or "?all" in value:
                continue
            elif "include" in value:
                parts = value.split(":")
                logger.debug("Checking: " + parts[1])
                temp = recursive_search(logger, parts[1], google_dns)
                for entry in temp:
                    if entry not in ranges:
                        ranges.append(entry)
            elif "/" in value:
                if value not in ranges:
                    ranges.append(value)
            else:
                logger.warning("Unrecognized string: " + value)

    return ranges


def main(logger=None):
    """
    This function extract the IP address ranges from the TXT records
    and stores them in gcp_ips collection within the database.
    """
    if logger is None:
        logger = LoggingUtil.create_log(__name__)

    now = datetime.now()
    print("Starting: " + str(now))
    logger.info("Starting...")

    mongo_connector = MongoConnector.MongoConnector()
    gcp_collection = mongo_connector.get_gcp_ips_connection()
    google_dns = GoogleDNS.GoogleDNS()
    jobs_manager = JobsManager.JobsManager(mongo_connector, "get_gcp_ranges")
    jobs_manager.record_job_start()

    ip_ranges = recursive_search(
        logger, "_cloud-netblocks.googleusercontent.com", google_dns
    )

    ipv4_ranges = []
    ipv6_ranges = []

    for entry in ip_ranges:
        parts = entry.split(":", 1)
        if parts[0] == "ip4" and parts[1] not in ipv4_ranges:
            ipv4_ranges.append({"ip_prefix": parts[1]})
        elif parts[0] == "ip6" and parts[1] not in ipv6_ranges:
            ipv6_ranges.append({"ipv6_prefix": parts[1]})
        else:
            logger.warning("Unrecognized data: " + entry)

    new_data = {}
    new_data["prefixes"] = ipv4_ranges
    new_data["ipv6_prefixes"] = ipv6_ranges
    new_data["created"] = now

    gcp_collection.delete_many({})
    mongo_connector.perform_insert(gcp_collection, new_data)

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
