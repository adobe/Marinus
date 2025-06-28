#!/usr/bin/python3

# Copyright 2025 Adobe. All rights reserved.
# This file is licensed to you under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License. You may obtain a copy
# of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR REPRESENTATIONS
# OF ANY KIND, either express or implied. See the License for the specific language
# governing permissions and limitations under the License.

"""
Get the list of Google Cloud Compute public IP ranges per the following page:
https://cloud.google.com/compute/docs/faq#find_ip_range

As the above page notes:
Important: In the past, Google Cloud instructed users to inspect the
_cloud-netblocks.googleusercontent.com DNS TXT record (and the records it referenced).
Update your scripts or software libraries so that they read from the cloud.json file instead.
The JSON file includes additional information, such as the region to which a regional external
IP address is attached.
"""

import argparse
import json
import logging
from datetime import datetime

import requests
from libs3 import GoogleDNS, JobsManager, MongoConnector
from libs3.LoggingUtil import LoggingUtil
from requests.adapters import HTTPAdapter
from urllib3.util import Retry


def recursive_search(logger, target, google_dns):
    """
    The TXT records are recursive with references to other TXT records.
    This function recursively searches all references and returns the
    associated IPv4 and IPv6 addresses.
    """
    results = google_dns.fetch_DNS_records(target, google_dns.DNS_TYPES["txt"])

    ranges = []

    if results is not None:
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


def dns_search(google_dns, logger):
    """
    This function performs the legacy search method via TXT records.
    """
    ip_ranges = recursive_search(
        logger, "_cloud-netblocks.googleusercontent.com", google_dns
    )

    ipv4_ranges = []
    ipv6_ranges = []

    already_seen = set()

    for entry in ip_ranges:
        parts = entry.split(":", 1)
        if parts[0] == "ip4" and parts[1] not in already_seen:
            ipv4_ranges.append({"ip_prefix": parts[1]})
            already_seen.add(parts[1])
        elif parts[0] == "ip6" and parts[1] not in already_seen:
            ipv6_ranges.append({"ipv6_prefix": parts[1]})
            already_seen.add(parts[1])
        else:
            logger.warning("Unrecognized data: " + entry)

    return ipv4_ranges, ipv6_ranges


def _requests_retry_session(
    retries=5,
    backoff_factor=7,
    status_forcelist=[408, 500, 502, 503, 504],
    session=None,
):
    """
    A Closure method for this static method.
    """
    session = session or requests.Session()
    retry = Retry(
        total=retries,
        read=retries,
        connect=retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def json_search(google_dns, logger):
    """
    This function performs the new method of fetching the JSON file.
    """

    ipv4_ranges = []
    ipv6_ranges = []

    try:
        req = _requests_retry_session().get(
            "https://www.gstatic.com/ipranges/cloud.json", timeout=120
        )
    except Exception as ex:
        logger.error("Google GCP range download attempts failed!")
        logger.error(str(ex))
        return None, None

    if req.status_code != 200:
        logger.debug("HTTP Error fetching GCP ranges!")
        return None

    json_results = json.loads(req.text)

    already_seen = set()

    try:
        for entry in json_results["prefixes"]:
            if "ipv4Prefix" in entry and entry["ipv4Prefix"] not in already_seen:
                ipv4_ranges.append(
                    {
                        "ip_prefix": entry["ipv4Prefix"],
                        "service": entry["service"],
                        "scope": entry["scope"],
                    }
                )
                already_seen.add(entry["ipv4Prefix"])
            elif "ipv6Prefix" in entry and entry["ipv6Prefix"] not in already_seen:
                ipv6_ranges.append(
                    {
                        "ipv6_prefix": entry["ipv6Prefix"],
                        "service": entry["service"],
                        "scope": entry["scope"],
                    }
                )
                already_seen.add(entry["ipv6Prefix"])
    except Exception as ex:
        logger.error("Error parsing GCP ranges!")
        logger.error(str(ex))
        return None, None

    return ipv4_ranges, ipv6_ranges


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

    parser = argparse.ArgumentParser(
        description="Retrieve GCP IP ranges from DNS TXT records or the public JSON file."
    )
    parser.add_argument(
        "--source",
        required=False,
        default="json",
        choices=["json", "dns"],
        help="Specify whether to fetch from DNS TXT records or the public JSON file",
    )

    args = parser.parse_args()

    mongo_connector = MongoConnector.MongoConnector()
    gcp_collection = mongo_connector.get_gcp_ips_connection()
    google_dns = GoogleDNS.GoogleDNS()
    jobs_manager = JobsManager.JobsManager(mongo_connector, "get_gcp_ranges")
    jobs_manager.record_job_start()

    if args.source == "dns":
        ipv4_ranges, ipv6_ranges = dns_search(google_dns, logger)
    elif args.source == "json":
        ipv4_ranges, ipv6_ranges = json_search(google_dns, logger)
    else:
        logger.error("Invalid source: " + args.source)
        exit(1)

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

