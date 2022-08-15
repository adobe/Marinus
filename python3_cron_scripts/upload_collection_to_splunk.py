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
Some organizations may want to export portions of a database to a Splunk index in order
to take advantage of dashboarding or to cross-reference the data with other tools. This
script is a template for exporting data to a Splunk instance.

In this template, the HTTP headers from ZGrab scans are exported to a Splunk HTTP Event
Collector (HEC). By exporting the Headers from the server response, an organization could
measure best practice adoption for Cookies, HSTS, X-XSS-Protection, CORS, X-Frame-Options,
etc. Since the ZGrab schema is complex, only the relevant subset of data is uploaded in
order to make queries easier and to avoid truncation by Splunk.

This script could be altered to upload any collection that is relevant to your organization.
"""

import argparse
import logging
from datetime import datetime

import requests
from libs3 import JobsManager, MongoConnector, SplunkHECManager
from libs3.LoggingUtil import LoggingUtil


def upload_zgrab_443(logger, splunk_manager, mongo_connector):
    """
    Upload the HTTP Headers from Zgrab scans of HTTPS servers
    In a redirect scenario, this uploads the headers of the final page which returns a 200.
    It does not upload the headers of the first response which returned the 30x response.
    This also does not include headers from requests sent to IP addresses.
    """
    zgrab_443_collection = mongo_connector.get_zgrab_443_data_connection()

    results = mongo_connector.perform_find(
        zgrab_443_collection, {"domain": {"$ne": "<nil>"}}, batch_size=80
    )

    for result in results:
        data = {}
        data["zones"] = result["zones"]
        data["timestamp"] = result["timestamp"]
        data["domain"] = result["domain"]

        try:
            data["host"] = result["data"]["http"]["result"]["response"]["request"][
                "host"
            ]
        except:
            logger.debug("Passing on host")
            pass

        try:
            data["response_headers"] = result["data"]["http"]["result"]["response"][
                "headers"
            ]
        except:
            logger.debug("Skipping on headers")
            continue

        try:
            data["status_code"] = result["data"]["http"]["result"]["response"][
                "status_code"
            ]
        except:
            logger.debug("Passing on status_code")
            pass

        splunk_manager.push_to_splunk_hec("marinus_443_domain_headers", data)


def upload_zgrab_80(logger, splunk_manager, mongo_connector):
    """
    Upload the HTTP Headers from Zgrab scans of HTTP servers.
    In a redirect scenario, this uploads the headers of the final page which returns a 200.
    It does not upload the headers of the first response which returned the 30x response.
    This also does not include headers from requests sent to IP addresses.
    """
    zgrab_80_collection = mongo_connector.get_zgrab_80_data_connection()

    results = mongo_connector.perform_find(
        zgrab_80_collection, {"domain": {"$ne": "<nil>"}}, batch_size=100
    )

    for result in results:
        data = {}
        data["zones"] = result["zones"]
        data["timestamp"] = result["timestamp"]
        data["domain"] = result["domain"]

        try:
            data["host"] = result["data"]["http"]["result"]["response"]["request"][
                "host"
            ]
        except:
            logger.debug("Passing on host")
            pass

        try:
            data["response_headers"] = result["data"]["http"]["result"]["response"][
                "headers"
            ]
        except:
            logger.debug("Skipping on headers")
            continue

        try:
            data["status_code"] = result["data"]["http"]["result"]["response"][
                "status_code"
            ]
        except:
            logger.debug("Passing on status_code")
            pass

        splunk_manager.push_to_splunk_hec("marinus_80_domain_headers", data)


def main(logger=None):
    """
    Begin main...
    """
    if logger is None:
        logger = LoggingUtil.create_log(__name__)

    now = datetime.now()
    print("Starting: " + str(now))
    logger.info("Starting...")

    parser = argparse.ArgumentParser(description="Search Splunk logs for IP address")
    parser.add_argument(
        "--collection_name",
        choices=["http_80", "http_443"],
        metavar="COLLECTION",
        required=True,
        help="The collection to upload to Splunk",
    )
    args = parser.parse_args()

    mongo_connector = MongoConnector.MongoConnector()
    splunk_manager = SplunkHECManager.SplunkHECManager()

    jobs_manager = JobsManager.JobsManager(
        mongo_connector, "splunk_headers_upload_" + args.collection_name
    )
    jobs_manager.record_job_start()

    if args.collection_name == "http_443":
        upload_zgrab_443(logger, splunk_manager, mongo_connector)
    elif args.collection_name == "http_80":
        upload_zgrab_80(logger, splunk_manager, mongo_connector)

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
