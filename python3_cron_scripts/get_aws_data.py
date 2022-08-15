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
This script runs daily to pull down the list of AWS CIDRs and uploads them to the Marinus database.
It has no dependencies on other scripts.
"""

import json
import logging
from datetime import datetime

import requests
from libs3 import JobsManager, MongoConnector
from libs3.LoggingUtil import LoggingUtil

JSON_LOCATION = "https://ip-ranges.amazonaws.com/ip-ranges.json"


def main(logger=None):
    """
    Begin main...
    """
    if logger is None:
        logger = LoggingUtil.create_log(__name__)

    # Make database connections
    mongo_connector = MongoConnector.MongoConnector()

    now = datetime.now()
    print("Starting: " + str(now))
    logger.info("Starting...")

    jobs_manager = JobsManager.JobsManager(mongo_connector, "get_aws_data")
    jobs_manager.record_job_start()

    # Download the JSON file
    req = requests.get(JSON_LOCATION)

    if req.status_code != 200:
        logger.error("Bad Request")
        jobs_manager.record_job_error()
        exit(1)

    # Convert the response to JSON
    json_data = json.loads(req.text)

    # Replace the old entries with the new entries
    aws_collection = mongo_connector.get_aws_ips_connection()
    aws_collection.delete_many({})
    mongo_connector.perform_insert(aws_collection, json_data)

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
