#!/usr/bin/python3

# Copyright 2024 Adobe. All rights reserved.
# This file is licensed to you under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License. You may obtain a copy
# of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR REPRESENTATIONS
# OF ANY KIND, either express or implied. See the License for the specific language
# governing permissions and limitations under the License.

"""
This script has been updated to dynamically fetch the list of Akamai IP ranges from Akamai.
Unlike the previous version, it does not include the "ip_range" metadata since that was unused.
The note field was also removed since it was no longer relevant.
"""

from datetime import datetime
from io import BytesIO
from zipfile import ZipFile

import requests
from libs3 import JobsManager, MongoConnector
from libs3.LoggingUtil import LoggingUtil
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

ZIP_FILE_LOCATION = (
    "https://techdocs.akamai.com/property-manager/pdfs/akamai_ipv4_ipv6_CIDRs-txt.zip"
)


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


def main(logger=None):
    if logger is None:
        logger = LoggingUtil.create_log(__name__)

    now = datetime.now()
    print("Starting: " + str(now))
    logger.info("Starting...")

    mongo_connector = MongoConnector.MongoConnector()
    akamai_collection = mongo_connector.get_akamai_ips_connection()
    jobs_manager = JobsManager.JobsManager(mongo_connector, "upload_akamai_data")
    jobs_manager.record_job_start()

    # Clear previous data
    akamai_collection.delete_many({})

    AKAMAI_DATA = {}

    # Record the date that the data was updated.
    AKAMAI_DATA["created"] = datetime.now()

    try:
        response = _requests_retry_session().get(
            ZIP_FILE_LOCATION,
            stream=True,
            timeout=120,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127"
            },
        )
    except requests.exceptions.HTTPError as e:
        logger.error("FATAL: HTTP error retrieving Akamai data: " + str(e))
        jobs_manager.record_job_error()
        exit(1)
    except Exception as ex:
        logger.error("FATAL: Error fetching Akamai data: " + str(ex))
        jobs_manager.record_job_error()
        exit(1)

    if response.status_code == 200:
        # Create the list of known IPV4 ranges.
        AKAMAI_DATA["ranges"] = []

        ipZip = ZipFile(BytesIO(response.content))
        for line in ipZip.open("akamai_ipv4_CIDRs.txt").readlines():
            AKAMAI_DATA["ranges"].append(
                {
                    "cidr": line.decode("utf-8").rstrip(),
                }
            )

        # Create the list of known IPV6 ranges.
        AKAMAI_DATA["ipv6_ranges"] = []
        for line in ipZip.open("akamai_ipv6_CIDRs.txt").readlines():
            AKAMAI_DATA["ipv6_ranges"].append(
                {
                    "cidr": line.decode("utf-8").rstrip(),
                }
            )
    else:
        logger.error(
            "FATAL: Non 200 status code from Akamai: " + str(response.status_code)
        )
        jobs_manager.record_job_error()
        exit(1)

    # Insert the data
    mongo_connector.perform_insert(akamai_collection, AKAMAI_DATA)

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

