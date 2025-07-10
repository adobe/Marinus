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
This script parses an Azure IP list provided in the JSON file that can be found at:
https://www.microsoft.com/en-us/download/details.aspx?id=56519

Unfortunately, Microsoft doesn't provide an API to retrieve the list.
Therefore, this script parses the web page looking for the link.
This technique is bound to break over time.
However, it is what is possible until a better solution is provided.
"""

import json
import logging
from datetime import datetime
from html.parser import HTMLParser

import requests
from libs3 import JobsManager, MongoConnector
from libs3.LoggingUtil import LoggingUtil
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

JSON_LOCATION = "https://www.microsoft.com/en-us/download/details.aspx?id=56519"


class MyHTMLParser(HTMLParser):
    """
    Create a subclass and override the handler methods.
    """

    URL = ""
    logger = LoggingUtil.create_log(__name__)

    def handle_starttag(self, tag, attrs):
        found = False
        if tag == "a":
            for attr in attrs:
                if (
                    attr[0] == "data-m"
                    and attr[1].find("Azure IP Ranges and Service Tags") != -1
                ):
                    found = True

            if found:
                for attr in attrs:
                    if attr[0] == "href":
                        self.logger.info(attr[1])
                        self.URL = attr[1]


def requests_retry_session(
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
    """
    Begin main...
    """
    if logger is None:
        logger = LoggingUtil.create_log(__name__)

    now = datetime.now()
    print("Starting: " + str(now))
    logger.info("Starting...")

    mongo_connector = MongoConnector.MongoConnector()
    jobs_manager = JobsManager.JobsManager(mongo_connector, "get_azure_data")
    jobs_manager.record_job_start()

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.3",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
    }

    # Find the JSON file location
    try:
        req = requests_retry_session().get(JSON_LOCATION, timeout=120, headers=headers)
    except Exception as ex:
        logger.error(
            "FATAL: Azure HTTP request for HTML page failed multiple attempts!"
        )
        logger.error(str(ex))
        exit(1)

    if req.status_code != 200:
        logger.error(
            "FATAL: Unexpected response for Azure HTML page: " + str(req.status_code)
        )
        jobs_manager.record_job_error()
        exit(1)

    parser = MyHTMLParser()
    parser.feed(req.text)

    if parser.URL == "":
        logger.error("FATAL: Unable to identify URL in Microsoft HTML")
        jobs_manager.record_job_error()
        exit(1)

    # Download the XML file
    try:
        req = requests_retry_session().get(parser.URL, timeout=120, headers=headers)
    except Exception as ex:
        logger.error("Azure request for JSON data failed multiple attempts!")
        logger.error(str(ex))
        return None

    if req.status_code != 200:
        logger.error(
            "FATAL: Unexpected response for Azure JSON data: " + str(req.status_code)
        )
        jobs_manager.record_job_error()
        exit(1)

    root = json.loads(req.text)

    insert_json = {}
    insert_json["created"] = datetime.now()
    insert_json["prefixes"] = []

    for value in root["values"]:
        # Just import the regional data for now
        if value["name"].find("AzureCloud.") == 0:
            region_name = value["properties"]["region"]
            for iprange in value["properties"]["addressPrefixes"]:
                insert_json["prefixes"].append(
                    {"region": region_name, "ip_prefix": iprange}
                )

    azure_ips = mongo_connector.get_azure_ips_connection()
    azure_ips.delete_many({})
    mongo_connector.perform_insert(azure_ips, insert_json)

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
