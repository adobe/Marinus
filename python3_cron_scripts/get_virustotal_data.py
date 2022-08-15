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
This script queries the VirusTotal domain reports for any reports that match a tracked domain.
This script uses the free API because the results are the same as the paid API.
We are also allowed more queries per day on the free API than the paid API.
Therefore, we use the free API in order to save the paid API credits for more critical work.
"""

import logging
import time
from datetime import datetime

from libs3 import JobsManager, MongoConnector, VirusTotal
from libs3.LoggingUtil import LoggingUtil
from libs3.ZoneManager import ZoneManager


def main(logger=None):
    """
    Begin Main...
    """
    if logger is None:
        logger = LoggingUtil.create_log(__name__)

    now = datetime.now()
    print("Starting: " + str(now))
    logger.info("Starting...")

    # Create an instance of the VirusTotal class
    vt_instance = VirusTotal.VirusTotal()

    # Get collections for the queries
    mongo_connector = MongoConnector.MongoConnector()
    vt_collection = mongo_connector.get_virustotal_connection()

    jobs_manager = JobsManager.JobsManager(mongo_connector, "get_virustotal_data")
    jobs_manager.record_job_start()

    # Collect the list of tracked TLDs
    zones = ZoneManager.get_distinct_zones(mongo_connector)

    # For each tracked TLD
    for zone in zones:
        logger.debug("Checking " + zone)
        results = vt_instance.get_domain_report(zone)

        if results is None:
            logger.warning("Error querying zone " + zone)
        elif results["response_code"] == -1:
            logger.warning("VT unhappy with " + zone)
        elif results["response_code"] == 0:
            logger.warning("VT doesn't have " + zone)
        else:
            logger.debug("Matched " + zone)

            results["zone"] = zone
            results["created"] = datetime.now()

            # Mongo doesn't allow key names with periods in them
            # Re-assign to an undotted key name
            if "Dr.Web category" in results:
                results["Dr Web category"] = results.pop("Dr.Web category")
            elif "alphaMountain.ai category" in results:
                results["alphaMountain_ai category"] = results.pop(
                    "alphaMountain.ai category"
                )

            vt_collection.delete_one({"zone": zone})

            if "last_https_certificate" in results:
                if "extensions" in results["last_https_certificate"]:
                    if (
                        "1.3.6.1.4.1.11129.2.4.2"
                        in results["last_https_certificate"]["extensions"]
                    ):
                        results["last_https_certificate"]["extensions"][
                            "sct_list"
                        ] = results["last_https_certificate"]["extensions"].pop(
                            "1.3.6.1.4.1.11129.2.4.2"
                        )

            mongo_connector.perform_insert(vt_collection, results)

        # This sleep command is so that we don't exceed the daily limit on the free API
        # This setting results in this script taking several days to complete
        time.sleep(25)

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
