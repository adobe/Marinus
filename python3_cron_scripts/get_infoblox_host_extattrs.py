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
This script queries Infoblox for the extattr information from the "Host" records
for each root domains.

This script is only useful to Infoblox customers who take advantage of the
extattr functionality.
"""

import logging
from datetime import datetime

from libs3 import InfobloxExtattrManager, JobsManager, MongoConnector
from libs3.LoggingUtil import LoggingUtil


def main(logger=None):
    """
    Begin Main...
    """
    if logger is None:
        logger = LoggingUtil.create_log(__name__)

    print("Starting: " + str(datetime.now()))
    logger.info("Starting...")

    # Make database connections
    mc = MongoConnector.MongoConnector()
    jobs_manager = JobsManager.JobsManager(mc, "get_infoblox_host_extattrs")
    jobs_manager.record_job_start()

    iem = InfobloxExtattrManager.InfobloxExtattrManager("host")
    iem.get_infoblox_extattr()

    # Record status
    jobs_manager.record_job_complete()

    print("Ending: " + str(datetime.now()))
    logger.info("Complete.")


if __name__ == "__main__":
    logger = LoggingUtil.create_log(__name__)

    try:
        main(logger)
    except Exception as e:
        logger.error("FATAL: " + str(e), exc_info=True)
        exit(1)
