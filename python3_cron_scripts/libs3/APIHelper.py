#!/usr/bin/python3

# Copyright 2018 Adobe. All rights reserved.
# This file is licensed to you under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License. You may obtain a copy
# of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR REPRESENTATIONS
# OF ANY KIND, either express or implied. See the License for the specific language
# governing permissions and limitations under the License.

import logging

from libs3 import JobsManager, MongoConnector


class APIHelper(object):
    _logger = logging.getLogger(__name__)

    MC = MongoConnector.MongoConnector()

    INCORRECT_RESPONSE_JSON_ALLOWED = 20

    _allowed_giveup_failures = 20

    def handle_api_error(self, err, jobs_reference):
        """
        Exits the script execution post setting the status in database.
        :param err: Exception causing script exit.
        :param jobs_reference: A string with the job name or the JobsManager for the exiting script.
        """
        self._logger.error("FATAL: " + str(err))
        self._logger.error("Exiting script execution.")
        if isinstance(jobs_reference, str):
            jobs_manager = JobsManager.JobsManager(self.MC, jobs_reference)
            jobs_manager.record_job_error()
        else:
            jobs_reference.record_job_error()

        exit(1)

    def connection_error_retry(self, details):
        self._logger.error(
            "Connection Error encountered. Retrying in {wait:0.1f} seconds".format(
                **details
            )
        )

    def backoff_giveup(self, details):
        """
        This is a temporary addition to see how often the system calls this function.
        It will need tuning.
        """
        self._logger.error(
            "FATAL: Calling function {target} could not connect with args {args} and kwargs "
            "{kwargs}".format(**details)
        )

        # This is temporary addition that will require tuning to get the correct threshold
        self._allowed_giveup_failures = self._allowed_giveup_failures - 1
        if self._allowed_giveup_failures <= 0:
            self._logger.error("FATAL: Number of allowed failures reached. Exiting.")
            exit(1)
