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

from libs3 import MongoConnector, JobsManager


class APIHelper(object):

    _logger = logging.getLogger(__name__)

    MC = MongoConnector.MongoConnector()

    INCORRECT_RESPONSE_JSON_ALLOWED = 20

    def handle_api_error(self, err, job_name):
        """
        Exits the script execution post setting the status in database.
        :param err: Exception causing script exit.
        :param job_manager: The JobManager for the exiting script.
        """
        self._logger.error(err)
        self._logger.error('Exiting script execution.')
        jobs_manager = JobsManager.JobsManager(self.MC, job_name)
        jobs_manager.record_job_error()
        exit(1)

    def connection_error_retry(self, details):
        self._logger.error('Connection Error encountered. Retrying in {wait:0.1f} seconds'.format(**details))
