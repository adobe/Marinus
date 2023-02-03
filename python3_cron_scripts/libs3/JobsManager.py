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

import logging
from datetime import datetime


class JobsManager(object):
    """
    The jobs collection is responsible for tracking the progress of the various scripts.
    This class is responsible for recording the status of jobs within the jobs collection.
    """

    # Job states
    ##################

    # Never been run
    NOT_RUN = "NOT_RUN"

    # In progress
    RUNNING = "RUNNING"

    # Ready for next phase
    READY = "READY"

    # An error has occurred
    ERROR = "ERROR"

    # The job is complete
    COMPLETE = "COMPLETE"

    # The job is no longer used
    RETIRED = "RETIRED"

    # Settings
    ###################

    # Print debug output
    _logger = None

    # JobsCollection
    _jobs_collection = None

    # Mongo_Connector
    _mongo_connector = None

    # Job Name
    _job_name = ""

    def _log(self):
        """
        Get the log
        """
        return logging.getLogger(__name__)

    def __init__(self, mongo_connector, job_name, log_level=None):
        self._logger = self._log()
        if log_level is not None:
            self._logger.setLevel(log_level)

        self._mongo_connector = mongo_connector
        self._jobs_collection = mongo_connector.get_jobs_connection()
        self._job_name = job_name

    def __check_job_exists(self, job_name):
        """
        Verify that the job name exists in the collection.
        If the job does not exist, this will create it.
        """
        if (
            self._mongo_connector.perform_count(
                self._jobs_collection, {"job_name": job_name}
            )
            == 0
        ):
            now = datetime.now()
            self._mongo_connector.perform_insert(
                self._jobs_collection,
                {"job_name": job_name, "status": self.NOT_RUN, "updated": now},
            )

    def create_job(self, job_name):
        """
        Create a new job in the jobs_collection.
        """
        self.__check_job_exists(job_name)

    def record_job_start(self):
        """
        This will record the job as having started processing.
        """
        self.__check_job_exists(self._job_name)
        self._jobs_collection.update_one(
            {"job_name": self._job_name},
            {"$currentDate": {"updated": True}, "$set": {"status": self.RUNNING}},
        )

    def record_job_error(self):
        """
        This will record the job as having encountered an ERROR during its run.
        """
        self.__check_job_exists(self._job_name)
        self._jobs_collection.update_one(
            {"job_name": self._job_name},
            {"$currentDate": {"updated": True}, "$set": {"status": self.ERROR}},
        )

    def record_job_complete(self):
        """
        This will record the job as having successfully completed its run.
        """
        self.__check_job_exists(self._job_name)
        self._jobs_collection.update_one(
            {"job_name": self._job_name},
            {"$currentDate": {"updated": True}, "$set": {"status": self.COMPLETE}},
        )
