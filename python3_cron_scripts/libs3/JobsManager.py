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


from datetime import datetime

from libs3 import MongoConnector

class JobsManager(object):
    """
    The jobs collection is responsible for tracking the progress of the various scripts.
    This class is responsible for recording the status of jobs within the jobs collection.
    """
        
    # Job states
    NOT_RUN = "NOT_RUN"

    RUNNING = "RUNNING"

    ERROR = "ERROR"

    COMPLETE = "COMPLETE"

    # Debug
    DEBUG = False

    # JobsCollection
    _jobs_collection = None

    # Job Name
    _job_name = ""


    def __init__(self, mongo_connector, job_name, debug=False):
        self.debug = debug
        self.jobs_collection = mongo_connector.get_jobs_connection()
        self._job_name = job_name


    def __check_job_exists(self, job_name):
        """
        Verify that the job name exists in the collection.
        If the job does not exist, this will create it.
        """
        if self.jobs_collection.find({'job_name': job_name}).count() == 0:
            now = datetime.now()
            self.jobs_collection.insert({"job_name": job_name, "status": self.NOT_RUN, "updated": now})


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
        self.jobs_collection.update_one({'job_name': self._job_name},
                                        {'$currentDate': {"updated": True},
                                        "$set": {'status': self.RUNNING}})


    def record_job_error(self):
        """
        This will record the job as having encountered an ERROR during its run.
        """
        self.__check_job_exists(self._job_name)
        self.jobs_collection.update_one({'job_name': self._job_name},
                                        {'$currentDate': {"updated": True},
                                        "$set": {'status': self.ERROR}})


    def record_job_complete(self):
        """
        This will record the job as having successfully completed its run.
        """
        self.__check_job_exists(self._job_name)
        self.jobs_collection.update_one({'job_name': self._job_name},
                                        {'$currentDate': {"updated": True},
                                        "$set": {'status': self.COMPLETE}})
