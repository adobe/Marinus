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

from libs3 import MongoConnector


class APIHelper(object):

    MC = MongoConnector.MongoConnector()
    jobs_collection = MC.get_jobs_connection()

    INCORRECT_RESPONSE_JSON_ALLOWED = 20

    def handle_api_error(self, err, job_name):
        """
        Exits the script execution post setting the status in database.
        :param err: Exception causing script exit.
        :param job_name: Script exiting.
        """
        print(err)
        print('Exiting script execution.')
        self.jobs_collection.update_one({'job_name': job_name},
                                        {'$currentDate': {'updated': True},
                                         '$set': {'status': 'ERROR'}})
        exit(1)

    @staticmethod
    def connection_error_retry(details):
        print('Connection Error encountered. Retrying in {wait:0.1f} seconds'.format(**details))
