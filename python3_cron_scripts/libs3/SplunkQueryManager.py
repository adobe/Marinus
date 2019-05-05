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
This module allows scripts to perform paginated queries against a Splunk server.
"""

import configparser
import json
import time

import splunklib.client as client
import splunklib.results as results
from splunklib.binding import HTTPError

from libs3 import SplunkConnector


class SplunkQueryManager(object):

    # The offset within the query
    _OFFSET = 0

    # How many results to fetch
    _COUNT = 100

    # The result count
    RESULTCOUNT = 0

    # The Splunk client connection
    _CLIENT = None

    # A pointer to the last job executed
    _JOB = None


    def __init__(self, debug=False):
        """
        Initialize the query manager
        """
        self.debug = debug

        if self._CLIENT == None:
            splunk_connector = SplunkConnector.SplunkConnector()
            self._CLIENT = splunk_connector.get_splunk_client()

        self._OFFSET = 0
        self._COUNT = 100


    def _create_job(self, search_query):
        """
        Create the new job
        """
        return self._CLIENT.jobs.create(search_query, **{"exec_mode": "blocking"})


    def do_search(self, search_query, count):
        """
        Perform a paginated search.
        The search query should in the format of "search index=...."
        Count refers to the number of results per page.
        """

        self._JOB = self._create_job(search_query)
        self._COUNT = count

        self.RESULTCOUNT = int(self._JOB["resultCount"])

        if self.RESULTCOUNT < self._COUNT:
            result_stream = self._JOB.results()
            return results.ResultsReader(result_stream)


        kwargs_paginate = {"count": self._COUNT,
                            "offset": self._OFFSET}

        blocksearch_results = self._JOB.results(**kwargs_paginate)

        self._OFFSET = self._OFFSET + self._COUNT

        return results.ResultsReader(blocksearch_results)


    def get_next_page(self):
        """
        Get the next page of query results
        """
        if self._OFFSET >= self.RESULTCOUNT:
            return None

        kwargs_paginate = {"count": self._COUNT,
                            "offset": self._OFFSET}

        try:
            blocksearch_results = self._JOB.results(**kwargs_paginate)
        except HTTPError as http_error:
            print("First HTTP Error: " + str(http_error))
            time.sleep(10)
            try:
                blocksearch_results = self._JOB.results(**kwargs_paginate)
            except HTTPError as http_error:
                print("Second HTTP Error! " + str(http_error))
                exit(1)
        except SocketError as socket_error:
            if socket_error.errno != errno.ECONNRESET:
                raise
            else:
                print("First Socket Timeout Error: " + str(socket_error))
                time.sleep(10)
                try:
                    blocksearch_results = self._JOB.results(**kwargs_paginate)
                except SocketError as socket_error:
                    print("Second Socket Timeout Error! " + str(socket_error))
                    exit(1)

        self._OFFSET = self._OFFSET + self._COUNT

        return results.ResultsReader(blocksearch_results)

