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

import errno
import json
import logging
import time
from socket import error as SocketError

import splunklib.client as client
import splunklib.results as results
from libs3 import SplunkConnector
from splunklib.binding import HTTPError


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

    # The logger
    _logger = None

    def _log(self):
        """
        Get the log
        """
        return logging.getLogger(__name__)

    def __init__(self, config_file="", log_level=None):
        """
        Initialize the query manager
        """
        self._logger = self._log()
        if log_level is not None:
            self._logger.setLevel(log_level)

        if self._CLIENT is None:
            splunk_connector = SplunkConnector.SplunkConnector(config_file)
            self._CLIENT = splunk_connector.get_splunk_client()

        if self._CLIENT is None:
            self._logger.error("FATAL: Could not create Splunk client")
            exit(1)

        self._OFFSET = 0
        self._COUNT = 100

    def _create_job(self, search_query):
        """
        Create the new job
        """
        return self._CLIENT.jobs.create(
            search_query, **{"exec_mode": "blocking", "output_mode": "json"}
        )

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
            result_stream = self._JOB.results(output_mode="json")
            return results.JSONResultsReader(result_stream)

        kwargs_paginate = {
            "count": self._COUNT,
            "offset": self._OFFSET,
            "output_mode": "json",
        }

        blocksearch_results = self._JOB.results(**kwargs_paginate)

        self._OFFSET = self._OFFSET + self._COUNT

        return results.JSONResultsReader(blocksearch_results)

    def get_next_page(self):
        """
        Get the next page of query results
        """
        if self._OFFSET >= self.RESULTCOUNT:
            return None

        kwargs_paginate = {
            "count": self._COUNT,
            "offset": self._OFFSET,
            "output_mode": "json",
        }

        try:
            blocksearch_results = self._JOB.results(**kwargs_paginate)
        except HTTPError as http_error:
            self._logger.warning("First HTTP Error: " + str(http_error))
            time.sleep(10)
            try:
                blocksearch_results = self._JOB.results(**kwargs_paginate)
            except HTTPError as http_error:
                self._logger.error("FATAL: Second HTTP Error! " + str(http_error))
                exit(1)
        except SocketError as socket_error:
            if socket_error.errno != errno.ECONNRESET:
                raise
            else:
                self._logger.warning("First Socket Timeout Error: " + str(socket_error))
                time.sleep(15)
                try:
                    blocksearch_results = self._JOB.results(**kwargs_paginate)
                except SocketError as socket_error:
                    self._logger.error(
                        "FATAL: Second Socket Timeout Error! " + str(socket_error)
                    )
                    exit(1)

        self._OFFSET = self._OFFSET + self._COUNT

        return results.JSONResultsReader(blocksearch_results)
