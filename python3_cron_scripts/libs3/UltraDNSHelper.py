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

"""
This script contains the helper functions for querying UltraDNS.

To login, the initial query is made with grant_type=password. The subsequent
query to fetch the access token post the initial expiration time is made with
grant_type=refresh_token
"""

import logging

import backoff
import requests

from libs3 import APIHelper, JobsManager, MongoConnector, UltraDNSConnector


class UltraDNSHelper(object):
    refresh_token = None
    access_token = None
    zone_queried = None
    previous_zones = None
    jobs_manager = None
    offset = 0
    source = "UltraDNS"
    # This is as required by the UltraDNS documentation.
    access_token_expiration_error = "invalid_grant:Token not found, expired or invalid."

    MC = MongoConnector.MongoConnector()
    APIH = APIHelper.APIHelper()

    # Get the UltraDNS connection data
    ULTRACONNECT = UltraDNSConnector.UltraDNSConnector()

    zones_collection = MC.get_zone_connection()

    _logger = None

    def _log(self):
        """
        Get the log
        """
        return logging.getLogger(__name__)

    @backoff.on_exception(
        backoff.expo,
        requests.exceptions.ConnectionError,
        max_tries=4,
        factor=10,
        on_backoff=APIH.connection_error_retry,
    )
    def backoff_api_retry(self, url, params, headers):
        """
        Makes API calls with exponential retry capabilities using 'backoff'. The API is
        retried 3 times in case of ConnectionError exception before the script exists.
        """
        return requests.get(url, params, headers=headers, timeout=120)

    @backoff.on_exception(
        backoff.expo,
        requests.exceptions.ConnectionError,
        max_tries=4,
        factor=10,
        on_backoff=APIH.connection_error_retry,
    )
    def login(self, grant_type):
        """
        Retrieves the access and refresh token to login into UltraDNS.
        The first call is made with grant_type=password. Any subsequent request
        to fetch the accessToken is made with grant_type=refresh_token.
        :param grant_type: String specifying the grant_type
        """
        login_url = self.ULTRACONNECT.LOGIN
        data = dict()
        data["grant_type"] = grant_type

        if grant_type == "password":
            data["username"] = self.ULTRACONNECT.USERNAME
            data["password"] = self.ULTRACONNECT.PASSWORD
        elif grant_type == "refresh_token":
            data["refresh_token"] = self.refresh_token

        try:
            res = requests.post(login_url, data, timeout=120)
            res.raise_for_status()
        except requests.exceptions.HTTPError as herr:
            self.APIH.handle_api_error(str(herr) + " : " + res.text, self.jobs_manager)
        else:
            token = res.json()
            self.refresh_token = token["refreshToken"]
            self.access_token = token["accessToken"]

    def get_previous_zones(self):
        """
        Fetches the currently present zones/sub-zones in the zone collection with source 'UltraDNS'.
        The result is a dictionary with the zones as keys. The value of the key is True if the zone
        is sub_zone.
        """
        zones = self.zones_collection.find(
            {
                "$or": [
                    {"reporting_sources.source": self.source},
                    {"sub_zones.source": self.source},
                ]
            },
            {"reporting_sources": 1, "zone": 1, "sub_zones": 1},
        )
        self.previous_zones = {}
        for zone in zones:
            for reporting_source in zone["reporting_sources"]:
                if reporting_source["source"] == self.source:
                    self.previous_zones[zone["zone"]] = False
            for sub_zone in zone["sub_zones"]:
                if sub_zone["source"] == self.source:
                    self.previous_zones[sub_zone["sub_zone"]] = True

    def set_offset(self, result_info):
        """
        Sets the offset value for the next API call to be made to UtraDNS.
        :param result_info: Part of response containing pagination infomation.
        """
        # The 'returnedCount' is the number of entries returned in the current API call.
        # Add this to the previous offset to get the new offset. If the new offset value
        # equals the 'totalCount' of records, unset offset to 0 to symbolise end of records.
        self.offset += result_info["returnedCount"]
        if self.offset == result_info["totalCount"]:
            self.offset = 0

    def __init__(self, invoking_job):
        self._logger = self._log()

        self.incorrect_response_json_allowed = self.APIH.INCORRECT_RESPONSE_JSON_ALLOWED
        # invoking_job is the job accessing the helper.
        self.jobs_manager = JobsManager.JobsManager(self.MC, invoking_job)
        self.login("password")
