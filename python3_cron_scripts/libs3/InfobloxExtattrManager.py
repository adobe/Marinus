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
This script queries Infoblox for the extattr information.

The Infoblox are used in the paginated form to handle large data sets.

The script allows for 20 incorrect response jsons and 3 connection failures
to be received post which the script exits. In case a connection failure is
encountered, the script sleeps for 10secs before re-trying the previous call.

The script exits when request exceptions are encountered.
"""

import logging
from datetime import datetime

import backoff
import requests
from requests.auth import HTTPBasicAuth

from libs3 import APIHelper, InfobloxHelper, MongoConnector
from libs3.ZoneManager import ZoneManager


class InfobloxExtattrManager(object):
    # Make database connections
    MC = MongoConnector.MongoConnector()
    APIH = APIHelper.APIHelper()
    IH = InfobloxHelper.InfobloxHelper()

    iblox_extattr_collection = MC.get_infoblox_extattr_connection()
    zone_queried = None
    record_type = None
    next_page_id = None
    _logger = None

    def _log(self):
        """
        Get the log
        """
        return logging.getLogger(__name__)

    def __get_record_type_url(self):
        """
        Returns the url to be queried at infoblox to return the extattr information.
        Paging information is appended to the URL as per the condition satisfied.
        :return: string: URL to be queried
        """
        paging_info = self.IH.get_pagination_params(self.next_page_id)

        return_fields = "&_return_fields=extattrs,zone"
        if self.record_type == "a":
            return_fields += ",ipv4addr"
        elif self.record_type == "aaaa":
            return_fields += ",ipv6addr"
        elif self.record_type == "zone":
            return_fields = "&_return_fields=extattrs"

        url = self.IH.get_infoblox_base_url(
            self.zone_queried,
            self.record_type,
        ).format(
            return_fields=return_fields,
            paging_info=paging_info,
        )
        return url

    def __insert_extattrs(self, insert_object):
        """
        Inserts/Updates the extattr information in the database. '_ref' uniquely identifies the
        resource.
        :param insert_object: Dictionary containing the details of the resource.
        """
        if not insert_object["_ref"] in self.previous_records:
            insert_object["created"] = datetime.now()
            insert_object["updated"] = datetime.now()
            self.MC.perform_insert(self.iblox_extattr_collection, insert_object)
        else:
            self.previous_records.remove(insert_object["_ref"])
            self.iblox_extattr_collection.update_one(
                {"_ref": insert_object["_ref"]},
                {
                    "$set": {
                        "updated": datetime.now(),
                        "extattrs": insert_object["extattrs"],
                    }
                },
            )

    def __get_previous_records(self):
        """
        Retrieve the current data related to the zone and record_type. This is evaluated
        against the data that we receive in the latest script run to determine stale records.
        The data is stored as a list of _ref
        """
        self.previous_records = []
        previous_records = self.iblox_extattr_collection.find(
            {
                "zone": self.zone_queried,
                "record_type": self.record_type,
            },
            {"_ref": 1},
        )
        for record in previous_records:
            self.previous_records.append(record["_ref"])

    def __sanitise_response(self, response_object):
        """
        For record_type of zone type, we extract 'infoblox_zone' from the '_ref'.
        For record_type of a type, we get the 'value' from the 'ipv4addr' key for other
        record_types it is extracted from '_ref'
        The general format of _ref is: {record_type_iden}/{hash_iden}:{value}/External
        The valid record_type_iden values are 'zone_auth', 'record:cname', 'record:host', 'record:a'
        :param response_object: Value of 'result' key of response in JSON format.
        """
        insert_object = {
            "record_type": self.record_type,
            "zone": self.zone_queried,
        }

        if self.record_type == "zone":
            response_object["infoblox_zone"] = (
                response_object["_ref"].split(":")[1].split("/")[0]
            )
        else:
            response_object["infoblox_zone"] = response_object["zone"]
            response_object.pop("zone")

        if self.record_type == "a":
            response_object["value"] = response_object["ipv4addr"]
            response_object.pop("ipv4addr")
        elif self.record_type == "aaaa":
            response_object["value"] = response_object["ipv6addr"]
            response_object.pop("ipv6addr")
        else:
            response_object["value"] = (
                response_object["_ref"].split("/")[1].split(":")[1]
            )

        response_object.update(insert_object)

    def __infoblox_response_handler(self, response):
        """
        Handles the API response. Incorrect JSON parsing is allowed upto 20 times post which the
        script exits. No action is performed when the 'extattrs' is an empty dictionary.
        :param response: Response object
        """
        try:
            response_data = response.json()
            response_result = response_data["result"]
        except (ValueError, AttributeError) as err:
            if self.incorrect_response_json_allowed > 0:
                self._logger.warning(
                    "Unable to parse response JSON for zone " + self.zone_queried
                )
                self.incorrect_response_json_allowed -= 1
            else:
                self.APIH.handle_api_error(
                    "Unable to parse response JSON for 20 zones: " + repr(err),
                    "get_infoblox_" + self.record_type.lower() + "_extattrs",
                )
        else:
            for response_object in response_result:
                if not response_object["extattrs"]:
                    continue

                # Adding the exception handling for the scenario when the '_ref' format
                # changes and leads to 'split' not working as expected.
                try:
                    self.__sanitise_response(response_object)
                except IndexError as err:
                    self.APIH.handle_api_error(
                        err, "get_infoblox_" + self.record_type.lower() + "_extattrs"
                    )
                else:
                    self.__insert_extattrs(response_object)

            if "next_page_id" in response_data:
                self.next_page_id = response_data["next_page_id"]

    @backoff.on_exception(
        backoff.expo,
        requests.exceptions.ConnectionError,
        max_tries=4,
        factor=10,
        on_backoff=APIH.connection_error_retry,
    )
    def __backoff_api_retry(self):
        """
        Makes API calls to Infoblox with exponential retry capabilities using 'backoff'. The API is
        retried 3 times in case of ConnectionError exception before the script exists.
        :return:
        """
        return requests.get(
            (self.__get_record_type_url()),
            auth=HTTPBasicAuth(self.IH.IBLOX_UNAME, self.IH.IBLOX_PASSWD),
            timeout=120,
        )

    def __infoblox_paginated_request(self):
        """
        Makes paginated API calls to Infoblox. The API is retried 3 times in case of ConnectionError
        exception before the script exists. The script exists on encountering HTTPError or any other
        RequestException. On success, the next_page_id is set to None for the next API call.
        """
        try:
            response = self.__backoff_api_retry()
            response.raise_for_status()
        except requests.exceptions.HTTPError as herr:
            self.APIH.handle_api_error(
                herr, "get_infoblox_" + self.record_type.lower() + "_extattrs"
            )
        except requests.exceptions.RequestException as err:
            self.APIH.handle_api_error(
                err, "get_infoblox_" + self.record_type.lower() + "_extattrs"
            )
        else:
            self.next_page_id = None
            self.__infoblox_response_handler(response)

    def get_infoblox_extattr(self):
        """
        Extracts the zones from the zone collection to query Infoblox. The API calls continue to be made
        for the zone till the next_page_id is set to None indicating no new results to be fetched.
        Post the retrieval of all the data, the archaic data for a zone and record_type is purged.
        """
        zones = ZoneManager.get_zones_by_source(self.MC, "Infoblox")
        for zone in zones:
            self.zone_queried = zone
            self.next_page_id = None
            self.__get_previous_records()
            self.__infoblox_paginated_request()
            while self.next_page_id:
                self.__infoblox_paginated_request()
            self.IH.clean_collection(
                self.previous_records, self.iblox_extattr_collection
            )

    def __init__(self, record_type):
        self.record_type = record_type
        self.incorrect_response_json_allowed = self.APIH.INCORRECT_RESPONSE_JSON_ALLOWED
        self._logger = self._log()
