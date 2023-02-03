#!/usr/bin/python3

# Copyright 2021 Adobe. All rights reserved.
# This file is licensed to you under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License. You may obtain a copy
# of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR REPRESENTATIONS
# OF ANY KIND, either express or implied. See the License for the specific language
# governing permissions and limitations under the License.

"""
This script fetches new zones (root domains) from UltraDNS.
This script should be run prior to executing get_ultradns_zones_info.

This script assumes that you are an UltraDNS customer.
"""

import json
import logging
from datetime import datetime

import requests
from libs3 import APIHelper, UltraDNSHelper, ZoneIngestor
from libs3.LoggingUtil import LoggingUtil


class UltraDNSZone(object):
    UH = UltraDNSHelper.UltraDNSHelper("get_ultradns_zones")
    APIH = APIHelper.APIHelper()
    ZI = ZoneIngestor.ZoneIngestor()
    _logger = None

    def __ultradns_zone_response_handler(self, response):
        """
        Handles the API response. Incorrect JSON parsing is allowed upto 20 times post which the
        script exits. No action is performed when the zone name ends in "in-addr.arpa".
        :param response: Response object
        """
        try:
            response = response.json()
        except (ValueError, AttributeError) as err:
            if self.UH.incorrect_response_json_allowed > 0:
                self._logger.warning(
                    "Unable to parse response JSON for retrieving UltraDNS zones for the offset"
                    + self.UH.offset
                )
                self.UH.incorrect_response_json_allowed -= 1
            else:
                self.APIH.handle_api_error(
                    "Unable to parse response JSON for 20 zones: " + repr(err),
                    self.UH.jobs_manager,
                )
        else:
            # the zone names end in '.'. Removing that before ingesting into collection.
            for zone in response["zones"]:
                zone_name = zone["properties"]["name"][:-1]

                if not zone_name.endswith("in-addr.arpa"):
                    # Part of clean_collection code.
                    # if zone_name in self.UH.previous_zones:
                    #     del self.UH.previous_zones[zone_name]

                    custom_fields = {}
                    custom_fields["accountName"] = zone["properties"]["accountName"]
                    if "owner" in zone["properties"]:
                        custom_fields["owner"] = zone["properties"]["owner"]

                    # Add the zone to the zones collection
                    self.ZI.add_zone(
                        zone_name, self.UH.source, custom_fields=custom_fields
                    )

            self.UH.set_offset(response["resultInfo"])

    def __paginated_ultradns_zones_request(self):
        """
        Makes paginated API calls to UltraDNS. The API is retried 3 times in case of ConnectionError
        exception before the script exists. The script exists on encountering HTTPError or any other
        RequestException.
        The value of the limit has been set as mentioned in the docs.
        In case a 401 is encountered along with the required token expiration message, another login
        API is sent with grant_type set as 'refresh_token' to retrieve a valid access token.
        """
        url = self.UH.ULTRACONNECT.ZONES
        try:
            res = self.UH.backoff_api_retry(
                url,
                {"limit": 1000, "offset": self.UH.offset, "q": "zone_type:PRIMARY"},
                {"authorization": "Bearer " + self.UH.access_token},
            )
            res.raise_for_status()
        except requests.exceptions.HTTPError as herr:
            err_msg = json.loads(res.text)["errorMessage"]
            if (
                res.status_code == 401
                and err_msg == self.UH.access_token_expiration_error
            ):
                self.UH.login("refresh_token")
                self.__paginated_ultradns_zones_request()
            else:
                self.APIH.handle_api_error(herr, self.UH.jobs_manager)
        except requests.exceptions.RequestException as err:
            self.APIH.handle_api_error(err, self.UH.jobs_manager)
        else:
            self.__ultradns_zone_response_handler(res)

    def get_ultradns_zones(self):
        """
        Extracts the zones listing from UltraDNS in a paginated manner.
        """

        self.UH.jobs_manager.record_job_start()

        # Part of clean_collection code.
        # self.UH.get_previous_zones()

        self.__paginated_ultradns_zones_request()
        while self.UH.offset:
            self.__paginated_ultradns_zones_request()

        # Record status
        self.UH.jobs_manager.record_job_complete()

    def __init__(self):
        self._logger = logging.getLogger(__name__)
        self.get_ultradns_zones()


def main(logger=None):
    if logger is None:
        logger = LoggingUtil.create_log(__name__)

    print("Starting: " + str(datetime.now()))
    logger.info("Starting...")

    LocalUltraDNSZone = UltraDNSZone()

    print("Ending: " + str(datetime.now()))
    logger.info("Complete.")


if __name__ == "__main__":
    logger = LoggingUtil.create_log(__name__)

    try:
        main(logger)
    except Exception as e:
        logger.error("FATAL: " + str(e), exc_info=True)
        exit(1)
