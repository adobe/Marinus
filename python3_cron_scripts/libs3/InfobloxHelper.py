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
This helper class will provide the utility functions to the Infoblox scripts.
"""

import re

from libs3 import InfobloxConnector, MongoConnector


class InfobloxHelper(object):
    MC = MongoConnector.MongoConnector()

    IC = InfobloxConnector.InfobloxConnector()
    jobs_collection = MC.get_jobs_connection()

    IBLOX_HOST = IC.HOST
    IBLOX_UNAME = IC.UNAME
    IBLOX_PASSWD = IC.PASSWD
    IBLOX_VERSION = IC.VERSION

    IBLOX_COLLECTIONS = {
        "a": "get_infoblox_address_connection",
        "cname": "get_infoblox_cname_connection",
        "host": "get_infoblox_host_connection",
        "mx": "get_infoblox_mx_connection",
        "txt": "get_infoblox_txt_connection",
        "aaaa": "get_infoblox_aaaa_connection",
    }

    @staticmethod
    def __convert_zone_to_regex(zone_queried):
        """
        Converts the zone value into the regex which retrieves name/fqdn which
        end with the zone value. This hence fetches values for sub-zones also.
        :return: regex object
        """
        regex_string = "^(.*\\.)*" + re.escape(zone_queried) + "$"
        return re.compile(regex_string)

    @staticmethod
    def get_pagination_params(next_page_id):
        """
        The paging format for Infoblox expects _paging and _return_as_object to be set as 1
        for the first call. Post this, _next_page_id is used to retrieve the subsequent page
        data.
        """
        paging_info = "&_paging=1&_return_as_object=1&_max_results=1500"
        if next_page_id:
            paging_info = "&_page_id=" + next_page_id
        return paging_info

    def get_infoblox_base_url(self, zone, record_type):
        """
        Returns the base url to be queried for Infoblox.
        :param zone: Zone value to be queried
        :param record_type: Record type(host, a, cname, zone, mx, txt) to be queried.
        :return: string: Base URL.
        """
        zone_regex = self.__convert_zone_to_regex(zone)
        url = (
            "https://"
            + self.IBLOX_HOST
            + "/wapi/v"
            + self.IBLOX_VERSION
            + "/record:"
            + record_type
            + "?view=External&name~="
            + zone_regex.pattern
            + "{return_fields}{paging_info}"
        )

        if record_type == "zone":
            url = (
                "https://"
                + self.IBLOX_HOST
                + "/wapi/v"
                + self.IBLOX_VERSION
                + "/zone_auth?view=External&fqdn~="
                + zone_regex.pattern
                + "{return_fields}{paging_info}"
            )

        return url

    @staticmethod
    def clean_collection(previous_records, collection):
        """
        Cleans the database of the records which are not seen again on the basis of the _ref value.
        """
        for previous_record in previous_records:
            collection.delete_one({"_ref": previous_record})
