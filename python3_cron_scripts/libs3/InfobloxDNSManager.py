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
This script queries Infoblox for the host, a, cname, mx and txt information of the domain belonging to
the zones in the zone collection.
'_ref' uniquely identifies the resource.
The general format of _ref is: {record_type_iden}/{hash_iden}:{value}/External
The valid record_type_iden values are 'zone_auth', 'record:cname', 'record:host', 'record:a'
"""

import logging
from datetime import datetime

import backoff
import requests
from libs3 import APIHelper, DNSManager, InfobloxHelper, MongoConnector
from libs3.ZoneManager import ZoneManager
from requests.auth import HTTPBasicAuth


class InfobloxDNSManager(object):
    # Make database connections
    MC = MongoConnector.MongoConnector()
    zone_collection = MC.get_zone_connection()

    APIH = APIHelper.APIHelper()
    IH = InfobloxHelper.InfobloxHelper()
    DNS_MGR = DNSManager.DNSManager(MC)

    next_page_id = None
    zone_queried = None
    record_type = None
    iblox_collection = None
    dns_value_mapper = {
        "mx": "mail_exchanger",
        "txt": "text",
        "a": "ipv4addr",
        "cname": "canonical",
        "aaaa": "ipv6addr",
    }
    _logger = None

    def _log(self):
        """
        Get the log
        """
        return logging.getLogger(__name__)

    def __get_record_type_url(self):
        """
        Returns the url to be queried at infoblox to return the DNS information.
        Paging information is appended to the URL as per the condition satisfied.
        :return: string: URL to be queried
        """
        paging_info = self.IH.get_pagination_params(self.next_page_id)

        url = self.IH.get_infoblox_base_url(
            self.zone_queried,
            self.record_type,
        ).format(
            return_fields="&_return_fields%2B=zone",
            paging_info=paging_info,
        )
        return url

    def __get_previous_records(self):
        """
        Retrieve the current data related to the zone. This is evaluated against the data that we
        receive in the latest script run to determine stale records.
        The data is stored as a list of _ref.
        """
        self.previous_records = self.iblox_collection.distinct(
            "_ref", {"zone": self.zone_queried}
        )

    def __insert_dns_information(self, dns_information):
        """
        Inserts the DNS information into the all_dns collection. For the 'host' records, iterate over
        all the ipv4addrs mentioned to get the data.
        :param dns_information: DNS data for the zone and 'record_type'
        """
        del dns_information["_ref"]
        del dns_information["view"]
        del dns_information["infoblox_zone"]

        if self.record_type == "host":
            # In order to resolve multiple ipv4addrs
            if "ipv4addrs" in dns_information:
                for ipv4 in dns_information["ipv4addrs"]:
                    dns_info = dict()
                    dns_info["zone"] = dns_information["zone"]
                    dns_info["type"] = "a"
                    dns_info["value"] = ipv4["ipv4addr"]
                    dns_info["fqdn"] = ipv4["host"]
                    dns_info["status"] = "unknown"
                    dns_info["created"] = datetime.now()
                    self.DNS_MGR.insert_record(dns_info, "infoblox-host")
            elif "ipv6addrs" in dns_information:
                for ipv6 in dns_information["ipv6addrs"]:
                    dns_info = dict()
                    dns_info["zone"] = dns_information["zone"]
                    dns_info["type"] = "aaaa"
                    dns_info["value"] = ipv6["ipv6addr"]
                    dns_info["fqdn"] = ipv6["host"]
                    dns_info["status"] = "unknown"
                    dns_info["created"] = datetime.now()
                    self.DNS_MGR.insert_record(dns_info, "infoblox-host")
            else:
                self._logger.error(
                    "FATAL: No IPv4 or IPv6 informaiton found in host records for: "
                    + str(dns_information["zone"])
                )
        else:
            # Removing the 'preference' key from the 'mx' records
            dns_information["value"] = dns_information[
                self.dns_value_mapper[self.record_type]
            ]
            # Reconstruct the actual MX record
            if self.record_type == "mx":
                dns_information["value"] = (
                    str(dns_information["preference"])
                    + " "
                    + dns_information["value"]
                    + "."
                )
                del dns_information["preference"]

            del dns_information[self.dns_value_mapper[self.record_type]]
            dns_information["fqdn"] = dns_information["name"]
            del dns_information["name"]
            dns_information["type"] = self.record_type
            dns_information["status"] = "unknown"
            dns_information["created"] = datetime.now()
            self.DNS_MGR.insert_record(dns_information, "infoblox-" + self.record_type)

    def __insert_records(self, insert_object):
        """
        Inserts/Updates the dns information in the database. '_ref' uniquely identifies the
        resource. The data is injected into the individual collections belonging to the
        record_type and also into the all_dns collection.
        :param insert_object: Dictionary containing the details of the resource.
        """
        dns_information = insert_object.copy()
        if not insert_object["_ref"] in self.previous_records:
            insert_object["created"] = datetime.now()
            insert_object["updated"] = datetime.now()
            self.MC.perform_insert(self.iblox_collection, insert_object)
        else:
            self.previous_records.remove(insert_object["_ref"])
            insert_object["updated"] = datetime.now()
            self.iblox_collection.update_one(
                {"_ref": insert_object["_ref"]}, {"$set": insert_object}
            )
        # Update DNS Information.
        self.__insert_dns_information(dns_information)

    def __infoblox_response_handler(self, response):
        """
        Handles the API response. Incorrect JSON parsing is allowed upto 20 times post which the
        script exits. "next_page_id" holds the pagination information.
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
                    "get_iblox_" + self.record_type.lower(),
                )
        except Exception as unk_err:
            self.APIH.handle_api_error(
                "Unknown_exception occurred: " + repr(unk_err),
                "get_iblox_" + self.record_type.lower(),
            )
        else:
            # Add the zone parameter to each record and insert
            for entry in response_result:
                entry["infoblox_zone"] = entry["zone"]
                entry["zone"] = self.zone_queried
                self.__insert_records(entry)

            if "next_page_id" in response_data:
                self.next_page_id = response_data["next_page_id"]

    @backoff.on_exception(
        backoff.expo,
        requests.exceptions.ConnectionError,
        max_tries=4,
        factor=10,
        on_backoff=APIH.connection_error_retry,
        on_giveup=APIH.backoff_giveup,
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
            self.APIH.handle_api_error(herr, "get_iblox_" + self.record_type.lower())
        except requests.exceptions.RequestException as err:
            self.APIH.handle_api_error(err, "get_iblox_" + self.record_type.lower())
        except Exception as unk_err:
            self.APIH.handle_api_error(unk_err, "get_iblox_" + self.record_type.lower())
        else:
            self.next_page_id = None
            self.__infoblox_response_handler(response)

    def get_infoblox_dns(self):
        """
        Extracts the zones from the zone collection to query Infoblox. The API calls continue to be made
        for the zone till the next_page_id is set to None indicating no new results to be fetched.
        Post the retrieval of all the data, the archaic data for a zone is purged.
        """
        zones = ZoneManager.get_zones_by_source(self.MC, "Infoblox")
        for zone in zones:
            self.zone_queried = zone
            self.next_page_id = None
            self.__get_previous_records()
            self.__infoblox_paginated_request()
            while self.next_page_id:
                self.__infoblox_paginated_request()
            self.IH.clean_collection(self.previous_records, self.iblox_collection)

    def __init__(self, record_type):
        self.record_type = record_type
        self.iblox_collection = self.MC.__getattribute__(
            self.IH.IBLOX_COLLECTIONS[self.record_type]
        )()
        self.incorrect_response_json_allowed = self.APIH.INCORRECT_RESPONSE_JSON_ALLOWED
        self._logger = self._log()
