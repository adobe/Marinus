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
This script fetches the zones DNS information from UltraDNS.

This script assumes that you are an UltraDNS customer.
"""

import requests
import json
from datetime import datetime
from netaddr import IPAddress
from netaddr.core import AddrFormatError
from libs3 import APIHelper, DNSManager, UltraDNSHelper


class UltraDNSZonesInfo(object):

    UH = UltraDNSHelper.UltraDNSHelper('get_ultradns_zones_info')
    APIH = APIHelper.APIHelper()
    DNS_MGR = DNSManager.DNSManager(UH.MC)

    def __ultradns_zone_info_response_handler(self, response):
        """
        Handles the API response. Incorrect JSON parsing is allowed upto 20 times post which the
        script exits.
        :param response: Response object
        """
        try:
            response_data = response.json()
            record_sets = response_data['rrSets']
        except (ValueError, AttributeError) as err:
            if self.UH.incorrect_response_json_allowed > 0:
                print('Unable to parse response JSON for zone ' + self.zone_queried)
                self.UH.incorrect_response_json_allowed -= 1
            else:
                self.APIH.handle_api_error(
                    'Unable to parse response JSON for 20 zones: ' + repr(err),
                    'get_ultradns_zones_info',
                )
        else:
            for record in record_sets:
                dns_info = dict()
                # The ownerName could be either the FQDN or a relative domain name.
                # In case it is a FQDN it will end in '.'
                fqdn = record['ownerName'] + '.' + self.zone_queried
                if record['ownerName'].endswith('.'):
                    fqdn = record['ownerName'][:-1]

                dns_info['zone'] = self.zone_queried
                dns_info['fqdn'] = fqdn
                dns_info['type'] = record['rrtype'].split(' ')[0].lower()
                dns_info['status'] = 'unknown'

                for dns in record['rdata']:
                    if dns_info['type'] in ['a', 'ptr']:
                        try:
                            if IPAddress(dns).is_private():
                                continue
                        except AddrFormatError as err:
                            print('For ' + fqdn + ' encountered: ' + str(err))
                            continue

                    if not(dns_info['type'] in ['soa', 'txt']) and dns.endswith('.'):
                        dns = dns[:-1]
                    dns_info['value'] = dns
                    dns_info['created'] = datetime.now()
                    self.DNS_MGR.insert_record(dns_info.copy(), self.UH.source)

            self.UH.set_offset(response_data['resultInfo'])

    def __paginated_ultradns_zones_info_request(self):
        """
        Makes paginated API calls to UltraDNS. The API is retried 3 times in case of ConnectionError
        exception before the script exists. The script exists on encountering HTTPError or any other
        RequestException.
        In case a 401 is encountered along with the required token expiration message, another login
        API is sent with grant_type set as 'refresh_token' to retrieve a valid access token.
        """
        url = self.UH.ULTRACONNECT.ZONEINFO.format(zone_queried=self.zone_queried)
        try:
            response = self.UH.backoff_api_retry(
                url,
                {
                    'q': 'kind:RECORDS',
                    'limit': 2000,
                    'offset': self.UH.offset,
                },
                {'authorization': 'Bearer ' + self.UH.access_token}
            )
            response.raise_for_status()
        except requests.exceptions.HTTPError as herr:
            err_msg = json.loads(response.text)['errorMessage']
            if response.status_code == 401 and err_msg == self.UH.access_token_expiration_error:
                self.UH.login('refresh_token')
                self.__paginated_ultradns_zones_info_request()
            else:
                self.APIH.handle_api_error(herr, 'get_ultradns_zones_info')
        except requests.exceptions.RequestException as err:
            self.APIH.handle_api_error(err, 'get_ultradns_zones_info')
        else:
            self.__ultradns_zone_info_response_handler(response)

    def __get_ultradns_zones_info(self):
        """
        Extracts the zone DNS information from UltraDNS in a paginated manner for the UltraDNS zones.
        """
        print("Starting: " + str(datetime.now()))
        self.UH.get_previous_zones()

        # For querying UltraDNS, we need to query on the exact zones reported
        # hence we query for previous_zones.
        for zone in self.UH.previous_zones:
            self.zone_queried = zone
            self.UH.offset = 0
            self.__paginated_ultradns_zones_info_request()
            while self.UH.offset:
                self.__paginated_ultradns_zones_info_request()

        # Record status
        self.APIH.jobs_collection.update_one({'job_name': 'get_ultradns_zones_info'},
                                             {'$currentDate': {"updated": True},
                                              "$set": {'status': 'COMPLETE'}})
        print("Ending: " + str(datetime.now()))

    def __init__(self):
        self.__get_ultradns_zones_info()


if __name__ == '__main__':
    UltraDNSZonesInfo = UltraDNSZonesInfo()
