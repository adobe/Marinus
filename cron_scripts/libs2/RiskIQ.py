#!/usr/bin/python

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
This module handles interactions with the RiskIQ service.
"""

import ConfigParser
import json
import requests
from requests.auth import HTTPBasicAuth


class RiskIQ(object):
    """
    This class is designed for interacting with RiskIQ
    """

    riskiq_config_file = 'connector.config'
    KEY = None
    TOKEN = None
    URL = None
    debug = False

    @staticmethod
    def _get_config_setting(config, section, key, type='str'):
        """
        Retrieves the key value from inside the section the connector.config file.

        This function is in multiple modules because it was originally designed
        that each module could be standalone.

        :param config: A Python ConfigParser object
        :param section: The section where the key exists
        :param key: The name of the key to retrieve
        :param type: (Optional) Specify 'boolean' to convert True/False strings to booleans.
        :return: A string or boolean from the config file.
        """
        try:
            if type == 'boolean':
                result = config.getboolean(section, key)
            else:
                result = config.get(section, key)
        except ConfigParser.NoSectionError as err:
            print 'Warning: ' + section + ' does not exist in config file'
            if type == 'boolean':
                return 0
            else:
                return ""
        except ConfigParser.NoOptionError as err:
            print 'Warning: ' + key + ' does not exist in the config file'
            if type == 'boolean':
                return 0
            else:
                return ""
        except ConfigParser.Error as err:
            print 'Warning: Unexpected error with config file'
            if type == 'boolean':
                return 0
            else:
                return ""

        return result


    def _init_riskiq(self, config, debug):
        self.URL = self._get_config_setting(config, "RiskIQ", "riskiq.url")
        self.KEY = self._get_config_setting(config, "RiskIQ", "riskiq.key")
        self.TOKEN = self._get_config_setting(config, "RiskIQ", "riskiq.token")


    def __init__(self, config_file="", debug=False):
        if config_file != "":
            self.riskiq_config_file = config_file
        self.debug = debug

        config = ConfigParser.ConfigParser()
        list = config.read(self.riskiq_config_file)
        if len(list) == 0:
            print 'Error: Could not find the config file'
            exit(0)

        self._init_riskiq(config, debug)


    def get_whois(self, email, domain):
        """
        Search the whois database for the provided email and domain scope.

        @param email The email to search for in the whois/query API.
        @param domain The domain to search for in the whois/query API.
        @return the JSON response or None if not found
        """
        post_data = {'email': email, 'domain': domain, 'maxResults': 1000}
        post_headers = {"Accept": "application/json", "Content-type": "application/json"}
        req = requests.post(self.URL + "whois/query", json=post_data, headers=post_headers,
                            auth=HTTPBasicAuth(self.TOKEN, self.KEY))

        if req.status_code != 200:
            print req.status_code
            print req.text
            return None

        try:
            res = json.loads(req.text)
        except:
            return None

        return res
