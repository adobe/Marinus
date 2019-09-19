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
This module is for interacting with the VirusTotal service.
"""

import configparser
import json
import logging
import requests

class VirusTotal(object):
    """
    This class is designed for interacting with VirusTotal service.
    It currently supports fetching domain reports.
    """

    virustotal_config_file = 'connector.config'
    PRIVATE_APIKEY = None
    PUBLIC_APIKEY = None
    APIKEY = None
    URL = None
    _logger = None


    def _log(self):
        """
        Get the log
        """
        return logging.getLogger(__name__)


    @staticmethod
    def _get_config_setting(logger, config, section, key, type='str'):
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
        except configparser.NoSectionError:
            logger.warning ('Warning: ' + section + ' does not exist in config file')
            if type == 'boolean':
                return 0
            else:
                return ""
        except configparser.NoOptionError:
            logger.warning ('Warning: ' + key + ' does not exist in the config file')
            if type == 'boolean':
                return 0
            else:
                return ""
        except configparser.Error as err:
            logger.warning ('Warning: Unexpected error with config file')
            logger.warning (str(err))
            if type == 'boolean':
                return 0
            else:
                return ""

        return result


    def _init_vt(self, config):
        self.URL = self._get_config_setting(self._logger, config, "VirusTotal", "virustotal.url")
        self.PRIVATE_APIKEY = self._get_config_setting(self._logger, config, "VirusTotal", "virustotal.apikey")
        self.PUBLIC_APIKEY = self._get_config_setting(self._logger, config, "VirusTotal",
                                                      "virustotal.public_apikey")


    def __init__(self, config_file="", key="public", log_level=None):
        if config_file != "":
            self.virustotal_config_file = config_file

        self._logger = self._log()
        if log_level is not None:
            self._logger.setLevel(log_level)

        config = configparser.ConfigParser()
        list = config.read(self.virustotal_config_file)
        if len(list) == 0:
            self._logger.error ('Error: Could not find the config file')
            exit(0)

        self._init_vt(config)

        if key == "private":
            self.APIKEY = self.PRIVATE_APIKEY
        else:
            self.APIKEY = self.PUBLIC_APIKEY


    def get_domain_report(self, domain):
        """
        Get The Virustotal report for the given domain.

        :param domain: The name of the domain to search.
        :return: The JSON response or None if not found.
        """
        req = requests.get((self.URL + "domain/report" +
                            "?apikey=" + self.APIKEY + "&domain=" + domain))
        if req.status_code != 200:
            self._logger.error ("Error: " + str(req.status_code))
            return None
        try:
            res = json.loads(req.text)
        except:
            return None

        return res
