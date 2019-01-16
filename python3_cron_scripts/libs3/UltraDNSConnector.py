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
This module is intended to initialize the connection to the UltraDNS services.
"""

import configparser
from sys import exit


class UltraDNSConnector(object):
    ultra_config_file = 'connector.config'

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
        except configparser.NoSectionError:
            print ('Warning: ' + section + ' does not exist in config file')
            if type == 'boolean':
                return 0
            else:
                return ''
        except configparser.NoOptionError:
            print ('Warning: ' + key + ' does not exist in the config file')
            if type == 'boolean':
                return 0
            else:
                return ''
        except configparser.Error as err:
            print ('Warning: Unexpected error with config file')
            print (str(err))
            if type == 'boolean':
                return 0
            else:
                return ''

        return result

    def _init_ultra_connection(self, config):
        self.USERNAME = self._get_config_setting(config, 'UltraDNS', 'ultra.username')
        self.PASSWORD = self._get_config_setting(config, 'UltraDNS', 'ultra.password')
        self.LOGIN = self._get_config_setting(config, 'UltraDNS', 'ultra.login_url')
        self.ZONES = self._get_config_setting(config, 'UltraDNS', 'ultra.zones_listing')
        self.ZONEINFO = self._get_config_setting(config, 'UltraDNS', 'ultra.zones_dns')

    def __init__(self, debug=False):
        self.debug = debug

        config = configparser.ConfigParser()
        config_file = config.read(self.ultra_config_file)
        if len(config_file) == 0:
            print ('Error: Could not find the config file')
            exit(0)

        self._init_ultra_connection(config)
