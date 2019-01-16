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
This module manages interactions with the Facebook Graph API.
"""

import configparser
import json
import requests

class FacebookConnector(object):
    """
    This class is designed for interacting with the Facebook Graph API
    """

    fb_config_file = 'connector.config'
    KEY = None
    TOKEN = None
    BASE_URL = "https://graph.facebook.com/"
    debug = False
    VERSION = "v2.11"

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
            print('Warning: ' + section + ' does not exist in config file')
            if type == 'boolean':
                return 0
            else:
                return ""
        except configparser.NoOptionError:
            print('Warning: ' + key + ' does not exist in the config file')
            if type == 'boolean':
                return 0
            else:
                return ""
        except configparser.Error as err:
            print('Warning: Unexpected error with config file')
            print(str(err))
            if type == 'boolean':
                return 0
            else:
                return ""

        return result


    def _init_facebook(self, config):
        self.BASE_URL = self._get_config_setting(config, "Facebook", "fb.url")
        self.KEY = self._get_config_setting(config, "Facebook", "fb.app_id")
        self.TOKEN = self._get_config_setting(config, "Facebook", "fb.app_secret")
        self.VERSION = self._get_config_setting(config, "Facebook", "fb.graph_version")


    def __init__(self, config_file="", debug=False):
        if config_file != "":
            self.fb_config_file = config_file
        self.debug = debug

        config = configparser.ConfigParser()
        list = config.read(self.fb_config_file)
        if len(list) == 0:
            print('Error: Could not find the config file')
            exit(0)

        self._init_facebook(config)


    def get_facebook_access_token(self):
        """
        Fetch the Facebook oauth access token.
        This is not completely necessary since app_id|app_secret also works as an access token.
        Exit if there is an error
        """
        try:
            req = requests.get(self.BASE_URL + self.VERSION + \
                            "/oauth/access_token?client_id=" + self.KEY + \
                            "&client_secret=" + self.TOKEN + \
                            "&grant_type=client_credentials")
            req.raise_for_status()

        except requests.exceptions.ConnectionError:
            print("Connection Error while obtaining access token")
            exit(0)
        except requests.exceptions.HTTPError:
            print("HTTP Error while obtaining access token")
            exit(0)
        except requests.exceptions.RequestException as err:
            print("Request exception while obtaining access token")
            print(str(err))
            exit(0)

        if req.status_code != 200:
            print("Error while obtaining access token")
            exit(0)

        response = json.loads(req.text)

        return response['access_token']
