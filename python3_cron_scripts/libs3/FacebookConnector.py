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
import logging

import requests

from libs3.ConnectorUtil import ConnectorUtil


class FacebookConnector(object):
    """
    This class is designed for interacting with the Facebook Graph API
    """

    fb_config_file = "connector.config"
    KEY = None
    TOKEN = None
    BASE_URL = "https://graph.facebook.com/"
    VERSION = "v2.11"
    _logger = None

    def _log(self):
        """
        Get the log
        """
        return logging.getLogger(__name__)

    def _init_facebook(self, config):
        self.BASE_URL = ConnectorUtil.get_config_setting(
            self._logger, config, "Facebook", "fb.url"
        )
        self.KEY = ConnectorUtil.get_config_setting(
            self._logger, config, "Facebook", "fb.app_id"
        )
        self.TOKEN = ConnectorUtil.get_config_setting(
            self._logger, config, "Facebook", "fb.app_secret"
        )
        self.VERSION = ConnectorUtil.get_config_setting(
            self._logger, config, "Facebook", "fb.graph_version"
        )

    def __init__(self, config_file="", log_level=None):
        if config_file != "":
            self.fb_config_file = config_file

        self._logger = self._log()
        if log_level is not None:
            self._logger.setLevel(log_level)

        config = configparser.ConfigParser()
        list = config.read(self.fb_config_file)
        if len(list) == 0:
            self._logger.error("Error: Could not find the config file")
            exit(1)

        self._init_facebook(config)

    def get_facebook_access_token(self):
        """
        Fetch the Facebook oauth access token.
        This is not completely necessary since app_id|app_secret also works as an access token.
        Exit if there is an error
        """
        try:
            req = requests.get(
                self.BASE_URL
                + self.VERSION
                + "/oauth/access_token?client_id="
                + self.KEY
                + "&client_secret="
                + self.TOKEN
                + "&grant_type=client_credentials",
                timeout=120,
            )
            req.raise_for_status()

        except requests.exceptions.ConnectionError:
            self._logger.error("Connection Error while obtaining access token")
            exit(1)
        except requests.exceptions.HTTPError:
            self._logger.error("HTTP Error while obtaining access token")
            exit(1)
        except requests.exceptions.RequestException as err:
            self._logger.error("Request exception while obtaining access token")
            self._logger.error(str(err))
            exit(1)

        if req.status_code != 200:
            self._logger.error("Error while obtaining access token")
            exit(1)

        response = json.loads(req.text)

        return response["access_token"]
