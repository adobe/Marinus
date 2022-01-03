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
import logging
from sys import exit

from libs3.ConnectorUtil import ConnectorUtil


class UltraDNSConnector(object):
    ultra_config_file = "connector.config"

    LOGIN = "https://api.ultradns.com/authorization/token"
    ZONES = "https://api.ultradns.com/zones/"
    ZONEINFO = "https://api.ultradns.com/zones/{zone_queried}./rrsets"

    _logger = None

    def _log(self):
        """
        Get the log
        """
        return logging.getLogger(__name__)

    def _init_ultra_connection(self, config):
        self.USERNAME = ConnectorUtil.get_config_setting(
            self._logger, config, "UltraDNS", "ultra.username"
        )
        self.PASSWORD = ConnectorUtil.get_config_setting(
            self._logger, config, "UltraDNS", "ultra.password"
        )
        self.LOGIN = ConnectorUtil.get_config_setting(
            self._logger, config, "UltraDNS", "ultra.login_url"
        )
        self.ZONES = ConnectorUtil.get_config_setting(
            self._logger, config, "UltraDNS", "ultra.zones_listing"
        )
        self.ZONEINFO = ConnectorUtil.get_config_setting(
            self._logger, config, "UltraDNS", "ultra.zones_dns"
        )

    def __init__(self, log_level=None):
        self._logger = self._log()
        if log_level is not None:
            self._logger.setLevel(log_level)

        config = configparser.ConfigParser()
        config_file = config.read(self.ultra_config_file)
        if len(config_file) == 0:
            self._logger.error("Error: Could not find the config file")
            exit(1)

        self._init_ultra_connection(config)
