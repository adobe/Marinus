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
This module is design to manage Adobe Infoblox connection data.
"""

import configparser
import logging

import requests

from libs3.ConnectorUtil import ConnectorUtil


class InfobloxConnector(object):
    """
    This class is designed to manage Infoblox connection data.

    It is assumed that the requests to Infoblox will be done by
    the individual scripts.
    """

    iblox_config_file = "connector.config"
    _logger = None
    HOST = ""
    UNAME = ""
    PASSWD = ""
    VERSION = ""

    def _log(self):
        """
        Get the log
        """
        return logging.getLogger(__name__)

    def __init_iblox_connection(self, config):
        self.HOST = ConnectorUtil.get_config_setting(
            self._logger, config, "Infoblox", "infoblox.HOST"
        )
        self.UNAME = ConnectorUtil.get_config_setting(
            self._logger, config, "Infoblox", "infoblox.username"
        )
        self.PASSWD = ConnectorUtil.get_config_setting(
            self._logger, config, "Infoblox", "infoblox.passwd"
        )
        self.VERSION = ConnectorUtil.get_config_setting(
            self._logger, config, "Infoblox", "infoblox.version"
        )

    def __init__(self, config_file="", log_level=None):
        if config_file != "":
            self.iblox_config_file = config_file

        self._logger = self._log()
        if log_level is not None:
            self._logger.setLevel(log_level)

        config = configparser.ConfigParser()
        list = config.read(self.iblox_config_file)
        if len(list) == 0:
            self._logger.error("Error: Could not find the config file")
            exit(1)

        self.__init_iblox_connection(config)
