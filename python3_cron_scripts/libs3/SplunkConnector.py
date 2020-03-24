#!/usr/bin/python3

# Copyright 2019 Adobe. All rights reserved.
# This file is licensed to you under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License. You may obtain a copy
# of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR REPRESENTATIONS
# OF ANY KIND, either express or implied. See the License for the specific language
# governing permissions and limitations under the License.

"""
This module creates a Splunk client for querying a Splunk service.
It is used by the SplunkQueryManager.
"""

import configparser
import logging

from libs3.ConnectorUtil import ConnectorUtil

import splunklib.client as client


class SplunkConnector(object):
    splunk_config_file = 'connector.config'
    _logger = None


    def _log(self):
        """
        Get the log
        """
        return logging.getLogger(__name__)


    def _init_splunk_connection(self, config):
        """
        Initialize defaults
        """
        self.HOST = ConnectorUtil.get_config_setting(self._logger, config, 'Splunk', 'splunk.host')
        self.PORT = ConnectorUtil.get_config_setting(self._logger, config, 'Splunk', 'splunk.port')
        self.USERNAME = ConnectorUtil.get_config_setting(self._logger, config, 'Splunk', 'splunk.username')
        self.PASSWORD = ConnectorUtil.get_config_setting(self._logger, config, 'Splunk', 'splunk.password')
        self.APP = ConnectorUtil.get_config_setting(self._logger, config, 'Splunk', 'splunk.app')


    def __init__(self, log_level=None):
        """
        Initialize the object
        """

        self._logger = self._log()
        if log_level is not None:
            self._logger.setLevel(log_level)

        config = configparser.ConfigParser()
        config_file = config.read(self.splunk_config_file)
        if len(config_file) == 0:
            self._logger.error('Error: Could not find the config file')
            exit(1)

        self._init_splunk_connection(config)


    def get_splunk_client(self):
        """
        Create a Splunk client
        """
        if self.APP is not None and self.APP != '':
            service = client.connect(host=self.HOST,
                                    port=self.PORT,
                                    username=self.USERNAME,
                                    password=self.PASSWORD,
                                    app=self.APP)
        else:
            service = client.connect(host=self.HOST,
                                     port=self.PORT,
                                     username=self.USERNAME,
                                     password=self.PASSWORD)

        return service

