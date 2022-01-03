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
This module is a basic client for sending logs to a Splunk HTTP Event Collector (HEC).
Splunk configuration settings is read from connector.config and set at object creation.
Data is sent to the HEC in a JSON format. RAW support will be added in the future.
"""

import configparser
import json
import logging
import time

import requests
from bson import json_util
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

from libs3.ConnectorUtil import ConnectorUtil


class HECLogLevel(object):
    """
    A class to represent the Splunk log levels
    """

    INFO = "INFO"
    WARN = "WARN"
    ERROR = "ERROR"


class HECEndpoint(object):
    """
    A class to represent the Splunk endpoints
    """

    RAW = "raw"
    EVENT = "event"


class SplunkHECManager(object):
    """
    This class is for sending data to a Splunk HEC
    """

    splunk_config_file = "connector.config"
    _logger = None

    def _log(self):
        """
        Get the log
        """
        return logging.getLogger(__name__)

    def _init_splunk_hec_connection(self, config):
        """
        Initialize the class members
        """
        self.HOST = ConnectorUtil.get_config_setting(
            self._logger, config, "SplunkHEC", "splunk.host"
        )
        self.PORT = ConnectorUtil.get_config_setting(
            self._logger, config, "SplunkHEC", "splunk.port"
        )
        self.ACCESS_TOKEN = ConnectorUtil.get_config_setting(
            self._logger, config, "SplunkHEC", "splunk.access_token"
        )
        self.HOSTNAME = ConnectorUtil.get_config_setting(
            self._logger, config, "SplunkHEC", "splunk.hostname"
        )
        self.INDEX = ConnectorUtil.get_config_setting(
            self._logger, config, "SplunkHEC", "splunk.index"
        )
        self.URL = "https://" + self.HOST + ":" + self.PORT + "/services/collector/"
        self.HEADERS = {"Authorization": "Splunk {}".format(self.ACCESS_TOKEN)}

    def __init__(self, log_level=None):
        """
        Class initialization
        """
        self._logger = self._log()
        if log_level is not None:
            self._logger.setLevel(log_level)

        config = configparser.ConfigParser()
        config_file = config.read(self.splunk_config_file)
        if len(config_file) == 0:
            self._logger.error("Error: Could not find the config file")
            exit(1)

        self._init_splunk_hec_connection(config)

    def push_to_splunk_hec(
        self, source, message, endpoint=HECEndpoint.EVENT, level=HECLogLevel.INFO
    ):
        """
        Create the HTTPS request and send the data as a JSON object.
        """

        def _requests_retry_session(
            retries=5,
            backoff_factor=7,
            status_forcelist=[408, 500, 502, 503, 504],
            session=None,
        ):
            """
            A Closure method for this static method.
            """
            session = session or requests.Session()
            retry = Retry(
                total=retries,
                read=retries,
                connect=retries,
                backoff_factor=backoff_factor,
                status_forcelist=status_forcelist,
            )
            adapter = HTTPAdapter(max_retries=retry)
            session.mount("http://", adapter)
            session.mount("https://", adapter)
            return session

        data = {}
        data["time"] = time.time()
        data["source"] = source
        data["sourcetype"] = "_json"
        data["host"] = self.HOSTNAME
        data["index"] = self.INDEX

        body = {"severity": level}
        body["message"] = message

        data["event"] = body

        message_body = json_util.dumps(data)

        try:
            _requests_retry_session().post(
                self.URL + endpoint,
                data=message_body,
                headers=self.HEADERS,
                timeout=120,
            )
        except requests.exceptions.HTTPError as e:
            self._logger.error(
                "Error uploading record: "
                + json.dumps(message, default=json_util.default)
            )
            self._logger.error(e)
        except Exception as ex:
            self._logger.error(
                "Error uploading record: "
                + json.dumps(message, default=json_util.default)
            )
            self._logger.error(ex)
