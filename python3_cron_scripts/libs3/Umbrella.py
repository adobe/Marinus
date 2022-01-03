#!/usr/bin/python3

# Copyright 2020 Adobe. All rights reserved.
# This file is licensed to you under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License. You may obtain a copy
# of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR REPRESENTATIONS
# OF ANY KIND, either express or implied. See the License for the specific language
# governing permissions and limitations under the License.

"""
This module manages interactions with the Cisco Umbrella service.

A paid subscription is required.
"""

import configparser
import json
import logging

import requests
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

from libs3.ConnectorUtil import ConnectorUtil


class Umbrella(object):
    """
    This class is designed for interacting with Cisco Umbrella.
    """

    umbrella_config_file = "connector.config"
    TOKEN = None
    URL = "https://investigate.api.umbrella.com/"
    _logger = None

    def _log(self):
        """
        Get the log
        """
        return logging.getLogger(__name__)

    def _init_umbrella(self, config):
        """
        Obtain the configuration data
        """
        self.URL = ConnectorUtil.get_config_setting(
            self._logger, config, "Cisco", "umbrella.url", "str", self.URL
        )
        self.TOKEN = ConnectorUtil.get_config_setting(
            self._logger, config, "Cisco", "umbrella.key"
        )

    def __init__(self, config_file="", log_level=None):
        """
        Initialize the class
        """
        if config_file != "":
            self.umbrella_config_file = config_file

        self._logger = self._log()

        if log_level is not None:
            self._logger.setLevel(log_level)

        config = configparser.ConfigParser()
        list = config.read(self.umbrella_config_file)
        if len(list) == 0:
            self._logger.error("Error: Could not find the config file")
            exit(1)

        self._init_umbrella(config)

    def __requests_retry_session(
        self,
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

    def search_by_name_server(self, name_server):
        """
        Fetches the whois records from Umbrella based on the registered name server.
        @param name_server The name server to search for in the whois records
        """
        path = self.URL + "whois/nameservers/" + name_server

        headers = {"Authorization": "Bearer " + self.TOKEN}
        parameters = {}

        req = self.__requests_retry_session().get(
            path, params=parameters, headers=headers, timeout=120
        )

        try:
            res = json.loads(req.text)
        except:
            return None

        return res

    def search_by_name_servers(self, name_server_list):
        """
        Fetches the whois records from Umbrella based on the provided registered name server list.
        @param name_server_list The name servers to search for in the whois records delimited by a comma
        """
        path = self.URL + "whois/nameservers"

        headers = {"Authorization": "Bearer " + self.TOKEN}
        parameters = {"nameServerList", name_server_list}

        req = self.__requests_retry_session().get(
            path, params=parameters, headers=headers, timeout=120
        )

        try:
            res = json.loads(req.text)
        except:
            return None

        return res

    def search_by_email(self, email, offset=None):
        """
        Fetches the whois records from Umbrella based on the registered email.
        @param email The email to search for in the whois records
        """
        path = self.URL + "whois/emails/" + email
        headers = {"Authorization": "Bearer " + self.TOKEN}

        params = {}

        if offset is not None:
            params["offset"] = offset

        req = self.__requests_retry_session().get(
            path, params=params, headers=headers, timeout=120
        )

        try:
            res = json.loads(req.text)
        except:
            return None

        return res

    def search_by_emails(self, email_list, offset=None):
        """
        Fetches the whois records from Umbrella based on the registered email list.
        @param email_list The comma delimited email list to search for in the whois records
        """
        path = self.URL + "whois/emails"
        headers = {"Authorization": "Bearer " + self.TOKEN}

        params = {}
        params["emailList"] = email_list

        if offset is not None:
            params["offset"] = offset

        req = self.__requests_retry_session().get(
            path, params=params, headers=headers, timeout=120
        )

        try:
            res = json.loads(req.text)
        except:
            return None

        return res

    def search_by_domain(self, domain_name, include_history=False, limit=10):
        """
        Search Umbrella for a single DNS record
        """
        path = self.URL + "/whois/" + domain_name
        headers = {"Authorization": "Bearer " + self.TOKEN}

        params = {}

        if include_history:
            path = path + "/history"
            params["limit"] = limit

        req = self.__requests_retry_session().get(
            path, params=params, headers=headers, timeout=120
        )

        try:
            res = json.loads(req.text)
        except:
            return None

        return res
