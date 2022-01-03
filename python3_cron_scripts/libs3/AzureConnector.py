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
This module manages interactions with Azure and supports filed based and RBAC based authentication.
The authentication methods are described here:
https://docs.microsoft.com/en-us/python/azure/python-sdk-azure-authenticate?view=azure-python
"""

import configparser
import json
import logging

import requests
from azure.mgmt.dns import DnsManagementClient
from azure.mgmt.resource import ResourceManagementClient

from libs3.ConnectorUtil import ConnectorUtil


class AzureConnector(object):
    """
    This class is designed for interacting with the Azure APIs
    """

    azure_config_file = "connector.config"
    TENANT_ID = None
    SUBSCRIPTION_ID = None
    KEY = None
    CLIENT_ID = None
    FILE_PATH = None
    _logger = None

    def _log(self):
        """
        Get the log
        """
        return logging.getLogger(__name__)

    def _init_azure(self, config):
        self.TENANT_ID = ConnectorUtil.get_config_setting(
            self._logger, config, "Azure", "az.tenant_id"
        )
        self.CLIENT_ID = ConnectorUtil.get_config_setting(
            self._logger, config, "Azure", "az.client_id"
        )
        self.KEY = ConnectorUtil.get_config_setting(
            self._logger, config, "Azure", "az.sp_password"
        )
        self.SUBSCRIPTION_ID = ConnectorUtil.get_config_setting(
            self._logger, config, "Azure", "az.subscription_id"
        )
        self.FILE_PATH = ConnectorUtil.get_config_setting(
            self._logger, config, "Azure", "az.file_path"
        )

    def __init__(self, config_file="", log_level=None):
        if config_file != "":
            self.azure_config_file = config_file

        self._logger = self._log()
        if log_level is not None:
            self._logger.setLevel(log_level)

        config = configparser.ConfigParser()
        list = config.read(self.azure_config_file)
        if len(list) == 0:
            self._logger.error("Error: Could not find the config file")
            exit(1)

        self._init_azure(config)

    def get_dns_client(self):
        """
        Get a connection to the Azure DNS service
        """
        if self.FILE_PATH is not None and self.FILE_PATH != "":
            from azure.common.client_factory import get_client_from_auth_file

            return get_client_from_auth_file(DnsManagementClient)

        elif self.KEY is not None and self.KEY != "":
            from azure.common.credentials import ServicePrincipalCredentials

            credentials = ServicePrincipalCredentials(
                client_id=self.CLIENT_ID, secret=self.KEY, tenant=self.TENANT_ID
            )

            dns_client = DnsManagementClient(credentials, self.SUBSCRIPTION_ID)

            return dns_client

    def get_resources_client(self):
        """
        Get a connection to the Azure Resource Mananger
        """
        if self.FILE_PATH is not None and self.FILE_PATH != "":
            from azure.common.client_factory import get_client_from_auth_file

            return get_client_from_auth_file(ResourceManagementClient)

        elif self.KEY is not None and self.KEY != "":
            from azure.common.credentials import ServicePrincipalCredentials

            credentials = ServicePrincipalCredentials(
                client_id=self.CLIENT_ID, secret=self.KEY, tenant=self.TENANT_ID
            )

            resources_client = ResourceManagementClient(
                credentials, self.SUBSCRIPTION_ID
            )

            return resources_client
