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
import requests

from azure.mgmt.dns import DnsManagementClient
from azure.mgmt.resource import ResourceManagementClient


class AzureConnector(object):
    """
    This class is designed for interacting with the Azure APIs
    """

    azure_config_file = 'connector.config'
    TENANT_ID = None
    SUBSCRIPTION_ID = None
    KEY = None
    CLIENT_ID = None
    FILE_PATH = None

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


    def _init_azure(self, config):
        self.TENANT_ID = self._get_config_setting(config, "Azure", "az.tenant_id")
        self.CLIENT_ID = self._get_config_setting(config, "Azure", "az.client_id")
        self.KEY = self._get_config_setting(config, "Azure", "az.sp_password")
        self.SUBSCRIPTION_ID = self._get_config_setting(config, "Azure", "az.subscription_id")
        self.FILE_PATH = self._get_config_setting(config, "Azure", "az.file_path")



    def __init__(self, config_file="", debug=False):
        if config_file != "":
            self.azure_config_file = config_file
        self.debug = debug

        config = configparser.ConfigParser()
        list = config.read(self.azure_config_file)
        if len(list) == 0:
            print('Error: Could not find the config file')
            exit(0)

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
                client_id = self.CLIENT_ID,
                secret = self.KEY,
                tenant = self.TENANT_ID
            )

            dns_client = DnsManagementClient(
                credentials,
                self.SUBSCRIPTION_ID
            )

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
                client_id = self.CLIENT_ID,
                secret = self.KEY,
                tenant = self.TENANT_ID
            )

            resources_client = ResourceManagementClient(
                credentials,
                self.SUBSCRIPTION_ID
            )

            return resources_client
