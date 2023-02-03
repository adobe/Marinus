#!/usr/bin/python3

# Copyright 2022 Adobe Inc. All rights reserved.
# This file is licensed to you under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License. You may obtain a copy
# of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR REPRESENTATIONS
# OF ANY KIND, either express or implied. See the License for the specific language
# governing permissions and limitations under the License.

"""
This class is a wrapper around Azure, AWS, and local storage so that the storage location
can be changed through a simple flag. Changing the flag will require no functional changes
to the parent code. If the AWS or Azure environments are chosen, then the code assumes
that the authentication requirements are already met through config or environment
variables.
This class will default to writing to the local filesystem.
"""

import configparser
import logging

from libs3 import AWSStorageManager, AzureStorageManager, LocalStorageManager
from libs3.ConnectorUtil import ConnectorUtil


class StorageManager(object):
    AZURE_BLOB = "azure_blob"
    AWS_S3 = "aws_s3"
    LOCAL_FILESYSTEM = "local_filesystem"

    TEXT_MODE = "text"
    BYTES_MODE = "bytes"

    storage_location = LOCAL_FILESYSTEM
    _storage_config_file = "connector.config"

    _logger = None
    _log_level = None

    _instance = None

    def _log(self):
        """
        Get the log
        """
        return logging.getLogger(__name__)

    def __init__(self, location=None, config_file="", log_level=None) -> None:
        """
        Initialize the instance
        """

        self._logger = self._log()
        if log_level is not None:
            self._logger.setLevel(log_level)
            self._log_level = log_level

        if location not in [self.LOCAL_FILESYSTEM, self.AWS_S3, self.AZURE_BLOB]:
            self._logger("Unknown logging location provided. Exiting")
            exit(1)

        if config_file != "":
            self._storage_config_file = config_file

        config = configparser.ConfigParser()
        list = config.read(self._storage_config_file)
        if len(list) == 0:
            self._logger.error("Error: Could not find the config file")
            exit(1)

        if location is not None and location != "":
            self.storage_location = location
        else:
            self.storage_location = ConnectorUtil.get_config_setting(
                self._logger, config, "DefaultStorage", "storage.location", "str", ""
            )
            if self.storage_location is None or self.storage_location == "":
                self.storage_location = self.LOCAL_FILESYSTEM

        # There is a classier (pun intended) way to do this.
        # However, this is functional for now.
        if self.storage_location == self.AZURE_BLOB:
            self._instance = AzureStorageManager.AzureStorageManager(
                config_file, log_level
            )
        elif self.storage_location == self.AWS_S3:
            self._instance = AWSStorageManager.AWSStorageManager(config_file, log_level)
        else:
            self._instance = LocalStorageManager.LocalStorageManager(
                config_file, log_level
            )

        # Supported across all three classes
        self.write_file = self._instance.write_file
        self.read_file = self._instance.read_file
        self.create_folder = self._instance.create_folder
        self.write_large_file = self._instance.write_large_file
        self.delete_file = self._instance.delete_file
        self.list_directory = self._instance.list_directory
