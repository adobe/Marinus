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
This is a simple interface for local file interactions.
DO NOT rename the methods since they are meant to be inherited by the storage manager class.
"""

import configparser
import logging
import os
from ast import Bytes


class LocalStorageManager(object):
    _logger = None
    _storage_config_file = "connector.config"

    def _log(self):
        """
        Get the log
        """
        return logging.getLogger(__name__)

    def __init__(self, config_file="", log_level=None) -> None:

        self._logger = self._log()
        if log_level is not None:
            self._logger.setLevel(log_level)

        if config_file != "":
            self._storage_config_file = config_file

        config = configparser.ConfigParser()
        list = config.read(self._storage_config_file)
        if len(list) == 0:
            self._logger.error("Error: Could not find the config file")
            exit(1)

    def write_file(self, folder: str, filename: str, data) -> bool:
        """
        Write to the local filesystem
        """
        try:
            with open(folder + "/" + filename, "wb") as dest_file:
                dest_file.write(data)
        except Exception as err:
            self._logger.error("Could not write to local filesystem")
            self._logger.error(str(err))
            return False

        return True

    def create_folder(self, foldername: str) -> bool:
        """
        Create a local folder for the data
        """
        try:
            if not os.path.exists(foldername):
                os.makedirs(foldername)
        except Exception as err:
            self._logger.error("Could not create the local folder")
            self._logger.error(str(err))
            return False

        return True

    def read_file(self, foldername: str, filename: str) -> Bytes:
        """
        Read a local file
        """
        try:
            f = open(foldername + "/" + filename, "rb")
            data = f.read()
            f.close()
        except Exception as err:
            self._logger.error("Could not read " + filename + " from " + foldername)
            self._logger.error(str(err))
            return None

        return data
