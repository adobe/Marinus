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
import shutil
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

    def write_large_file(
        self, folder: str, remote_file_name: str, local_file_path: str
    ) -> bool:
        """
        Copy a large file between two local folders.
        """
        try:
            shutil.copy(local_file_path, folder + "/" + remote_file_name)
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

    def read_file(self, foldername: str, filename: str, mode: str = "bytes") -> Bytes:
        """
        Read a local file
        """
        try:
            if mode == "text":
                f = open(foldername + "/" + filename, "r")
            else:
                f = open(foldername + "/" + filename, "rb")
            data = f.read()
            f.close()
        except Exception as err:
            self._logger.error("Could not read " + filename + " from " + foldername)
            self._logger.error(str(err))
            return None

        return data

    def delete_file(self, foldername: str, filename: str):
        """
        Delete a local file.
        Returns True if success, False otherwise
        """
        try:
            path = foldername + "/" + filename
            if os.path.exists(path):
                os.remove(path)
            else:
                self._logger.error("The file does not exist")
                return False
        except Exception as err:
            self._logger.error("Could not delete " + filename + " from " + foldername)
            self._logger.error(str(err))
            return False

        return True

    def list_directory(self, foldername: str):
        """
        Return a list of local files
        """
        try:
            if os.path.exists(foldername):
                return os.listdir(foldername)
            else:
                return None
        except Exception as err:
            self._logger.error("Could not list the files in: " + foldername)
            self._logger.error(str(err))
            return None

        return True
