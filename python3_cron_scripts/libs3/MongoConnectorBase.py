#!/usr/bin/python3

# Copyright 2022 Adobe. All rights reserved.
# This file is licensed to you under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License. You may obtain a copy
# of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR REPRESENTATIONS
# OF ANY KIND, either express or implied. See the License for the specific language
# governing permissions and limitations under the License.

"""
This module manages the connection to the primary, authoritative MongoDB.
"""

import configparser
import logging
import time
import urllib.parse
from pymongo import MongoClient
from pymongo.errors import AutoReconnect, DocumentTooLarge

from libs3.ConnectorUtil import ConnectorUtil


class MongoConnectorBase(object):
    """
    This class is designed for interacting with MongoDB
    """

    protocol = "mongodb://"
    mongo_config_file = "connector.config"
    m_connection = None
    _logger = None

    def _log(self):
        """
        Get the log
        """
        return logging.getLogger(__name__)

    def _init_mongo_connection(self, config, config_location):
        """Obtains all the parameters from the config file"""
        protocol = ConnectorUtil.get_config_setting(
            self._logger,
            config,
            config_location,
            "mongo.protocol",
            "str",
            self.protocol,
        )
        endpoint = ConnectorUtil.get_config_setting(
            self._logger, config, config_location, "mongo.host"
        )
        path = ConnectorUtil.get_config_setting(
            self._logger, config, config_location, "mongo.path"
        )
        username = ConnectorUtil.get_config_setting(
            self._logger, config, config_location, "mongo.username"
        )
        password = ConnectorUtil.get_config_setting(
            self._logger, config, config_location, "mongo.password"
        )
        cacert = ConnectorUtil.get_config_setting(
            self._logger, config, config_location, "mongo.ca_cert"
        )

        if username != "" and password != "":
            connection_string = (
                protocol
                + username
                + ":"
                + urllib.parse.quote(password)
                + "@"
                + endpoint
                + path
            )
        else:
            connection_string = protocol + endpoint + path

        if cacert != "":
            client = MongoClient(connection_string, tls=True, tlsCAFile=cacert)
        else:
            client = MongoClient(connection_string)

        self.m_connection = client[path[1:]]

    def __init__(self, config_file="", config_location="MongoDB", log_level=None):
        if config_file != "":
            self.mongo_config_file = config_file

        self._logger = self._log()
        if log_level is not None:
            self._logger.setLevel(log_level)

        config = configparser.ConfigParser()
        list = config.read(self.mongo_config_file)
        if len(list) == 0:
            self._logger.error("Error: Could not find the config file")
            exit(1)

        self._init_mongo_connection(config, config_location)

    def perform_find(self, collection, query, filter=None, batch_size=None):
        """
        This will perform a find with a retry for dropped connections
        """
        success = False
        num_tries = 0
        while not success:
            try:
                if filter is not None:
                    if batch_size is not None:
                        result = collection.find(query, filter).batch_size(batch_size)
                    else:
                        result = collection.find(query, filter)
                else:
                    if batch_size is not None:
                        result = collection.find(query).batch_size(batch_size)
                    else:
                        result = collection.find(query)
                success = True
            except AutoReconnect:
                if num_tries < 5:
                    self._logger.warning(
                        "Warning: Failed to connect to the database. Retrying."
                    )
                    time.sleep(5)
                    num_tries = num_tries + 1
                else:
                    self._logger.error(
                        "ERROR: Exceeded the max number of connection attempts to MongoDB!"
                    )
                    exit(1)

        return result

    def perform_find_one(self, collection, query, filter=None):
        """
        This will perform a find_one with a retry for dropped connections
        """
        success = False
        num_tries = 0
        while not success:
            try:
                if filter is not None:
                    result = collection.find_one(query, filter)
                else:
                    result = collection.find_one(query)
                success = True
            except AutoReconnect:
                if num_tries < 5:
                    self._logger.warning(
                        "Warning: Failed to connect to the database. Retrying."
                    )
                    time.sleep(5)
                    num_tries = num_tries + 1
                else:
                    self._logger.error(
                        "ERROR: Exceeded the max number of connection attempts to MongoDB!"
                    )
                    exit(1)

        return result

    def perform_count(self, collection, query):
        """
        This will perform a find.count() with a retry for dropped connections
        """
        success = False
        num_tries = 0
        while not success:
            try:
                result = collection.count_documents(query)
                success = True
            except AutoReconnect:
                if num_tries < 5:
                    self._logger.warning(
                        "Warning: Failed to connect to the database. Retrying."
                    )
                    time.sleep(5)
                    num_tries = num_tries + 1
                else:
                    self._logger.error(
                        "ERROR: Exceeded the max number of connection attempts to MongoDB!"
                    )
                    exit(1)

        return result

    def perform_distinct(self, collection, field, query=None):
        """
        This will perform a distinct with a retry for dropped connections
        """
        success = False
        num_tries = 0
        while not success:
            try:
                if query is not None:
                    result = collection.distinct(field, query)
                else:
                    result = collection.distinct(field)
                success = True
            except AutoReconnect:
                if num_tries < 5:
                    self._logger.warning(
                        "Warning: Failed to connect to the database. Retrying."
                    )
                    time.sleep(5)
                    num_tries = num_tries + 1
                else:
                    self._logger.error(
                        "ERROR: Exceeded the max number of connection attempts to MongoDB!"
                    )
                    exit(1)

        return result

    def perform_insert(self, collection, query):
        """
        This will perform an insert_one with a retry for dropped connections
        """
        success = False
        num_tries = 0
        while not success:
            try:
                result = collection.insert_one(query)
                success = True
            except AutoReconnect:
                if num_tries < 5:
                    self._logger.warning(
                        "Warning: Failed to connect to the database. Retrying."
                    )
                    time.sleep(5)
                    num_tries = num_tries + 1
                else:
                    self._logger.error(
                        "ERROR: Exceeded the max number of connection attempts to MongoDB!"
                    )
                    exit(1)
            except DocumentTooLarge:
                self._logger.error(
                    "ERROR: Document could not be inserted because it exceeded maximum JSON size"
                )
                success = True
                result = None

        return result
