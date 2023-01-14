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
This library handles the default logging configuration for Marinus.
Users can customize the logging output by using a logging.conf file in the main directory.
Please see: https://docs.python.org/3/howto/logging.html for more information.
"""

import logging
import logging.config
import os.path


class LoggingUtil:
    @staticmethod
    def create_log(name, level=None, config_file=None):
        """
        Steps:
           1. Check for a customized config file as a parameter
           2. If not 1, check for a "logging.conf" file
           3. If not 1 or 2, set a basic logging format.

        :param level: This is the logging.LEVEL setting (optional)
        :param config_file: A YAML Python logging config file (optional)
        :return: logger instance
        """
        if config_file is not None:
            logging.config.fileConfig(config_file)
        elif os.path.isfile("logging.conf"):
            logging.config.fileConfig("logging.conf")
        else:
            # create formatter
            logging.basicConfig(
                format="[%(asctime)s] %(name)s {%(funcName)s:%(lineno)d} : %(levelname)s : %(message)s"
            )

        logger = logging.getLogger(name)

        if level is not None:
            logger.setLevel(level)
        else:
            try:
                level = os.environ["LOG_LEVEL"]
            except:
                level = None

            if level is not None:
                logger.setLevel(int(level))

        return logger
