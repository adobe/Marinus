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
This class contains a helper function for parsing config files.
"""

import configparser


class ConnectorUtil:
    @staticmethod
    def get_config_setting(logger, config, section, key, type="str"):
        """
        Retrieves the key value from inside the section the connector.config file.

        This function is in multiple modules because it was originally designed
        that each module could be standalone.

        :param logger: A Python logging object
        :param config: A Python ConfigParser object
        :param section: The section where the key exists
        :param key: The name of the key to retrieve
        :param type: (Optional) Specify 'boolean' to convert True/False strings to booleans.
        :return: A string or boolean from the config file.
        """
        try:
            if type == "boolean":
                result = config.getboolean(section, key)
            else:
                result = config.get(section, key)
        except configparser.NoSectionError:
            logger.warning("Warning: " + section + " does not exist in config file")
            if type == "boolean":
                return 0
            else:
                return ""
        except configparser.NoOptionError:
            logger.warning("Warning: " + key + " does not exist in the config file")
            if type == "boolean":
                return 0
            else:
                return ""
        except configparser.Error as err:
            logger.warning("Warning: Unexpected error with config file")
            logger.warning(str(err))
            if type == "boolean":
                return 0
            else:
                return ""

        return result
