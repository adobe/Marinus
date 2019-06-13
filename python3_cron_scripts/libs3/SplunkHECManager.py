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
import requests
import time

from bson import json_util
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

class HECLogLevel(object):
    """
    A class to represent the Splunk log levels
    """
    INFO = 'INFO'
    WARN = 'WARN'
    ERROR = 'ERROR'


class HECEndpoint(object):
    """
    A class to represent the Splunk endpoints
    """
    RAW = 'raw'
    EVENT = 'event'


class SplunkHECManager(object):
    """
    This class is for sending data to a Splunk HEC
    """
    splunk_config_file = 'connector.config'

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
            print ('Warning: ' + section + ' does not exist in config file')
            if type == 'boolean':
                return 0
            else:
                return ''
        except configparser.NoOptionError:
            print ('Warning: ' + key + ' does not exist in the config file')
            if type == 'boolean':
                return 0
            else:
                return ''
        except configparser.Error as err:
            print ('Warning: Unexpected error with config file')
            print (str(err))
            if type == 'boolean':
                return 0
            else:
                return ''

        return result


    def _init_splunk_hec_connection(self, config):
        """
        Initialize the class members
        """
        self.HOST = self._get_config_setting(config, 'SplunkHEC', 'splunk.host')
        self.PORT = self._get_config_setting(config, 'SplunkHEC', 'splunk.port')
        self.ACCESS_TOKEN = self._get_config_setting(config, 'SplunkHEC', 'splunk.access_token')
        self.HOSTNAME = self._get_config_setting(config, 'SplunkHEC', 'splunk.hostname')
        self.INDEX = self._get_config_setting(config, 'SplunkHEC', 'splunk.index')
        self.URL = "https://" + self.HOST + ":" + self.PORT + "/services/collector/"
        self.HEADERS = { 'Authorization': "Splunk {}".format(self.ACCESS_TOKEN) }


    def __init__(self, debug=False):
        """
        Class initialization
        """
        self.debug = debug

        config = configparser.ConfigParser()
        config_file = config.read(self.splunk_config_file)
        if len(config_file) == 0:
            print ('Error: Could not find the config file')
            exit(0)

        self._init_splunk_hec_connection(config)


    def push_to_splunk_hec(self, source, message, endpoint=HECEndpoint.EVENT, level=HECLogLevel.INFO):
        """
        Create the HTTPS request and send the data as a JSON object.
        """
        def _requests_retry_session(retries=5, backoff_factor=7, status_forcelist=[408, 500, 502, 503, 504],session=None,):
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
            session.mount('http://', adapter)
            session.mount('https://', adapter)
            return session

        data = {}
        data['time'] = time.time()
        data['source'] = source
        data['sourcetype'] = '_json'
        data['host'] = self.HOSTNAME
        data['index'] = self.INDEX

        body = {'severity': level}
        body['message'] = message

        data['event'] = body

        message_body = json_util.dumps(data)

        try:
            _requests_retry_session().post(self.URL + endpoint, data=message_body, headers=self.HEADERS)
        except requests.exceptions.HTTPError as e:
            print("Error uploading record: " + json.dumps(message, default=json_util.default))
            print(e)
        except Exception as ex:
            print("Error uploading record: " + json.dumps(message, default=json_util.default))
            print(ex)
