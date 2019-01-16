#!/usr/bin/python

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
This module is for handling connections to the remote Mongo server.
"""


import ConfigParser
from pymongo import MongoClient

class RemoteMongoConnector(object):
    """
    This class is designed for interacting with the remote MongoDB.
    The remote MongoDB lives in AWS and it is where large jobs are processed.
    It contains mirros of the main Mongo collection for remote processing.
    """

    mongo_config_file = 'connector.config'
    m_connection = None
    debug = False

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
        except ConfigParser.NoSectionError:
            print 'Warning: ' + section + ' does not exist in config file'
            if type == 'boolean':
                return 0
            else:
                return ""
        except ConfigParser.NoOptionError:
            print 'Warning: ' + key + ' does not exist in the config file'
            if type == 'boolean':
                return 0
            else:
                return ""
        except ConfigParser.Error as err:
            print 'Warning: Unexpected error with config file'
            print str(err)
            if type == 'boolean':
                return 0
            else:
                return ""

        return result


    def _init_mongo_connection(self, config):
        protocol = self._get_config_setting(config, "RemoteMongoDB", "mongo.protocol")
        endpoint = self._get_config_setting(config, "RemoteMongoDB", "mongo.host")
        path = self._get_config_setting(config, "RemoteMongoDB", "mongo.path")
        username = self._get_config_setting(config, "RemoteMongoDB", "mongo.username")
        password = self._get_config_setting(config, "RemoteMongoDB", "mongo.password")
        cacert = self._get_config_setting(config, "RemoteMongoDB", "mongo.ca_cert")
        connection_string = protocol + username + ":" + password + "@" + endpoint + path
        client = MongoClient(connection_string, ssl=True, ssl_ca_certs=cacert)
        self.m_connection = client.censys


    def __init__(self, config_file="", debug=False):
        if config_file != "":
            self.mongo_config_file = config_file
        self.debug = debug

        config = ConfigParser.ConfigParser()
        list = config.read(self.mongo_config_file)
        if len(list) == 0:
            print 'Error: Could not find the config file'
            exit(0)

        self._init_mongo_connection(config)


    def get_results_connection(self):
        """ Returns a connection to the results collection in MongoDB """
        return self.m_connection.results

    def get_zone_connection(self):
        """ Returns a connection to the zones collection in MongoDB """
        return self.m_connection.zones

    def get_ipzone_connection(self):
        """ Returns a connection to the ip_zones collection in MongoDB """
        return self.m_connection.ip_zones

    def get_config_connection(self):
        """ Returns a connection to the config collection in MongoDB """
        return self.m_connection.config

    def get_jobs_connection(self):
        """ Returns a connection to the jobs collection in MongoDB """
        return self.m_connection.jobs

    def get_aws_ips_connection(self):
        """ Returns a connection to the aws_ips collection in MongoDB """
        return self.m_connection.aws_ips

    def get_azure_ips_connection(self):
        """ Returns a connection to the azure_ips collection in MongoDB """
        return self.m_connection.azure_ips

    def get_common_crawl_connection(self):
        """ Returns a connection to the common_crawl collection in MongoDB """
        return self.m_connection.common_crawl

    def get_all_dns_connection(self):
        """ Returns a connection to the all_dns collection in MongoDB """
        return self.m_connection.all_dns

    def get_zgrab_443_data_connection(self):
        """ Returns a connection to the zgrab_443 collection in MongoDB """
        return self.m_connection.zgrab_443_data

    def get_zgrab_80_data_connection(self):
        """ Returns a connection to the zgrab_80 collection in MongoDB """
        return self.m_connection.zgrab_80_data

    def get_zgrab_port_data_connection(self):
        """ Returns a connection to the zgrab_80 collection in MongoDB """
        return self.m_connection.zgrab_80_data
