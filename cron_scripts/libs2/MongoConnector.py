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
This module manages the connection to the primary, authoritative MongoDB.
"""

import ConfigParser
from pymongo import MongoClient


class MongoConnector(object):
    """
    This class is designed for interacting with the primary MongoDB
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
        """ Obtains all the parameters from the config file """
        protocol = self._get_config_setting(config, "MongoDB", "mongo.protocol")
        endpoint = self._get_config_setting(config, "MongoDB", "mongo.host")
        path = self._get_config_setting(config, "MongoDB", "mongo.path")
        username = self._get_config_setting(config, "MongoDB", "mongo.username")
        password = self._get_config_setting(config, "MongoDB", "mongo.password")
        connection_string = protocol + username + ":" + password + "@" + endpoint + path
        client = MongoClient(connection_string)
        self.m_connection = client.DOMAINS

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

    def get_zone_connection(self):
        """ Returns a connection to the zone collection in MongoDB """
        return self.m_connection.zones

    def get_ipzone_connection(self):
        """ Returns a connection to the ip_zones collection in MongoDB """
        return self.m_connection.ip_zones

    def get_ipv6_zone_connection(self):
        """ Returns a connection to the ipv6_zones collection in MongoDB """
        return self.m_connection.ipv6_zones

    def get_infoblox_address_connection(self):
        """ Returns a connection to the iblox_a_records collection in MongoDB """
        return self.m_connection.iblox_a_records

    def get_infoblox_aaaa_connection(self):
        """ Returns a connection to the iblox_a_records collection in MongoDB """
        return self.m_connection.iblox_aaaa_records
    
    def get_infoblox_host_connection(self):
        """ Returns a connection to the iblox_host_records collection in MongoDB """
        return self.m_connection.iblox_host_records

    def get_infoblox_cname_connection(self):
        """ Returns a connection to the iblox_cname_records collection in MongoDB """
        return self.m_connection.iblox_cname_records

    def get_infoblox_mx_connection(self):
        """ Returns a connection to the iblox_mx_records collection in MongoDB """
        return self.m_connection.iblox_mx_records

    def get_infoblox_txt_connection(self):
        """ Returns a connection to the iblox_txt_records collection in MongoDB """
        return self.m_connection.iblox_txt_records
    
    def get_infoblox_owners_connection(self):
        """ Returns a connection to the iblox_owner_records collection in MongoDB """
        return self.m_connection.iblox_owner_records

    def get_certificate_transparency_connection(self):
        """ Returns a connection to the ct_certs collection in MongoDB """
        return self.m_connection.ct_certs

    def get_censys_connection(self):
        """ Returns a connection to the censys collection in MongoDB """
        return self.m_connection.censys

    def get_whois_connection(self):
        """ Returns a connection to the whois collection in MongoDB """
        return self.m_connection.whois

    def get_sonar_reverse_dns_connection(self):
        """ Returns a connection to the sonar_rdns collection in MongoDB """
        return self.m_connection.sonar_rdns

    def get_sonar_dns_connection(self):
        """ Returns a connection to the sonar_dns collection in MongoDB """
        return self.m_connection.sonar_dns

    def get_virustotal_connection(self):
        """ Returns a connection to the virustotal collection in MongoDB """
        return self.m_connection.virustotal

    def get_config_connection(self):
        """ Returns a connection to the config collection in MongoDB """
        return self.m_connection.config

    def get_jobs_connection(self):
        """ Returns a connection to the jobs collection in MongoDB """
        return self.m_connection.jobs

    def get_aws_ips_connection(self):
        """ Returns a connection to the aws_ips collection in MongoDB """
        return self.m_connection.aws_ips

    def get_akamai_ips_connection(self):
        """ Returns a connection to the akamai_ips collection in MongoDB """
        return self.m_connection.akamai_ips

    def get_graphs_connection(self):
        """ Returns a connection to the graphs collection in MongoDB """
        return self.m_connection.graphs

    def get_graphs_data_connection(self):
        """ Returns a connection to the graphs_data collection in MongoDB """
        return self.m_connection.graphs_data

    def get_graphs_links_connection(self):
        """ Returns a connection to the graphs_links collection in MongoDB """
        return self.m_connection.graphs_links

    def get_graphs_docs_connection(self):
        """ Returns a connection to the graphs_docs collection in MongoDB """
        return self.m_connection.graphs_docs

    def get_tpds_connection(self):
        """ Returns a connection to the tpds collection in MongoDB """
        return self.m_connection.tpds

    def get_tpd_graphs_connection(self):
        """ Returns a connection to the tpd_graphs collection in MongoDB """
        return self.m_connection.tpd_graphs

    def get_cidr_graphs_connection(self):
        """ Returns a connection to the cidr_graphs collection in MongoDB """
        return self.m_connection.cidr_graphs

    def get_dead_dns_connection(self):
        """ Returns a connection to the dead_dns collection in MongoDB """
        return self.m_connection.dead_dns

    def get_azure_ips_connection(self):
        """ Returns a connection to the zure_ips collection in MongoDB """
        return self.m_connection.azure_ips

    def get_all_dns_connection(self):
        """ Returns a connection to the all_dns collection in MongoDB """
        return self.m_connection.all_dns

    def get_cert_graphs_connection(self):
        """ Returns a connection to the cert_graphs collection in MongoDB """
        return self.m_connection.cert_graphs

    def get_zgrab_443_data_connection(self):
        """ Returns a connection to the zgrab_443 collection in MongoDB """
        return self.m_connection.zgrab_443_data

    def get_zgrab_80_data_connection(self):
        """ Returns a connection to the zgrab_80 collection in MongoDB """
        return self.m_connection.zgrab_80_data

    def get_zgrab_port_data_connection(self):
        """ Returns a connection to the zgrab_80 collection in MongoDB """
        return self.m_connection.zgrab_port_data
