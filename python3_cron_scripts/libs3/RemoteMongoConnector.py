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
This module is for handling connections to the remote Mongo server.
"""

import logging

from libs3.MongoConnectorBase import MongoConnectorBase


class RemoteMongoConnector(MongoConnectorBase):
    """
    This class is designed for interacting with the remote MongoDB.
    The remote MongoDB lives in AWS and it is where large jobs are processed.
    It contains mirros of the main Mongo collection for remote processing.
    """

    mongo_config_file = "connector.config"
    m_connection = None
    _logger = None

    def _log(self):
        """
        Get the log
        """
        return logging.getLogger(__name__)

    def __init__(self, config_file="", log_level=None):
        """
        Initialize the instance
        """
        self._logger = self._log()

        if log_level is not None:
            self._logger.setLevel(log_level)

        if config_file != "":
            self.mongo_config_file = config_file

        m_base = MongoConnectorBase(config_file, "RemoteMongoDB", log_level)
        self.m_connection = m_base.m_connection

    def get_results_connection(self):
        """Returns a connection to the results collection in MongoDB"""
        return self.m_connection.results

    def get_zone_connection(self):
        """Returns a connection to the zones collection in MongoDB"""
        return self.m_connection.zones

    def get_ipzone_connection(self):
        """Returns a connection to the ip_zones collection in MongoDB"""
        return self.m_connection.ip_zones

    def get_ipv6_zone_connection(self):
        """Returns a connection to the ipv6_zones collection in MongoDB"""
        return self.m_connection.ipv6_zones

    def get_config_connection(self):
        """Returns a connection to the config collection in MongoDB"""
        return self.m_connection.config

    def get_jobs_connection(self):
        """Returns a connection to the jobs collection in MongoDB"""
        return self.m_connection.jobs

    def get_aws_ips_connection(self):
        """Returns a connection to the aws_ips collection in MongoDB"""
        return self.m_connection.aws_ips

    def get_azure_ips_connection(self):
        """Returns a connection to the azure_ips collection in MongoDB"""
        return self.m_connection.azure_ips

    def get_common_crawl_connection(self):
        """Returns a connection to the common_crawl collection in MongoDB"""
        return self.m_connection.common_crawl

    def get_gcp_ips_connection(self):
        """Returns a connection to the dead_dns collection in MongoDB"""
        return self.m_connection.gcp_ips

    def get_all_dns_connection(self):
        """Returns a connection to the all_dns collection in MongoDB"""
        return self.m_connection.all_dns

    def get_all_ips_connection(self):
        """Returns a connection to the all_ips collection in MongoDB"""
        return self.m_connection.all_ips

    def get_whois_connection(self):
        """Returns a connection to the whois collection in MongoDB"""
        return self.m_connection.whois

    def get_zgrab_22_data_connection(self):
        """Returns a connection to the zgrab_22 collection in MongoDB"""
        return self.m_connection.zgrab_22_data

    def get_zgrab_25_data_connection(self):
        """Returns a connection to the zgrab_25 collection in MongoDB"""
        return self.m_connection.zgrab_25_data

    def get_zgrab_80_data_connection(self):
        """Returns a connection to the zgrab_80 collection in MongoDB"""
        return self.m_connection.zgrab_80_data

    def get_zgrab_443_data_connection(self):
        """Returns a connection to the zgrab_443 collection in MongoDB"""
        return self.m_connection.zgrab_443_data

    def get_zgrab_467_data_connection(self):
        """Returns a connection to the zgrab_467 collection in MongoDB"""
        return self.m_connection.zgrab_467_data

    def get_zgrab_port_data_connection(self):
        """Returns a connection to the zgrab_port collection in MongoDB"""
        return self.m_connection.zgrab_port_data

    def get_akamai_ips_connection(self):
        """Returns a connection to the akamai_ips collection in MongoDB"""
        return self.m_connection.akamai_ips

    def get_owasp_amass_connection(self):
        """Returns a connection to the owasp_amass collection in MongoDB"""
        return self.m_connection.owasp_amass

    def get_sonar_data_dns(self):
        """Returns a connection to the sonar_dns collection in MongoDB"""
        return self.m_connection.sonar_dns

    def get_sonar_reverse_dns_connection(self):
        """Returns a connection to the sonar_rdns collection in MongoDB"""
        return self.m_connection.sonar_rdns
