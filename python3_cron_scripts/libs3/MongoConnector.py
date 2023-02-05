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

import logging

from libs3.MongoConnectorBase import MongoConnectorBase


class MongoConnector(MongoConnectorBase):
    """
    This class is designed for interacting with the primary MongoDB
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

        m_base = MongoConnectorBase(config_file, "MongoDB", log_level)
        self.m_connection = m_base.m_connection

    def get_akamai_ips_connection(self):
        """Returns a connection to the akamai_ips collection in MongoDB"""
        return self.m_connection.akamai_ips

    def get_all_dns_connection(self):
        """Returns a connection to the all_dns collection in MongoDB"""
        return self.m_connection.all_dns

    def get_all_ips_connection(self):
        """Returns a connection to the all_dns collection in MongoDB"""
        return self.m_connection.all_ips

    def get_aws_ips_connection(self):
        """Returns a connection to the aws_ips collection in MongoDB"""
        return self.m_connection.aws_ips

    def get_azure_ips_connection(self):
        """Returns a connection to the zure_ips collection in MongoDB"""
        return self.m_connection.azure_ips

    def get_censys_connection(self):
        """Returns a connection to the censys collection in MongoDB"""
        return self.m_connection.censys

    def get_cert_graphs_connection(self):
        """Returns a connection to the cert_graphs collection in MongoDB"""
        return self.m_connection.cert_graphs

    def get_certificate_transparency_connection(self):
        """Returns a connection to the ct_certs collection in MongoDB"""
        return self.m_connection.ct_certs

    def get_ct_last_index_connection(self):
        """Returns a connection to the last_ct_ids collection in MongoDB"""
        return self.m_connection.ct_last_index

    def get_cidr_graphs_connection(self):
        """Returns a connection to the cidr_graphs collection in MongoDB"""
        return self.m_connection.cidr_graphs

    def get_config_connection(self):
        """Returns a connection to the config collection in MongoDB"""
        return self.m_connection.config

    def get_dead_dns_connection(self):
        """Returns a connection to the dead_dns collection in MongoDB"""
        return self.m_connection.dead_dns

    def get_gcp_ips_connection(self):
        """Returns a connection to the dead_dns collection in MongoDB"""
        return self.m_connection.gcp_ips

    def get_graphs_connection(self):
        """Returns a connection to the graphs collection in MongoDB"""
        return self.m_connection.graphs

    def get_graphs_data_connection(self):
        """Returns a connection to the graphs_data collection in MongoDB"""
        return self.m_connection.graphs_data

    def get_graphs_links_connection(self):
        """Returns a connection to the graphs_links collection in MongoDB"""
        return self.m_connection.graphs_links

    def get_graphs_docs_connection(self):
        """Returns a connection to the graphs_docs collection in MongoDB"""
        return self.m_connection.graphs_docs

    def get_groups_connection(self):
        """Returns a connection to the groups collection in MongoDB"""
        return self.m_connection.groups

    def get_infoblox_address_connection(self):
        """Returns a connection to the iblox_a_records collection in MongoDB"""
        return self.m_connection.iblox_a_records

    def get_infoblox_aaaa_connection(self):
        """Returns a connection to the iblox_a_records collection in MongoDB"""
        return self.m_connection.iblox_aaaa_records

    def get_infoblox_host_connection(self):
        """Returns a connection to the iblox_host_records collection in MongoDB"""
        return self.m_connection.iblox_host_records

    def get_infoblox_cname_connection(self):
        """Returns a connection to the iblox_cname_records collection in MongoDB"""
        return self.m_connection.iblox_cname_records

    def get_infoblox_mx_connection(self):
        """Returns a connection to the iblox_mx_records collection in MongoDB"""
        return self.m_connection.iblox_mx_records

    def get_infoblox_txt_connection(self):
        """Returns a connection to the iblox_txt_records collection in MongoDB"""
        return self.m_connection.iblox_txt_records

    def get_infoblox_extattr_connection(self):
        """Returns a connection to the iblox_extattr_records collection in MongoDB"""
        return self.m_connection.iblox_extattr_records

    def get_ipzone_connection(self):
        """Returns a connection to the ip_zones collection in MongoDB"""
        return self.m_connection.ip_zones

    def get_ipv6_zone_connection(self):
        """Returns a connection to the ipv6_zones collection in MongoDB"""
        return self.m_connection.ipv6_zones

    def get_jobs_connection(self):
        """Returns a connection to the jobs collection in MongoDB"""
        return self.m_connection.jobs

    def get_owasp_amass_connection(self):
        """Returns a connection to the owasp_amass collection in MongoDB"""
        return self.m_connection.owasp_amass

    def get_sonar_reverse_dns_connection(self):
        """Returns a connection to the sonar_rdns collection in MongoDB"""
        return self.m_connection.sonar_rdns

    def get_tpd_graphs_connection(self):
        """Returns a connection to the tpd_graphs collection in MongoDB"""
        return self.m_connection.tpd_graphs

    def get_tpds_connection(self):
        """Returns a connection to the tpds collection in MongoDB"""
        return self.m_connection.tpds

    def get_users_connection(self):
        """Returns a connection to the users collection in MongoDB"""
        return self.m_connection.users

    def get_virustotal_connection(self):
        """Returns a connection to the virustotal collection in MongoDB"""
        return self.m_connection.virustotal

    def get_whois_connection(self):
        """Returns a connection to the whois collection in MongoDB"""
        return self.m_connection.whois

    def get_zgrab_443_data_connection(self):
        """Returns a connection to the zgrab_443 collection in MongoDB"""
        return self.m_connection.zgrab_443_data

    def get_zgrab_80_data_connection(self):
        """Returns a connection to the zgrab_80 collection in MongoDB"""
        return self.m_connection.zgrab_80_data

    def get_zgrab_port_data_connection(self):
        """Returns a connection to the zgrab_port collection in MongoDB"""
        return self.m_connection.zgrab_port_data

    def get_zone_connection(self):
        """Returns a connection to the zone collection in MongoDB"""
        return self.m_connection.zones

    def get_splunk_connection(self):
        """Returns a connection to the splunk collection in MongoDB"""
        return self.m_connection.splunk
