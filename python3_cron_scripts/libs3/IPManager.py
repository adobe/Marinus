#!/usr/bin/python3

# Copyright 2019 Adobe. All rights reserved.
# This file is licensed to you under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License. You may obtain a copy
# of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR REPRESENTATIONS
# OF ANY KIND, either express or implied. See the License for

"""
This class handles common IP comparisons with known network ranges.
In addition, it manages the entries within the all_ips collection. 
The all_ips collection contains the list of unique public IP addresses identified in DNS records.

NOTE: The find_splunk_data function within this script does not do anything. It is a placeholder
for any custom integrations that you may want to make within your network.
"""

import logging
from datetime import datetime

from bson.objectid import ObjectId
from netaddr import IPAddress, IPNetwork

from libs3 import DNSManager, GoogleDNS
from libs3.ZoneManager import ZoneManager


class IPManager(object):
    """
    This class provides utilities for common IP comparisons against known network ranges.
    In addtion, it manages the data within the all_ips collection.
    IPs within the all_ips collection are limited to a single unique entry and must be a public IP.
    In addition, metadata surrounding the IPs is stored for contextual understanding of its relevance.
    """

    all_ips_collection = None
    mongo_connector = None

    AKAMAI = "AKAMAI"
    Akamai_IPs = None

    AWS = "AWS"
    AWS_IPs = None

    AZURE = "AZURE"
    Azure_IPs = None

    GCP = "GCP"
    GCP_IPs = None

    TRACKED = "TRACKED"
    Tracked_CIDRs = None

    UNKNOWN = "UNKNOWN"

    _ZONES = None

    _logger = None

    def _log(self):
        """
        Get the log
        """
        return logging.getLogger(__name__)

    def __init__(self, mongo_connector, init_all=False):
        """
        The init_all parameter is useful if you need to get access to the partner IP
        addresses directly rather than using convenience functions.
        """
        self.mongo_connector = mongo_connector
        self.all_ips_collection = mongo_connector.get_all_ips_connection()

        self._logger = self._log()

        if init_all:
            self.__get_akamai_ips()
            self.__get_akamai_ipv6s()
            self.__get_aws_ips()
            self.__get_aws_ipv6s()
            self.__get_azure_ips()
            self.__get_gcp_ips()
            self.__get_gcp_ipv6s()
            self.__get_tracked_cidrs()
            self.__get_tracked_ipv6_cidrs()

    def __get_akamai_ips(self):
        """
        Extract the list of Akamai Networks from the Mongo database.
        They are stored within the akamai_ips global.
        """
        self.Akamai_IPs = []

        akamai_collection = self.mongo_connector.get_akamai_ips_connection()

        results = self.mongo_connector.perform_find_one(akamai_collection, {})

        if results is not None:
            for result in results["ranges"]:
                self.Akamai_IPs.append(IPNetwork(result["cidr"]))

    def __get_akamai_ipv6s(self):
        """
        Extract the list of Akamai Networks from the Mongo database.
        They are stored within the akamai_ips global.
        """
        if self.Akamai_IPs is None:
            self.Akamai_IPs = []

        akamai_collection = self.mongo_connector.get_akamai_ips_connection()

        results = self.mongo_connector.perform_find_one(akamai_collection, {})

        if results is not None:
            for result in results["ipv6_ranges"]:
                self.Akamai_IPs.append(IPNetwork(result["cidr"]))

    def __get_aws_ips(self):
        """
        Get the list of AWS IPv4 CIDRs.
        """
        self.AWS_IPs = []
        aws_ips_collection = self.mongo_connector.get_aws_ips_connection()

        results = self.mongo_connector.perform_find_one(aws_ips_collection, {})

        if results is not None:
            for result in results["prefixes"]:
                self.AWS_IPs.append(IPNetwork(result["ip_prefix"]))

    def __get_aws_ipv6s(self):
        """
        Get the list of AWS IPv6 CIDRs.
        """
        if self.AWS_IPs is None:
            self.AWS_IPs = []

        aws_ips_collection = self.mongo_connector.get_aws_ips_connection()

        results = self.mongo_connector.perform_find_one(aws_ips_collection, {})

        if results is not None:
            for result in results["ipv6_prefixes"]:
                self.AWS_IPs.append(IPNetwork(result["ipv6_prefix"]))

    def __get_azure_ips(self):
        """
        Get the list of Azure CIDRs.
        """
        self.Azure_IPs = []
        azure_ips_collection = self.mongo_connector.get_azure_ips_connection()

        results = self.mongo_connector.perform_find_one(azure_ips_collection, {})

        if results is not None:
            for result in results["prefixes"]:
                self.Azure_IPs.append(IPNetwork(result["ip_prefix"]))

    def __get_gcp_ips(self):
        """
        Get the list of GCP IPv4 CIDRs.
        """
        self.GCP_IPs = []
        gcp_ips_collection = self.mongo_connector.get_gcp_ips_connection()

        results = self.mongo_connector.perform_find_one(gcp_ips_collection, {})

        if results is not None:
            for result in results["prefixes"]:
                self.GCP_IPs.append(IPNetwork(result["ip_prefix"]))

    def __get_gcp_ipv6s(self):
        """
        Get the list of GCP IPv6 CIDRs.
        """
        if self.GCP_IPs is None:
            self.GCP_IPs = []

        gcp_ips_collection = self.mongo_connector.get_gcp_ips_connection()

        results = self.mongo_connector.perform_find_one(gcp_ips_collection, {})

        if results is not None:
            for result in results["ipv6_prefixes"]:
                self.GCP_IPs.append(IPNetwork(result["ipv6_prefix"]))

    def __get_tracked_cidrs(self):
        """
        Extract the list of tracked IPv4 CIDR Networks from the Mongo database.
        They are stored within the adope_ips global.
        """
        self.Tracked_CIDRs = []

        ipzone_collection = self.mongo_connector.get_ipzone_connection()

        results = self.mongo_connector.perform_find(
            ipzone_collection, {"status": {"$ne": "false_positive"}}
        )
        for result in results:
            self.Tracked_CIDRs.append(IPNetwork(result["zone"]))

    def __get_tracked_ipv6_cidrs(self):
        """
        Extract the list of tracked IPv6 CIDR Networks from the Mongo database.
        They are stored within the adope_ips global.
        """
        if self.Tracked_CIDRs is None:
            self.Tracked_CIDRs = []

        ipzone_collection = self.mongo_connector.get_ipv6_zone_connection()

        results = self.mongo_connector.perform_find(
            ipzone_collection, {"status": {"$ne": "false_positive"}}
        )
        for result in results:
            self.Tracked_CIDRs.append(IPNetwork(result["zone"]))

    def check_in_cidr(self, ip, cidrs):
        """
        Is the provided IP in one of the provided CIDRs?
        Returns a true/false result
        """
        try:
            if isinstance(ip, str):
                local_ip = IPAddress(ip)
            else:
                local_ip = ip

            for network in cidrs:
                if local_ip in network:
                    return True
        except:
            return False

        return False

    def find_cidr(self, ip, cidrs):
        """
        Is the provided IP in one of the provided CIDRs?
        Returns the CIDR that matches
        """
        try:
            if isinstance(ip, str):
                local_ip = IPAddress(ip)
            else:
                local_ip = ip

            for network in cidrs:
                if local_ip in network:
                    return network
        except:
            return None

        return None

    def is_aws_ip(self, ip):
        """
        Is the provided IP within one of the AWS CIDRs?
        """
        if isinstance(ip, str):
            ip_addr = IPAddress(ip)
        else:
            ip_addr = ip

        if self.AWS_IPs is None:
            self.__get_aws_ips()
            self.__get_aws_ipv6s()

        return self.check_in_cidr(ip_addr, self.AWS_IPs)

    def is_azure_ip(self, ip):
        """
        Is the provided IP within one of the Azure CIDRs?
        """
        if isinstance(ip, str):
            ip_addr = IPAddress(ip)
        else:
            ip_addr = ip

        if self.Azure_IPs is None:
            self.__get_azure_ips()

        return self.check_in_cidr(ip_addr, self.Azure_IPs)

    def is_gcp_ip(self, ip):
        """
        Is the provided IP within one of the GCP CIDRs?
        """
        if isinstance(ip, str):
            ip_addr = IPAddress(ip)
        else:
            ip_addr = ip

        if self.GCP_IPs is None:
            self.__get_gcp_ips()
            self.__get_gcp_ipv6s()

        return self.check_in_cidr(ip_addr, self.GCP_IPs)

    def is_tracked_ip(self, ip):
        """
        Is the provided IP within one of the Tracked CIDRs?
        """
        if isinstance(ip, str):
            ip_addr = IPAddress(ip)
        else:
            ip_addr = ip

        if self.Tracked_CIDRs is None:
            self.__get_tracked_cidrs()
            self.__get_tracked_ipv6_cidrs()

        return self.check_in_cidr(ip_addr, self.Tracked_CIDRs)

    def is_akamai_ip(self, ip):
        """
        Is the provided IP within an Akamai CIDR?
        """
        if isinstance(ip, str):
            ip_addr = IPAddress(ip)
        else:
            ip_addr = ip

        if self.Akamai_IPs is None:
            self.__get_akamai_ips()
            self.__get_akamai_ipv6s()

        return self.check_in_cidr(ip_addr, self.Akamai_IPs)

    def is_local_ip(self, ip):
        """
        Returns true if the IP is in a local IP address range
        """
        if (
            self.check_in_cidr(
                ip,
                [
                    IPNetwork("10.0.0.0/8"),
                    IPNetwork("172.16.0.0/12"),
                    IPNetwork("fd00::/8"),
                    IPNetwork("192.168.0.0/16"),
                    IPNetwork("127.0.0.0/8"),
                ],
            )
            or ip == "255.255.255.255"
        ):
            return True
        return False

    def find_partner_range(self, ip):
        """
        Find the CIDR range and partner for the provided IP
        """
        if isinstance(ip, str):
            ip_addr = IPAddress(ip)
        else:
            ip_addr = ip

        if self.Akamai_IPs is None:
            self.__get_akamai_ips()
            self.__get_akamai_ipv6s()

        cidr = self.find_cidr(ip_addr, self.Akamai_IPs)
        if cidr is not None:
            return self.AKAMAI, cidr

        if self.AWS_IPs is None:
            self.__get_aws_ips()
            self.__get_aws_ipv6s()

        cidr = self.find_cidr(ip_addr, self.AWS_IPs)
        if cidr is not None:
            return self.AWS, cidr

        if self.Azure_IPs is None:
            self.__get_azure_ips()

        cidr = self.find_cidr(ip_addr, self.Azure_IPs)
        if cidr is not None:
            return self.AZURE, cidr

        if self.Tracked_CIDRs is None:
            self.__get_tracked_cidrs()
            self.__get_tracked_ipv6_cidrs()

        cidr = self.find_cidr(ip_addr, self.Tracked_CIDRs)
        if cidr is not None:
            return self.TRACKED, cidr

        if self.GCP_IPs is None:
            self.__get_gcp_ips()
            self.__get_gcp_ipv6s()

        cidr = self.find_cidr(ip_addr, self.GCP_IPs)
        if cidr is not None:
            return self.GCP, cidr

        return self.UNKNOWN, None

    def find_partner_notes(self, cidr_value, partner):
        """
        Find the region and/or note information for the provided CIDR.
        Returns a string with the relevant data.
        """
        if isinstance(cidr_value, str):
            cidr = IPNetwork(cidr_value)
        else:
            cidr = cidr_value

        if partner == self.AWS:
            aws_ips_collection = self.mongo_connector.get_aws_ips_connection()

            if cidr.version == 4:
                meta_result = self.mongo_connector.perform_find_one(
                    aws_ips_collection, {"prefixes.ip_prefix": str(cidr)}
                )
                for result in meta_result["prefixes"]:
                    if result["ip_prefix"] == str(cidr):
                        return result["region"]
            else:
                meta_result = self.mongo_connector.perform_find_one(
                    aws_ips_collection, {"ipv6_prefixes.ipv6_prefix": str(cidr)}
                )
                for result in meta_result["ipv6_prefixes"]:
                    if result["ipv6_prefix"] == str(cidr):
                        return result["region"]
        elif partner == self.AZURE:
            azure_ips_collection = self.mongo_connector.get_azure_ips_connection()

            meta_result = self.mongo_connector.perform_find_one(
                azure_ips_collection, {"prefixes.ip_prefix": str(cidr)}
            )
            for result in meta_result["prefixes"]:
                if result["ip_prefix"] == str(cidr):
                    return result["region"]
        elif partner == self.TRACKED:
            if cidr.version == 4:
                ip_zones_collection = self.mongo_connector.get_ipzone_connection()

                meta_result = self.mongo_connector.perform_find_one(
                    ip_zones_collection, {"zone": str(cidr)}
                )
                if meta_result is not None and "notes" in meta_result:
                    return meta_result["notes"]
            else:
                ipv6_zone_collection = self.mongo_connector.get_ipv6_zone_connection()

                meta_result = self.mongo_connector.perform_find_one(
                    ipv6_zone_collection, {"zone": str(cidr)}
                )
                if meta_result is not None and "notes" in meta_result:
                    return meta_result["notes"]
        elif partner == self.AKAMAI:
            return ""
        elif partner == self.GCP:
            return ""
        elif partner == self.UNKNOWN:
            return ""

        return ""

    def find_reverse_dns(self, ip):
        """
        Perform a reverse DNS lookup of the IP
        """
        if isinstance(ip, str):
            ip_addr = IPAddress(ip)

        google_gns = GoogleDNS.GoogleDNS()

        results = google_gns.fetch_DNS_records(
            ip_addr.reverse_dns, google_gns.DNS_TYPES["ptr"]
        )

        if len(results) > 0:
            return results[0]["value"]

        return None

    def find_splunk_data(self, ip, partner):
        """
        Search splunk records for related information
        """

        if isinstance(ip, str):
            ip_addr = IPAddress(ip)
        else:
            ip_addr = ip

        if partner == self.AWS:
            """
            Add your own logic here to determine if it is an AWS resource that you own
            """
            return None

        elif partner == self.AZURE:
            """
            Add your own logic here to determine if it is an Azure resource that you own
            """
            return None

        elif partner == self.AKAMAI:
            return None
        elif partner == self.GCP_IPs:
            return None
        elif partner == self.TRACKED:
            return None
        elif partner == self.UNKNOWN:
            return None

        return None

    def find_dns_zones(self, ip):
        """
        Find DNS zones related to the IP address.
        """
        dns_manager = DNSManager.DNSManager(self.mongo_connector)

        results = dns_manager.find_multiple({"value": ip}, None)

        zones = []
        domains = []

        for result in results:
            if result["zone"] not in zones and result["zone"] != "":
                zones.append(result["zone"])
            if result["fqdn"] not in domains and result["fqdn"] != ip:
                domains.append(result["fqdn"])

        return zones, domains

    def extract_rdns_info(self, ip):
        """
        Extract RDNS domain and zone information from the IP address
        """
        rnds_value = self.find_reverse_dns(ip)

        if rnds_value is None:
            return "", None

        if self._ZONES is None:
            self._ZONES = ZoneManager.get_distinct_zones(self.mongo_connector)

        rdns_zone = ZoneManager.get_root_domain(rnds_value, None)

        return rnds_value, rdns_zone

    def insert_record(self, ip, source=None):
        """
        Insert an IP into the tracking table
        This function completely rebuilds the record because it is simpler and cleaner than tracking which
        data came from which location and whether to expire specific sections.
        """

        if ip is None or ip == "":
            self._logger.error("ERROR: Sent an invalid IP address: " + str(ip))
            return

        if isinstance(ip, str):
            ip_addr = IPAddress(ip)
        else:
            ip_addr = ip
            ip = str(ip_addr)

        if self.is_local_ip(ip):
            self._logger.warning("WARNING: all_ips does not track local IP addresses")
            return

        if ip_addr is None:
            self._logger.error("ERROR: Could not insert: " + str(ip))
            return

        record = {}
        record["ip"] = ip
        record["version"] = ip_addr.version
        record["updated"] = datetime.now()

        # Check existance
        result = self.mongo_connector.perform_find_one(
            self.all_ips_collection, {"ip": ip}
        )
        if result is not None:
            record["created"] = result["created"]
        else:
            record["created"] = datetime.now()

        if source is not None:
            if result is not None and "sources" not in result:
                record["sources"] = [{"source": source, "updated": datetime.now()}]
            elif result is not None:
                record["sources"] = []
                for source_entry in result["sources"]:
                    if source_entry["source"] == source:
                        record["sources"].append(
                            {"source": source, "updated": datetime.now()}
                        )
                    else:
                        record["sources"].append(source_entry)

        record["zones"], record["domains"] = self.find_dns_zones(ip)

        rdns_value, rdns_zone = self.extract_rdns_info(ip)
        if rdns_value != "":
            record["reverse_dns"] = rdns_value

            if (
                rdns_zone is not None
                and rdns_zone in self._ZONES
                and rdns_zone not in record["zones"]
            ):
                record["zones"].append(rdns_zone)

        partner, cidr = self.find_partner_range(ip_addr)

        if partner != self.UNKNOWN:
            notes = self.find_partner_notes(cidr, partner)

            record["host"] = {}
            record["host"]["hosting_partner"] = partner
            record["host"]["host_cidr"] = str(cidr)
            record["host"]["notes"] = notes

            if partner == self.AWS or partner == self.AZURE:
                result = self.find_splunk_data(ip, partner)
                if result is not None:
                    """
                    Add relevant data to the record
                    """
                    record["host"]["splunk"] = result

        self.all_ips_collection.replace_one({"ip": ip}, record, upsert=True)

    def delete_records_by_date(self, expire_date):
        """
        Delete old records that have not been updated since the provided date
        """

        results = self.mongo_connector.perform_find(
            self.all_ips_collection, {"updated": {"$lt": expire_date}}, batch_size=100
        )

        for result in results:
            self.all_ips_collection.delete_one({"ip": result["ip"]})

    def delete_records_by_date_and_source(self, source, expire_date):
        """
        Delete old records by source and date
        """

        results = self.all_ips_collection.find(
            {
                "sources": {
                    "$elemMatch": {"source": source, "updated": {"$lt": expire_date}}
                }
            }
        ).batch_size(30)

        for result in results:
            if len(result["sources"]) > 1:
                self.all_ips_collection.update_one(
                    {"_id": ObjectId(result["_id"])},
                    {"$pull": {"sources": {"source": source}}},
                )
            else:
                self.all_ips_collection.delete_one({"_id": ObjectId(result["_id"])})

        return True
