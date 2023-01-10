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
This script extracts domain names from all the SSL certificates collected by Marinus.
The script will then use Google HTTPS over DNS to get their DNS records and store them.

This script assumes that the censys and certificate transparency scripts have completed.
"""

import argparse
import json
import logging
import time
from datetime import datetime

from libs3 import DNSManager, GoogleDNS, JobsManager, MongoConnector
from libs3.LoggingUtil import LoggingUtil
from libs3.ZoneManager import ZoneManager


def add_to_list(str_to_add, dns_names):
    """
    This will add a string to the dns_names array if it does not exist.
    It will then return the index of the string within the Array
    """
    if str_to_add.lower() not in dns_names:
        dns_names.append(str_to_add.lower())
    return dns_names.index(str_to_add.lower())


def add_to_round_two(str_to_add, round_two):
    """
    This will add a string to the round_two array if it does not exist.
    It will then return the index of the string within the Array
    """
    if str_to_add.lower() not in round_two:
        round_two.append(str_to_add.lower())
    return round_two.index(str_to_add.lower())


def is_tracked_zone(cname, zones):
    """
    Is the root domain for the provided cname one of the known domains?
    """

    for zone in zones:
        if cname.endswith("." + zone) or cname == zone:
            return True
    return False


def get_tracked_zone(name, zones):
    """
    What is the tracked zone for the provided hostname?
    """
    for zone in zones:
        if name.endswith("." + zone) or name == zone:
            return zone
    return None


def extract_ct_certificate_names(dns_names, mongo_connector):
    """
    Extract the domain names from certificates found in the certificate transparency database.
    """
    ct_collection = mongo_connector.get_certificate_transparency_connection()

    res = ct_collection.find({"isExpired": False}, {"subject_dns_names": 1})

    for result in res:
        for dns_name in result["subject_dns_names"]:
            add_to_list(dns_name, dns_names)

    res = ct_collection.find({"isExpired": False}, {"subject_common_names": 1})

    for result in res:
        for dns_name in result["subject_common_names"]:
            add_to_list(dns_name, dns_names)


def extract_censys_certificate_names(logger, dns_names, mongo_connector):
    """
    Extract the domain names from certificates found in the censys records.
    """
    censys_collection = mongo_connector.get_censys_connection()

    res = censys_collection.find(
        {
            "$or": [
                {
                    "p443.https.tls.certificate.parsed.subject.common_name": {
                        "$exists": True
                    }
                },
                {
                    "p443.https.tls.certificate.parsed.extensions.subject_alt_name.dns_names": {
                        "$exists": True
                    }
                },
            ]
        },
        {
            "p443.https.tls.certificate.parsed.subject.common_name": 1,
            "p443.https.tls.certificate.parsed.extensions.subject_alt_name.dns_names": 1,
        },
    )

    for ssl_res in res:
        try:
            for dns_name in ssl_res["p443"]["https"]["tls"]["certificate"]["parsed"][
                "subject"
            ]["common_name"]:
                add_to_list(dns_name, dns_names)
        except KeyError:
            logger.debug("Censys: Common Name key not found.")

        try:
            for dns_name in ssl_res["p443"]["https"]["tls"]["certificate"]["parsed"][
                "extensions"
            ]["subject_alt_name"]["dns_names"]:
                add_to_list(dns_name, dns_names)
        except KeyError:
            logger.debug("Censys: DNS Name key not found.")


def extract_zgrab_certificate_names(logger, dns_names, mongo_connector):
    """
    Extract the domain names from certificates found in the ZGrab port records.
    """
    zgrab_port_collection = mongo_connector.get_zgrab_port_data_connection()

    res = zgrab_port_collection.find(
        {
            "$or": [
                {
                    "data.tls.server_certificates.certificate.parsed.subject.common_name": {
                        "$exists": True
                    }
                },
                {
                    "data.tls.server_certificates.certificate.parsed.extensions.subject_alt_name.dns_names": {
                        "$exists": True
                    }
                },
            ]
        },
        {
            "data.tls.server_certificates.certificate.parsed.subject.common_name": 1,
            "data.tls.server_certificates.certificate.parsed.extensions.subject_alt_name.dns_names": 1,
        },
    )

    for ssl_res in res:
        try:
            for dns_name in ssl_res["data"]["tls"]["server_certificates"][
                "certificate"
            ]["parsed"]["subject"]["common_name"]:
                add_to_list(dns_name, dns_names)
        except KeyError:
            logger.debug("Zgrab: Common Name key not found.")

        try:
            for dns_name in ssl_res["data"]["tls"]["server_certificates"][
                "certificate"
            ]["parsed"]["extensions"]["subject_alt_name"]["dns_names"]:
                add_to_list(dns_name, dns_names)
        except KeyError:
            logger.debug("Zgrab: DNS Name key not found.")


def extract_zgrab2_certificate_names(logger, dns_names, mongo_connector):
    """
    Extract the domain names from certificates found in the ZGrab 2.0 port records.
    """
    zgrab_port_collection = mongo_connector.get_zgrab_port_data_connection()

    res = zgrab_port_collection.find(
        {
            "$or": [
                {
                    "data.tls.result.handshake_log.server_certificates.certificate.parsed.subject.common_name": {
                        "$exists": True
                    }
                },
                {
                    "data.tls.result.handshake_log.server_certificates.certificate.parsed.extensions.subject_alt_name.dns_names": {
                        "$exists": True
                    }
                },
            ]
        },
        {
            "data.tls.result.handshake_log.server_certificates.certificate.parsed.subject.common_name": 1,
            "data.tls.result.handshake_log.server_certificates.certificate.parsed.extensions.subject_alt_name.dns_names": 1,
        },
    )

    for ssl_res in res:
        try:
            for dns_name in ssl_res["data"]["tls"]["result"]["handshake_log"][
                "server_certificates"
            ]["certificate"]["parsed"]["subject"]["common_name"]:
                add_to_list(dns_name, dns_names)
        except KeyError:
            logger.debug("ZGrab2: Common Name key not found.")

        try:
            for dns_name in ssl_res["data"]["tls"]["result"]["handshake_log"][
                "server_certificates"
            ]["certificate"]["parsed"]["extensions"]["subject_alt_name"]["dns_names"]:
                add_to_list(dns_name, dns_names)
        except KeyError:
            logger.debug("ZGrab2: DNS Name key not found.")


def main(logger=None):
    """
    Begin Main...
    """
    if logger is None:
        logger = LoggingUtil.create_log(__name__)

    now = datetime.now()
    print("Starting: " + str(now))
    logger.info("Starting...")

    mongo_connector = MongoConnector.MongoConnector()
    dns_manager = DNSManager.DNSManager(mongo_connector)
    google_dns = GoogleDNS.GoogleDNS()
    jobs_manager = JobsManager.JobsManager(mongo_connector, "extract_ssl_domains")
    jobs_manager.record_job_start()

    parser = argparse.ArgumentParser(
        description="Search TLS certificates for additional DNS names"
    )
    parser.add_argument(
        "--zgrab_version",
        default=2,
        type=int,
        choices=[1, 2],
        metavar="version",
        help="The version of ZGrab used to collect data",
    )
    args = parser.parse_args()

    dns_names = []
    round_two = []

    zones = ZoneManager.get_distinct_zones(mongo_connector)

    # Collect the list of domains from the SSL Certificates
    extract_ct_certificate_names(dns_names, mongo_connector)

    # Retired
    # extract_censys_certificate_names(dns_names, mongo_connector)

    if args.zgrab_version == 1:
        extract_zgrab_certificate_names(logger, dns_names, mongo_connector)
    else:
        extract_zgrab2_certificate_names(logger, dns_names, mongo_connector)

    input_list = []

    # Some SSL certificates are for multiple domains.
    # The tracked company may not own all domains.
    # Therefore, we filter to only the root domains that belong to the tracked company.
    logger.info("Pre-filter list: " + str(len(dns_names)))
    for hostname in dns_names:
        if not hostname.startswith("*"):
            zone = get_tracked_zone(hostname, zones)
            if zone != None:
                ips = google_dns.fetch_DNS_records(hostname)

                # Pause to prevent DoS-ing of Google's HTTPS DNS Service
                time.sleep(1)

                if ips != []:
                    for ip_addr in ips:
                        temp_zone = get_tracked_zone(ip_addr["fqdn"], zones)
                        if temp_zone is not None:
                            record = {"fqdn": ip_addr["fqdn"]}
                            record["zone"] = temp_zone
                            record["created"] = datetime.now()
                            record["type"] = ip_addr["type"]
                            record["value"] = ip_addr["value"]
                            record["status"] = "unknown"
                            input_list.append(record)

                        if ip_addr["type"] == "cname" and is_tracked_zone(
                            ip_addr["value"], zones
                        ):
                            add_to_round_two(ip_addr["value"], round_two)

                else:
                    logger.warning("Failed IP Lookup for: " + hostname)
            else:
                logger.warning("Failed match on zone for: " + hostname)
        else:
            logger.warning("Skipping wildcard: " + hostname)

    dead_dns_collection = mongo_connector.get_dead_dns_connection()

    # Some DNS records will be CNAME records pointing to other tracked domains.
    # This is a single level recursion to lookup those domains.
    logger.info("Round Two list: " + str(len(round_two)))
    for hostname in round_two:
        zone = get_tracked_zone(hostname, zones)
        if zone != None:
            ips = google_dns.fetch_DNS_records(hostname)
            time.sleep(1)
            if ips != []:
                for ip_addr in ips:
                    temp_zone = get_tracked_zone(ip_addr["fqdn"], zones)
                    if temp_zone is not None:
                        record = {"fqdn": ip_addr["fqdn"]}
                        record["zone"] = temp_zone
                        record["created"] = datetime.now()
                        record["type"] = ip_addr["type"]
                        record["value"] = ip_addr["value"]
                        record["status"] = "unknown"
                        input_list.append(record)
            else:
                logger.warning("Failed IP Lookup for: " + hostname)
                original_record = dns_manager.find_one({"fqdn": hostname}, "ssl")
                if original_record != None:
                    original_record.pop("_id")
                    mongo_connector.perform_insert(dead_dns_collection, original_record)
        else:
            logger.warning("Failed match on zone for: " + hostname)

    # Record all the results.
    dns_manager.remove_by_source("ssl")
    logger.info("List length: " + str(len(input_list)))
    for final_result in input_list:
        dns_manager.insert_record(final_result, "ssl")

    # Record status
    jobs_manager.record_job_complete()

    now = datetime.now()
    print("Ending: " + str(now))
    logger.info("Complete")


if __name__ == "__main__":
    logger = LoggingUtil.create_log(__name__)

    try:
        main(logger)
    except Exception as e:
        logger.error("FATAL: " + str(e), exc_info=True)
        exit(1)
