#!/usr/bin/python3

# Copyright 2021 Adobe. All rights reserved.
# This file is licensed to you under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License. You may obtain a copy
# of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR REPRESENTATIONS
# OF ANY KIND, either express or implied. See the License for the specific language
# governing permissions and limitations under the License.

"""
This script searches Sonar DNS data provided through Rapid7 Open Data.
This script searches the data for the root domains tracked by Marinus.
It will store the Sonar files in a './files' directory.
"""

import argparse
import ipaddress
import json
import logging
import os
import subprocess
import sys
import time
from datetime import datetime

import requests
from libs3 import (
    DNSManager,
    GoogleDNS,
    JobsManager,
    MongoConnector,
    Rapid7,
    RemoteMongoConnector,
)
from libs3.LoggingUtil import LoggingUtil
from libs3.ZoneManager import ZoneManager


def is_running(process):
    """
    Is the provided process name is currently running?
    """
    proc_list = subprocess.Popen(["pgrep", "-f", process], stdout=subprocess.PIPE)
    for proc in proc_list.stdout:
        if proc.decode("utf-8").rstrip() != str(os.getpid()) and proc.decode(
            "utf-8"
        ).rstrip() != str(os.getppid()):
            return True
    return False


def download_file(s, url, data_dir):
    """
    Download the file from the provided URL and put it in data_dir
    """
    local_filename = data_dir + url.split("/")[-1]
    # NOTE the stream=True parameter
    req = s.get(url, stream=True)
    with open(local_filename, "wb") as out_f:
        for chunk in req.iter_content(chunk_size=128 * 1024):
            if chunk:  # filter out keep-alive new chunks
                out_f.write(chunk)
    return local_filename


def find_zone(domain, zones):
    """
    Determine if the domain is in a tracked zone.
    """
    if domain is None:
        return ""

    for zone in zones:
        if domain.endswith("." + zone) or domain == zone:
            return zone
    return ""


def update_dns(logger, dns_file, zones, dns_mgr):
    """
    Insert any matching Sonar DNS records in the Marinus database.
    """
    with open(dns_file, "r") as dns_f:
        for line in dns_f:
            try:
                data = json.loads(line)
            except ValueError:
                continue
            except Exception as e:
                logger.error("Error parsing file...")
                logger.error("Exception: " + str(e))
                raise

            dtype = data["type"]
            try:
                value = data["value"]
                domain = data["name"]
                zone = find_zone(domain, zones)
            except KeyError:
                logger.warning("Error with line: " + line)
                value = ""
                zone = ""
                domain = ""

            timestamp = data["timestamp"]

            if zone != "" and value != "":
                logger.debug("Domain matches! " + domain + " Zone: " + zone)

                if dtype.startswith("unk_in_"):
                    # Sonar didn't recognize the response
                    type_num = int(dtype[7:])
                    g_dns = GoogleDNS.GoogleDNS()
                    for key, value in g_dns.DNS_TYPES.items():
                        if value == type_num:
                            dtype = key
                            break

                if dtype.startswith("unk_in_"):
                    # Marinus didn't recognize it either.
                    logger.warning("Unknown type: " + dtype)

                insert_json = {}
                insert_json["fqdn"] = domain
                insert_json["zone"] = zone
                insert_json["type"] = dtype
                insert_json["status"] = "unknown"
                insert_json["value"] = value
                insert_json["sonar_timestamp"] = int(timestamp)
                insert_json["created"] = datetime.now()
                dns_mgr.insert_record(insert_json, "sonar_dns")


def check_for_ptr_record(ipaddr, g_dns, zones, dns_manager):
    """
    For an identified Sonar RDNS record, confirm that there
    is a related PTR record for the IP address. If confirmed,
    add the record to the all_dns collection.
    """
    arpa_record = ipaddress.ip_address(ipaddr).reverse_pointer
    dns_result = g_dns.fetch_DNS_records(arpa_record, g_dns.DNS_TYPES["ptr"])
    if dns_result == []:
        # Lookup failed
        return

    rdns_zone = find_zone(dns_result[0]["value"], zones)

    if rdns_zone != "":
        new_record = dns_result[0]
        new_record["zone"] = rdns_zone
        new_record["created"] = datetime.now()
        new_record["status"] = "unknown"
        dns_manager.insert_record(new_record, "sonar_rdns")


def update_rdns(logger, rdns_file, zones, dns_mgr, mongo_connector):
    """
    Insert any matching Sonar RDNS records in the Marinus database.
    """
    rdns_collection = mongo_connector.get_sonar_reverse_dns_connection()
    g_dns = GoogleDNS.GoogleDNS()

    with open(rdns_file, "r") as read_f:
        for line in read_f:
            try:
                data = json.loads(line)
            except ValueError:
                continue
            except Exception as e:
                logger.error("Error parsing file...")
                logger.error("Exception: " + str(e))
                raise

            try:
                domain = data["value"]
                ip_addr = data["name"]
                zone = find_zone(domain, zones)
            except KeyError:
                domain = ""
                ip_addr = ""
                zone = ""

            timestamp = data["timestamp"]

            if zone != "" and domain != "":
                logger.debug("Domain matches! " + domain + " Zone: " + zone)
                result = mongo_connector.perform_count(rdns_collection, {"ip": ip_addr})
                if result == 0:
                    insert_json = {}
                    insert_json["ip"] = ip_addr
                    insert_json["zone"] = zone
                    insert_json["fqdn"] = domain
                    insert_json["status"] = "unknown"
                    insert_json["sonar_timestamp"] = int(timestamp)
                    insert_json["created"] = datetime.now()
                    insert_json["updated"] = datetime.now()
                    mongo_connector.perform_insert(rdns_collection, insert_json)
                else:
                    rdns_collection.update_one(
                        {"ip": ip_addr},
                        {"$set": {"fqdn": domain}, "$currentDate": {"updated": True}},
                    )

                check_for_ptr_record(ip_addr, g_dns, zones, dns_mgr)


def download_remote_files(logger, s, file_reference, data_dir, jobs_manager):
    """
    Download the provided file URL
    """
    subprocess.run("rm " + data_dir + "*", shell=True)

    dns_file = download_file(s, file_reference, data_dir)

    logger.info("Downloading file")

    try:
        subprocess.run(["gunzip", dns_file], check=True)
    except:
        logger.error("Could not unzip file: " + dns_file)
        jobs_manager.record_job_error()
        exit(1)

    unzipped_dns = dns_file.replace(".gz", "")

    return unzipped_dns


def check_save_location(location):
    """
    Check to see if the directory exists.
    If the directory does not exist, it will automatically create it.
    """
    if not os.path.exists(location):
        os.makedirs(location)


def main(logger=None):
    """
    Begin Main...
    """
    if logger is None:
        logger = LoggingUtil.create_log(__name__)

    if is_running(os.path.basename(__file__)):
        logger.warning("Already running...")
        exit(0)

    now = datetime.now()
    print("Starting: " + str(now))
    logger.info("Starting...")

    parser = argparse.ArgumentParser(
        description="Parse Sonar files based on domain zones."
    )
    parser.add_argument(
        "--sonar_file_type",
        choices=["dns-any", "dns-a", "rdns"],
        required=True,
        help='Specify "dns-any", "dns-a", or "rdns"',
    )
    parser.add_argument(
        "--database",
        choices=["local", "remote"],
        required=False,
        default="local",
        help="Whether to use the local or remote DB",
    )
    parser.add_argument(
        "--download_location",
        required=False,
        default="./files/",
        help="The location to save the downloaded files",
    )
    args = parser.parse_args()

    if args.database == "remote":
        mongo_connector = RemoteMongoConnector.RemoteMongoConnector()
        dns_manager = DNSManager.DNSManager(mongo_connector, "get_sonar_data_dns")
    else:
        mongo_connector = MongoConnector.MongoConnector()
        dns_manager = DNSManager.DNSManager(mongo_connector)

    zones = ZoneManager.get_distinct_zones(mongo_connector)

    r7 = Rapid7.Rapid7()

    save_directory = args.download_location
    check_save_location(save_directory)

    # A session is necessary for the multi-step log-in process
    s = requests.Session()

    if args.sonar_file_type == "rdns":
        logger.info("Updating RDNS records")
        jobs_manager = JobsManager.JobsManager(mongo_connector, "get_sonar_data_rdns")
        jobs_manager.record_job_start()

        try:
            html_parser = r7.find_file_locations(s, "rdns", jobs_manager)
            if html_parser.rdns_url == "":
                logger.error("Unknown Error")
                jobs_manager.record_job_error()
                exit(0)

            unzipped_rdns = download_remote_files(
                logger, s, html_parser.rdns_url, save_directory, jobs_manager
            )
            update_rdns(logger, unzipped_rdns, zones, dns_manager, mongo_connector)
        except Exception as ex:
            logger.error("Unexpected error: " + str(ex))
            jobs_manager.record_job_error()
            exit(0)

        jobs_manager.record_job_complete()
    elif args.sonar_file_type == "dns-any":
        logger.info("Updating DNS ANY records")

        jobs_manager = JobsManager.JobsManager(
            mongo_connector, "get_sonar_data_dns-any"
        )
        jobs_manager.record_job_start()

        try:
            html_parser = r7.find_file_locations(s, "fdns", jobs_manager)
            if html_parser.any_url != "":
                unzipped_dns = download_remote_files(
                    logger, s, html_parser.any_url, save_directory, jobs_manager
                )
                update_dns(logger, unzipped_dns, zones, dns_manager)
        except Exception as ex:
            logger.error("Unexpected error: " + str(ex))
            jobs_manager.record_job_error()
            exit(0)

        jobs_manager.record_job_complete()
    elif args.sonar_file_type == "dns-a":
        logger.info("Updating DNS A, AAAA, and CNAME records")

        jobs_manager = JobsManager.JobsManager(mongo_connector, "get_sonar_data_dns-a")
        jobs_manager.record_job_start()

        try:
            html_parser = r7.find_file_locations(s, "fdns", jobs_manager)
            if html_parser.a_url != "":
                logger.info("Updating A records")
                unzipped_dns = download_remote_files(
                    logger, s, html_parser.a_url, save_directory, jobs_manager
                )
                update_dns(logger, unzipped_dns, zones, dns_manager)
            if html_parser.aaaa_url != "":
                logger.info("Updating AAAA records")
                unzipped_dns = download_remote_files(
                    logger, s, html_parser.aaaa_url, save_directory, jobs_manager
                )
                update_dns(logger, unzipped_dns, zones, dns_manager)
            if html_parser.cname_url != "":
                logger.info("Updating CNAME records")
                unzipped_dns = download_remote_files(
                    logger, s, html_parser.cname_url, save_directory, jobs_manager
                )
                update_dns(logger, unzipped_dns, zones, dns_manager)
        except Exception as ex:
            logger.error("Unexpected error: " + str(ex))
            jobs_manager.record_job_error()
            exit(0)

        jobs_manager.record_job_complete()
    else:
        logger.error("Unrecognized sonar_file_type option. Exiting...")

    now = datetime.now()
    print("Complete: " + str(now))
    logger.info("Complete.")


if __name__ == "__main__":
    logger = LoggingUtil.create_log(__name__)

    try:
        main(logger)
    except Exception as e:
        logger.error("FATAL: " + str(e), exc_info=True)
        exit(1)
