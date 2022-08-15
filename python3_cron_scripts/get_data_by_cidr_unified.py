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
This script pulls records from Sonar files provided by the Rapid7 Open Data project.
This script searches the records using the CIDRs related to the tracked organization.
It will store the Sonar files in a './files' directory
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
    IPManager,
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
    Download the provided file and place it in data_dir
    """
    local_filename = data_dir + url.split("/")[-1]
    # NOTE the stream=True parameter
    req = s.get(url, stream=True)
    with open(local_filename, "wb") as local_f:
        for chunk in req.iter_content(chunk_size=128 * 1024):
            if chunk:  # filter out keep-alive new chunks
                local_f.write(chunk)
                local_f.flush()
    return local_filename


def get_sonar_rdns_ips(rdns_collection):
    """
    Get the list of Sonar RDNS IPs from the Marinus database
    """
    ips = []
    results = rdns_collection.find({}, {"ip": 1})
    for result in results:
        ips.append(result["ip"])
    return ips


def get_sonar_dns_ips(dns_manager):
    """
    Get the list of Sonar IP records from the Marinus database
    """
    ips = []
    results = dns_manager.find_multiple({"type": "a"}, "sonar_dns")
    for result in results:
        ips.append(result["value"])
    return ips


def find_zone(domain, zones):
    """
    Does the domain exist in a tracked zone?
    """
    if domain is None:
        return ""

    for zone in zones:
        if domain.endswith("." + zone) or domain == zone:
            return zone

    return ""


def update_dns(logger, dns_file, dns_manager, ip_manager, zones):
    """
    Search DNS file and insert relevant records into the database.
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

            try:
                domain = data["name"]
            except:
                logger.warning("Error with line: " + line)
                domain = ""

            dtype = data["type"]

            try:
                value = data["value"]
            except KeyError:
                logger.warning("Error with line: " + line)
                value = ""
            timestamp = data["timestamp"]

            if (
                dtype == "a"
                and value != ""
                and domain != ""
                and ip_manager.is_tracked_ip(value)
            ):
                logger.debug("Matched DNS " + value)
                zone = find_zone(domain, zones)
                insert_json = {}
                insert_json["fqdn"] = domain
                insert_json["zone"] = zone
                insert_json["type"] = dtype
                insert_json["status"] = "unknown"
                insert_json["value"] = value
                insert_json["sonar_timestamp"] = int(timestamp)
                insert_json["created"] = datetime.now()
                dns_manager.insert_record(insert_json, "sonar_dns")


def check_for_ptr_record(ipaddr, dns_manager, g_dns, zones):
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


def update_rdns(logger, rdns_file, mongo_connection, dns_manager, ip_manager, zones):
    """
    Search RDNS file and insert relevant records into the database.
    """
    g_dns = GoogleDNS.GoogleDNS()
    rdns_collection = mongo_connection.get_sonar_reverse_dns_connection()

    with open(rdns_file, "r") as rdns_f:
        for line in rdns_f:
            try:
                data = json.loads(line)
            except ValueError:
                continue
            except Exception as e:
                logger.error("Error parsing file...")
                logger.error("Exception: " + str(e))
                raise

            if "type" in data and data["type"] != "ptr":
                continue

            try:
                ip_addr = data["name"]
            except:
                ip_addr = None

            try:
                domain = data["value"]
            except KeyError:
                domain = None

            timestamp = data["timestamp"]

            if domain != None and ip_addr != None and ip_manager.is_tracked_ip(ip_addr):
                logger.debug("Matched RDNS " + ip_addr)
                zone = find_zone(domain, zones)
                result = mongo_connection.perform_count(
                    rdns_collection, {"ip": ip_addr}
                )

                if result == 0:
                    insert_json = {}
                    insert_json["ip"] = ip_addr
                    insert_json["zone"] = zone
                    insert_json["fqdn"] = domain
                    insert_json["status"] = "unknown"
                    insert_json["sonar_timestamp"] = int(timestamp)
                    insert_json["created"] = datetime.now()
                    insert_json["updated"] = datetime.now()
                    mongo_connection.perform_insert(rdns_collection, insert_json)
                else:
                    rdns_collection.update_one(
                        {"ip": ip_addr},
                        {"$set": {"fqdn": domain}, "$currentDate": {"updated": True}},
                    )

                check_for_ptr_record(ip_addr, dns_manager, g_dns, zones)


def download_remote_files(logger, s, file_reference, data_dir, jobs_manager):
    """
    Download and unzip the given file reference.
    """
    subprocess.run("rm " + data_dir + "*", shell=True)

    dns_file = download_file(s, file_reference, data_dir)

    logger.info("File downloaded.")

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

    parser = argparse.ArgumentParser(description="Parse Sonar files based on CIDRs.")
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

    r7 = Rapid7.Rapid7()

    if args.database == "remote":
        mongo_connection = RemoteMongoConnector.RemoteMongoConnector()
        dns_manager = DNSManager.DNSManager(mongo_connection, "get_sonar_data_dns")
    else:
        mongo_connection = MongoConnector.MongoConnector()
        dns_manager = DNSManager.DNSManager(mongo_connection)

    ip_manager = IPManager.IPManager(mongo_connection)

    zones = ZoneManager.get_distinct_zones(mongo_connection)
    logger.info("Zone length: " + str(len(zones)))

    save_directory = args.download_location
    check_save_location(save_directory)

    # A session is necessary for the multi-step log-in process
    s = requests.Session()

    if args.sonar_file_type == "rdns":
        jobs_manager = JobsManager.JobsManager(
            mongo_connection, "get_data_by_cidr_rdns"
        )
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
            update_rdns(
                logger, unzipped_rdns, mongo_connection, dns_manager, ip_manager, zones
            )
        except Exception as ex:
            logger.error("Unexpected error: " + str(ex))
            jobs_manager.record_job_error()
            exit(0)

        logger.info("RDNS Complete")
        jobs_manager.record_job_complete()

    elif args.sonar_file_type == "dns-any":
        jobs_manager = JobsManager.JobsManager(mongo_connection, "get_data_by_cidr_dns")
        jobs_manager.record_job_start()

        try:
            html_parser = r7.find_file_locations(s, "fdns", jobs_manager)

            if html_parser.any_url != "":
                unzipped_dns = download_remote_files(
                    logger, s, html_parser.any_url, save_directory, jobs_manager
                )
                update_dns(logger, unzipped_dns, dns_manager, ip_manager, zones)
        except Exception as ex:
            logger.error("Unexpected error: " + str(ex))

            jobs_manager.record_job_error()
            exit(0)

    elif args.sonar_file_type == "dns-a":
        jobs_manager = JobsManager.JobsManager(
            mongo_connection, "get_data_by_cidr_dns-a"
        )
        jobs_manager.record_job_start()

        try:
            html_parser = r7.find_file_locations(s, "fdns", jobs_manager)

            if html_parser.a_url != "":
                unzipped_dns = download_remote_files(
                    logger, s, html_parser.a_url, save_directory, jobs_manager
                )
                update_dns(logger, unzipped_dns, dns_manager, ip_manager, zones)
            if html_parser.aaaa_url != "":
                unzipped_dns = download_remote_files(
                    logger, s, html_parser.aaaa_url, save_directory, jobs_manager
                )
                update_dns(logger, unzipped_dns, dns_manager, ip_manager, zones)
        except Exception as ex:
            logger.error("Unexpected error: " + str(ex))

            jobs_manager.record_job_error()
            exit(0)

        logger.info("DNS Complete")

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
