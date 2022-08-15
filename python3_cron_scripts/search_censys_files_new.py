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
This script parses the file that was downloaded by get_files and identifies matches.
This script can be run daily because it checks for conflicting processes.
That said, the search_files script can take over a 2 days to run and take 99% of a core.

It should be run daily approximately 10.5 hours after get_files run its checks (8 hours to
download and then an additional 2+ hours to unpack).

Therefore, if get_file runs Monday at 1am and finishes Tuesday at 11:20am, then search
files can kick in at 11:30am.

Eventually, the two files can be joined as one so as not to play the crontab game.
"""

import json
import logging
import os.path
import re
import subprocess
import sys
from datetime import datetime

from libs3 import IPManager, RemoteMongoConnector
from libs3.LoggingUtil import LoggingUtil
from libs3.ZoneManager import ZoneManager

# Constants for output files
FILENAME_FILE = "filename.txt"


def is_running(process):
    """
    Is the provided process name is currently running?
    """
    proc_list = subprocess.Popen(["ps", "axw"], stdout=subprocess.PIPE)
    for proc in proc_list.stdout:
        if re.search(process, str(proc)):
            return True
    return False


def check_in_org(entry, orgs):
    """
    Obtain the organization from the entry's SSL certificate.
    Determine whether the org from the certificate is in the provided list of orgs.
    """
    if "p443" in entry:
        try:
            value = entry["p443"]["https"]["tls"]["certificate"]["parsed"]["subject"][
                "organization"
            ]
        except KeyError:
            return False

        for org in orgs:
            if org in value:
                return True

    return False


def zone_compare(value, zones):
    utf_val = value
    for zone in zones:
        if utf_val.endswith("." + zone) or utf_val == zone:
            return zone
    return None


def check_in_zone(entry, zones):
    """
    Obtain the DNS names from the common_name and dns_zones from the entry's SSL certificate.
    Determine if the entry's DNS names is in the list of provided zones.
    Return the matched zone.
    """
    cert_zones = []

    if "p443" in entry:
        try:
            temp1 = entry["p443"]["https"]["tls"]["certificate"]["parsed"]["subject"][
                "common_name"
            ]
        except KeyError:
            temp1 = []

        try:
            temp2 = entry["p443"]["https"]["tls"]["certificate"]["parsed"][
                "extensions"
            ]["subject_alt_name"]["dns_names"]
        except KeyError:
            temp2 = []

        value_array = temp1 + temp2
        for value in value_array:
            zone = zone_compare(value, zones)
            if zone is not None and zone not in cert_zones:
                cert_zones.append(zone)

        return cert_zones

    return []


def lookup_domain(entry, zones, all_dns_collection):
    """
    This tries to determine if the IP is known in the all_dns_collection.
    """
    domain_result = all_dns_collection.find({"value": entry["ip"]})
    domains = []
    domain_zones = []
    if domain_result is not None:
        for result in domain_result:
            domains.append(result["fqdn"])

    if len(domains) > 0:
        for domain in domains:
            zone = zone_compare(domain, zones)
            if zone is not None:
                domain_zones.append(zone)

    return (domains, domain_zones)


def insert_result(entry, results_collection):
    """
    Insert the matched IP into the collection of positive results.
    This was done as an update because it was clear whether Censys would de-duplicate.
    """
    entry["createdAt"] = datetime.utcnow()
    results_collection.update_one({"ip": entry["ip"]}, entry, upsert=True)


def main(logger=None):
    """
    Begin main...
    """
    if logger is None:
        logger = LoggingUtil.create_log(__name__)

    if is_running("get_censys_files.py"):
        """
        Check to see if a download is in process...
        """
        logger.warning("Can't run due to get_files running. Goodbye!")
        exit(0)

    if is_running(os.path.basename(__file__)):
        """
        Check to see if a previous attempt to parse is still running...
        """
        logger.warning("I am already running! Goodbye!")
        exit(0)

    # Make the relevant database connections
    RMC = RemoteMongoConnector.RemoteMongoConnector()

    ip_manager = IPManager.IPManager(RMC)

    # Verify that the get_files script has a recent file in need of parsing.
    jobs_collection = RMC.get_jobs_connection()

    status = jobs_collection.find_one({"job_name": "censys"})
    if status["status"] != "DOWNLOADED":
        logger.warning("The status is not set to DOWNLOADED. Goodbye!")
        exit(0)

    now = datetime.now()
    print("Starting: " + str(now))
    logger.info("Starting...")

    # Collect the list of available zones
    zones = ZoneManager.get_distinct_zones(RMC)

    logger.info("Zones: " + str(len(zones)))

    # Get the current configuration information for Marinus.
    config_collection = RMC.get_config_connection()

    configs = config_collection.find({})
    orgs = []
    for org in configs[0]["SSL_Orgs"]:
        orgs.append(org)

    logger.info("Orgs: " + str(len(orgs)))

    # Obtain the name of the decompressed file.
    filename_f = open(FILENAME_FILE, "r")
    decompressed_file = filename_f.readline()
    filename_f.close()

    # For manual testing: decompressed_file = "ipv4.json"

    logger.info("Beginning file processing...")

    # Remove old results from the database
    results_collection = RMC.get_results_connection()
    results_collection.delete_many({})
    all_dns_collection = RMC.get_all_dns_connection()

    try:
        with open(decompressed_file, "r") as dec_f:
            for line in dec_f:
                try:
                    entry = json.loads(line)

                    """
                    Does the SSL certificate match a known organization?
                    Is the IP address in a known CIDR?
                    Is the IP address recorded in Splunk?
                    """
                    if (
                        check_in_org(entry, orgs)
                        or ip_manager.is_tracked_ip(entry["ip"])
                        or ip_manager.find_splunk_data(entry["ip"], "AWS") is not None
                        or ip_manager.find_splunk_data(entry["ip"], "AZURE") is not None
                    ):
                        entry["zones"] = check_in_zone(entry, zones)
                        entry["aws"] = ip_manager.is_aws_ip(entry["ip"])
                        entry["azure"] = ip_manager.is_azure_ip(entry["ip"])
                        (domains, zones) = lookup_domain(
                            entry, zones, all_dns_collection
                        )
                        if len(domains) > 0:
                            entry["domains"] = domains
                            if len(zones) > 0:
                                for zone in zones:
                                    if zone not in entry["zones"]:
                                        entry["zones"].append(zone)
                        insert_result(entry, results_collection)
                    # else:
                    #     #This will add days to the amount of time necessary to scan the file.
                    #     matched_zones = check_in_zone(entry, zones)
                    #     if matched_zones != []:
                    #         entry['zones'] = matched_zones
                    #         entry['aws'] = ip_manager.is_aws_ip(entry['ip'])
                    #         entry['azure'] = ip_manager.is_azure_ip(entry['ip'])
                    #         insert_result(entry, results_collection)
                except ValueError as err:
                    logger.error("Value Error!")
                    logger.error(str(err))
                except:
                    logger.error("Line unexpected error: " + str(sys.exc_info()[0]))
                    logger.error("Line unexpected error: " + str(sys.exc_info()[1]))
    except IOError as err:
        logger.error("I/O error({0}): {1}".format(err.errno, err.strerror))
        exit(1)
    except:
        logger.error("Unexpected error: " + str(sys.exc_info()[0]))
        logger.error("Unexpected error: " + str(sys.exc_info()[1]))
        exit(1)

    # Indicate that the processing of the job is complete and ready for download to Marinus
    jobs_collection.update_one(
        {"job_name": "censys"},
        {"$currentDate": {"updated": True}, "$set": {"status": "COMPLETE"}},
    )

    now = datetime.now()
    print("Ending: " + str(now))
    logger.info("Complete.")


if __name__ == "__main__":
    logger = LoggingUtil.create_log(__name__)

    try:
        main(logger)
    except Exception as e:
        logger.error("FATAL: " + str(e), exc_info=True)
        exit(1)

exit(0)
