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
This script leverages the OWASP Amass tool to identify additional domain and IP records
through multiple third-party sources.  The Amass tool must be installed on the system
for this script to be usable.

The OWASP Amass tool can be found at: https://github.com/OWASP/Amass/

The config.ini should be used to specify the amass run options for your organization.
Please refer to: https://github.com/OWASP/Amass/blob/master/examples/amass_config.ini

Amass output files will be stored in "./amass_files" unless otherwise specified.

This script does not support "amass.netdomains" or "amass.viz" at this time.
"""
import argparse
import json
import logging
import os.path
import re
import subprocess
import time
from datetime import datetime, timedelta

from dateutil import parser
from libs3 import JobsManager, RemoteMongoConnector
from libs3.LoggingUtil import LoggingUtil
from libs3.ZoneManager import ZoneManager


def is_tracked_zone(cname, zones):
    """
    Does the CNAME belong to a tracked zone?
    """
    for zone in zones:
        if cname.endswith("." + zone) or cname == zone:
            return True
    return False


def check_save_location(save_location):
    """
    Check to see if the directory exists.
    If the directory does not exist, it will automatically create it.
    """
    if not os.path.exists(save_location):
        os.makedirs(save_location)


def main(logger=None):
    """
    Begin main...
    """
    if logger is None:
        logger = LoggingUtil.create_log(__name__)

    mongo_connector = RemoteMongoConnector.RemoteMongoConnector()

    now = datetime.now()
    print("Starting: " + str(now))
    logger.info("Starting...")

    jobs_manager = JobsManager.JobsManager(mongo_connector, "owasp_amass")

    amass_collection = mongo_connector.get_owasp_amass_connection()

    output_dir = "./amass_files/"

    arg_parser = argparse.ArgumentParser(
        description="Run the OWASP Amass tool and store the results in the database."
    )
    arg_parser.add_argument(
        "--config_file",
        required=False,
        help="An optional Amass config file. Otherwise, defaults will be used.",
    )
    arg_parser.add_argument(
        "--amass_path", required=True, help="The path to the amass binary"
    )
    arg_parser.add_argument(
        "--output_dir",
        default=output_dir,
        help="The local path where to save Amass files.",
    )
    arg_parser.add_argument(
        "--docker_output_dir",
        default=output_dir,
        help="The path within Docker where to save Amass files.",
    )
    arg_parser.add_argument(
        "--amass_version",
        type=int,
        default=3,
        help="The version of OWASP Amass being used.",
    )
    arg_parser.add_argument(
        "--amass_mode",
        required=False,
        type=str,
        default="local",
        choices=["local", "docker"],
        help="The version of OWASP Amass being used.",
    )
    arg_parser.add_argument(
        "--amass_timeout",
        required=False,
        type=str,
        help="The timeout value for the Amass command line",
    )
    arg_parser.add_argument(
        "--exclude_zones",
        required=False,
        type=str,
        default="",
        help="A comma delimited list of sub-strings used to exclude zones",
    )
    arg_parser.add_argument(
        "--exclude_regex",
        required=False,
        type=str,
        default="",
        help="Exclude a list of domains containing a substring",
    )
    arg_parser.add_argument(
        "--created_within_last",
        required=False,
        type=int,
        default=0,
        help="Only process zones created within the last x days",
    )
    arg_parser.add_argument(
        "--if_list",
        required=False,
        type=str,
        default="",
        help="The amass -if list of sources to include. Can't be used with -ef.",
    )
    arg_parser.add_argument(
        "--ef_list",
        required=False,
        type=str,
        default="",
        help="The amass -ef list of sources to exclude. Can't be used with -if.",
    )
    arg_parser.add_argument(
        "--sleep",
        type=int,
        default=5,
        help="Sleep time in seconds between amass runs so as not to overuse service limits.",
    )
    args = arg_parser.parse_args()

    if args.amass_mode == "local" and not os.path.isfile(args.amass_path):
        logger.error("Incorrect amass_path argument provided")
        exit(1)

    # In Docker mode, this would be relative to the Docker path and not the system path
    if (
        args.amass_mode == "local"
        and "config_file" in args
        and not os.path.isfile(args.config_file)
    ):
        logger.error("Incorrect config_file location")
        exit(1)

    if "output_dir" in args:
        output_dir = args.output_dir
        if not output_dir.endswith("/"):
            output_dir = output_dir + "/"

    # In Docker mode, this would be relative to the Docker path and not the system path
    if args.amass_mode == "local":
        check_save_location(output_dir)

    jobs_manager.record_job_start()

    if args.created_within_last > 0:
        zone_collection = mongo_connector.get_zone_connection()
        past_create_date = datetime.now() - timedelta(days=args.created_within_last)
        results = mongo_connector.perform_find(
            zone_collection, {"created": {"$gt": past_create_date}}
        )
        zones = []
        for entry in results:
            zones.append(entry["zone"])
    elif args.exclude_regex is not None and len(args.exclude_regex) > 0:
        exclude_re = re.compile(".*" + args.exclude_regex + ".*")
        zone_collection = mongo_connector.get_zone_connection()
        results = mongo_connector.perform_find(
            zone_collection,
            {
                "$and": [
                    {"zone": {"$not": exclude_re}},
                    {
                        "status": {
                            "$nin": [ZoneManager.FALSE_POSITIVE, ZoneManager.EXPIRED]
                        }
                    },
                ]
            },
        )
        zones = []
        for entry in results:
            zones.append(entry["zone"])
    else:
        zones = ZoneManager.get_distinct_zones(mongo_connector)

    # If the job died half way through, you can skip over domains that were already processed
    # when you restart the script.
    new_zones = []
    for zone in zones:
        if not os.path.isfile(output_dir + zone + "-do.json"):
            new_zones.append(zone)

    exclude_strings = args.exclude_zones.split()

    # If exclude_strings was specified, then remove any matching zones
    if len(exclude_strings) > 0:
        for zone in new_zones:
            for entry in exclude_strings:
                if entry in zone:
                    new_zones.remove(zone)

    # Recently updated zones
    # This helps reduce the number of redundant scans if you stop and restart
    all_dns_collection = mongo_connector.get_all_dns_connection()
    scrub_date = datetime.now() - timedelta(days=120, hours=9)
    recent_zones = mongo_connector.perform_distinct(
        all_dns_collection,
        "zone",
        {
            "sources.source": {"$regex": "amass:.*"},
            "sources.updated": {"$gt": scrub_date},
        },
    )
    for zone in recent_zones:
        if zone in new_zones:
            new_zones.remove(zone)

    logger.info("New Zones Length: " + str(len(new_zones)))

    for zone in new_zones:
        # Pace out calls to the Amass services
        time.sleep(args.sleep)

        if args.amass_mode == "local":
            command_line = []

            command_line.append(args.amass_path)
        else:
            command_line = args.amass_path.split()

        if int(args.amass_version) >= 3:
            command_line.append("enum")

        if args.config_file:
            command_line.append("-config")
            command_line.append(args.config_file)

        if args.amass_timeout:
            command_line.append("-timeout")
            command_line.append(args.amass_timeout)

        if args.if_list:
            command_line.append("-if")
            command_line.append(args.if_list)

        if args.ef_list:
            command_line.append("-ef")
            command_line.append(args.ef_list)

        command_line.append("-d")
        command_line.append(zone)
        command_line.append("-src")
        command_line.append("-ip")
        command_line.append("-nolocaldb")
        command_line.append("-json")
        command_line.append(args.docker_output_dir + zone + "-do.json")

        try:
            subprocess.check_call(command_line)
        except subprocess.CalledProcessError as e:
            # Even when there is an error, there will likely still be results.
            # We can continue with the data that was collected thus far.
            logger.warning("ERROR: Amass run exited with a non-zero status: " + str(e))

        if os.path.isfile(output_dir + zone + "-do.json"):
            output = open(output_dir + zone + "-do.json", "r")
            json_data = []
            for line in output:
                try:
                    json_data.append(json.loads(line))
                except:
                    logger.warning("Amass wrote an incomplete line: " + str(line))
            output.close()

            for finding in json_data:
                finding["timestamp"] = datetime.now()
                """
                Results from amass squash the cname records and only provides the final IPs.
                Therefore, we have to re-do the DNS lookup in download_from_remote_database.
                This collection is just a recording of the original results
                """
                mongo_connector.perform_insert(amass_collection, finding)

    # Clear old findings
    amass_collection.delete_many({"timestamp": {"$lt": now}})

    jobs_manager.record_job_complete()

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
