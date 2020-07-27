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
import subprocess
import time

from datetime import datetime
from dateutil import parser

from libs3 import DNSManager, JobsManager, MongoConnector
from libs3.ZoneManager import ZoneManager
from libs3.LoggingUtil import LoggingUtil


def is_tracked_zone(cname, zones):
    """
    Does the CNAME belong to a tracked zone?
    """
    for zone in zones:
        if cname.endswith("." + zone) or cname == zone:
            return True
    return False


def record_finding(dns_manager, finding):
    """
    Record a relevant line in the database.
    """
    new_record = {}
    new_record['zone'] = finding['domain']
    new_record['type'] = finding['type']

    if new_record['type'] == 'a' or new_record['type'] == 'aaaa':
        new_record['value'] = finding['addr']
    elif new_record['type'] == 'ns' or \
        new_record['type'] == 'cname' or \
        new_record['type'] == 'mx' or \
        new_record['type'] == 'ptr':
        new_record['value'] = finding['target_name']
    else:
        print("ERROR! Unrecognized type: " + finding['type'])
        return

    new_record['fqdn'] = finding['name']
    new_record['created'] = datetime.now()
    new_record['status'] = 'unknown'
    dns_manager.insert_record(new_record, "amass:" + finding['source'])


def check_save_location(save_location):
    """
    Check to see if the directory exists.
    If the directory does not exist, it will automatically create it.
    """
    if not os.path.exists(save_location):
        os.makedirs(save_location)


def main():
    """
    Begin main...
    """
    logger = LoggingUtil.create_log(__name__)

    mongo_connector = MongoConnector.MongoConnector()

    now = datetime.now()
    print("Starting: " + str(now))
    logger.info("Starting...")

    jobs_manager = JobsManager.JobsManager(mongo_connector, 'owasp_amass')

    zones = ZoneManager.get_distinct_zones(mongo_connector)
    dns_manager = DNSManager.DNSManager(mongo_connector)

    output_dir = "./amass_files/"

    arg_parser = argparse.ArgumentParser(description='Run the OWASP Amass tool and store the results in the database.')
    arg_parser.add_argument('--config_file', required=False, help='An optional Amass config file. Otherwise, defaults will be used.')
    arg_parser.add_argument('--amass_path', required=True, help='The path to the amass binary')
    arg_parser.add_argument('--output_dir', default=output_dir, help="The path where to save Amass files.")
    arg_parser.add_argument('--amass_version', type=int, default=3, help='The version of OWASP Amass being used.')
    arg_parser.add_argument('--sleep', type=int, default=5, help='Sleep time in seconds between amass runs so as not to overuse service limits.')
    args = arg_parser.parse_args()

    if not os.path.isfile(args.amass_path):
        logger.error("Incorrect amass_path argument provided")
        exit(1)

    if 'config_file' in args and not os.path.isfile(args.config_file):
        logger.error("Incorrect config_file location")
        exit(1)

    if 'output_dir' in args:
        output_dir = args.output_dir
        if not output_dir.endswith("/"):
            output_dir = output_dir + "/"

    check_save_location(output_dir)

    jobs_manager.record_job_start()

    # If the job died half way through, you can skip over domains that were already processed
    # when you restart the script.
    new_zones = []
    for zone in zones:
        if not os.path.isfile(output_dir + zone + "-do.json"):
            new_zones.append(zone)

    for zone in new_zones:
        # Pace out calls to the Amass services
        time.sleep(args.sleep)

        command_line = []

        command_line.append(args.amass_path)

        if int(args.amass_version) >= 3:
            command_line.append("enum")

        if args.config_file:
            command_line.append("-config")
            command_line.append(args.config_file)

        command_line.append("-d")
        command_line.append(zone)
        command_line.append("-src")
        command_line.append("-ip")
        command_line.append("-o")
        command_line.append(output_dir + zone + "-do.json")

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
                if 'type' in finding and finding['type'] == 'infrastructure' or finding['type'] == 'domain':
                    # Not currently recording
                    continue
                elif is_tracked_zone(finding['domain'], zones):
                    record_finding(dns_manager, finding)
                else:
                    # logger.debug("Skipping: " + finding['domain'] + " type: " + finding['type'])
                    pass

    jobs_manager.record_job_complete()

    now = datetime.now()
    print("Complete: " + str(now))
    logger.info("Complete.")


if __name__ == "__main__":
    main()
