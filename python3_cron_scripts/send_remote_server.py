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
A traditional remote cloud environment was created because some of the data sets are
so large that they required a cloud with TBs of data storage.

The scripts in the remote cloud environnment needed a local copy of the Marinus database
so that they knew what to look for in the data.

This script mirrors the necessary data to the remote cloud environment's MongoDB instance.
It does not create a full replica because that is unnecessary.

This script is only necessary if a remote MongoDB is deployed.
"""

import argparse
import logging
import sys
from datetime import datetime, timedelta

from libs3 import JobsManager, MongoConnector, RemoteMongoConnector
from libs3.LoggingUtil import LoggingUtil


def update_zones(logger, mongo_connector, rm_connector, update_zone_list):
    """
    Copy all the currently known FLDs to the remote database.
    """
    logger.info("Starting Zones..")
    zones_collection = mongo_connector.get_zone_connection()
    remote_zones_collection = rm_connector.get_zone_connection()

    zones = zones_collection.find({}, {"_id": 0})
    zone_list = []

    if update_zone_list:
        remote_zones_collection.delete_many({})
        for zone in zones:
            remote_zones_collection.insert_one(zone)
            zone_list.append(zone["zone"])
    else:
        for zone in zones:
            zone_list.append(zone["zone"])

    return zone_list


def update_ip_zones(logger, mongo_connector, rm_connector):
    """
    Copy all of the currently known CIDRs to the remote database.
    """
    logger.info("Starting IPZones..")
    ipzones_collection = mongo_connector.get_ipzone_connection()
    remote_ipzones_collection = rm_connector.get_ipzone_connection()

    ipzones = ipzones_collection.find({}, {"_id": 0})

    remote_ipzones_collection.delete_many({})
    for zone in ipzones:
        remote_ipzones_collection.insert_one(zone)

    ipv6_zones_collection = mongo_connector.get_ipv6_zone_connection()
    remote_ipv6_zones_collection = rm_connector.get_ipv6_zone_connection()

    ipv6_zones = ipv6_zones_collection.find({}, {"_id": 0})

    remote_ipv6_zones_collection.delete_many({})
    for zone in ipv6_zones:
        remote_ipv6_zones_collection.insert_one(zone)


def update_config(logger, mongo_connector, rm_connector):
    """
    Copy the config data to the remote database
    """
    logger.info("Starting Config..")
    config_collection = mongo_connector.get_config_connection()
    remote_config_collection = rm_connector.get_config_connection()

    configs = config_collection.find({}, {"_id": 0})

    remote_config_collection.delete_many({})
    for config in configs:
        remote_config_collection.insert_one(config)


def update_aws_cidrs(logger, mongo_connector, rm_connector):
    """
    Copy the list of AWS CIDRs to the remote database
    """
    logger.info("Starting AWS CIDRs..")
    aws_ips_collection = mongo_connector.get_aws_ips_connection()
    remote_aws_ips_collection = rm_connector.get_aws_ips_connection()

    aws_ips = aws_ips_collection.find({}, {"_id": 0})

    remote_aws_ips_collection.delete_many({})
    for ip_addr in aws_ips:
        remote_aws_ips_collection.insert_one(ip_addr)


def update_azure_cidrs(logger, mongo_connector, rm_connector):
    """
    Copy the list of Azure CIDRs to the remote database
    """
    logger.info("Starting Azure IPs..")
    azure_ips_collection = mongo_connector.get_azure_ips_connection()
    remote_azure_ips_collection = rm_connector.get_azure_ips_connection()

    azure_ips = azure_ips_collection.find({}, {"_id": 0})

    remote_azure_ips_collection.delete_many({})
    for ip_addr in azure_ips:
        remote_azure_ips_collection.insert_one(ip_addr)


def update_akamai_cidrs(logger, mongo_connector, rm_connector):
    """
    Copy the list of Akamai CIDRs to the remote database
    """
    logger.info("Starting Akamai IPs..")
    akamai_ips_collection = mongo_connector.get_akamai_ips_connection()
    remote_akamai_ips_collection = rm_connector.get_akamai_ips_connection()

    akamai_ips = akamai_ips_collection.find({}, {"_id": 0})

    remote_akamai_ips_collection.delete_many({})
    for ip_addr in akamai_ips:
        remote_akamai_ips_collection.insert_one(ip_addr)


def update_gcp_cidrs(logger, mongo_connector, rm_connector):
    """
    Copy the list of GCP CIDRs to the remote database
    """
    logger.info("Starting GCP IPs..")
    gcp_ips_collection = mongo_connector.get_gcp_ips_connection()
    remote_gcp_ips_collection = rm_connector.get_gcp_ips_connection()

    gcp_ips = gcp_ips_collection.find({}, {"_id": 0})

    remote_gcp_ips_collection.delete_many({})
    for ip_addr in gcp_ips:
        remote_gcp_ips_collection.insert_one(ip_addr)


def update_all_dns(logger, mongo_connector, rm_connector, zone_list):
    """
    Update the entire collection by deleting all previous records before
    inserting new records.

    Performing a zone by zone upload to minimize the chances of the zgrab script
    pulling a zone at the same time it is being deleted.
    """
    logger.info("Starting All DNS..")
    all_dns_collection = mongo_connector.get_all_dns_connection()
    remote_all_dns_collection = rm_connector.get_all_dns_connection()

    for zone in zone_list:
        all_dns = all_dns_collection.find({"zone": zone}, {"_id": 0}).batch_size(50)

        remote_all_dns_collection.delete_many({"zone": zone})
        for ip_addr in all_dns:
            remote_all_dns_collection.insert_one(ip_addr)


def update_all_dns_diff_mode(
    logger, mongo_connector, rm_connector, zone_list, date_diff
):
    """
    Only update the origial records if the number of records has changed or if there
    has been a recent update to the zone.

    Performing a zone by zone upload to minimize the chances of the zgrab script
    pulling a zone at the same time it is being deleted.
    """
    logger.info("Starting All DNS diff mode..")
    all_dns_collection = mongo_connector.get_all_dns_connection()
    remote_all_dns_collection = rm_connector.get_all_dns_connection()

    for zone in zone_list:
        all_dns_count = mongo_connector.perform_count(
            all_dns_collection, {"zone": zone}
        )
        remote_dns_count = rm_connector.perform_count(
            remote_all_dns_collection, {"zone": zone}
        )

        # Perform a full update
        if all_dns_count != remote_dns_count:
            logger.info("Performing a full update for zone: " + str(zone))
            all_dns = all_dns_collection.find({"zone": zone}, {"_id": 0}).batch_size(50)

            remote_all_dns_collection.delete_many({"zone": zone})
            for ip_addr in all_dns:
                rm_connector.perform_insert(remote_all_dns_collection, ip_addr)
        else:
            update_date = datetime.now() - timedelta(days=date_diff)
            new_entries = all_dns_collection.find(
                {"zone": zone, "updated": {"$gt": update_date}}, {"_id": 0}
            ).batch_size(50)

            i = 0
            for entry in new_entries:
                remote_all_dns_collection.delete_one({"fqdn": entry["fqdn"]})
                rm_connector.perform_insert(remote_all_dns_collection, entry)
                i = i + 1

            logger.info(
                "Performed a partial update for zone: "
                + str(zone)
                + " with "
                + str(i)
                + " records"
            )


def main(logger=None):
    """
    Begin Main...
    """
    if logger is None:
        logger = LoggingUtil.create_log(__name__)

    now = datetime.now()
    print("Starting: " + str(now))
    logger.info("Starting...")

    parser = argparse.ArgumentParser(
        description="Send specific collections to the remote MongoDB. If no arguments are provided, then all data is mirrored."
    )
    parser.add_argument(
        "--send_zones", action="store_true", required=False, help="Send IP zones"
    )
    parser.add_argument(
        "--send_ip_zones", action="store_true", required=False, help="Send IP zones"
    )
    parser.add_argument(
        "--send_third_party_zones",
        action="store_true",
        required=False,
        help="Send AWS, Azure, etc.",
    )
    parser.add_argument(
        "--send_config", action="store_true", required=False, help="Send configs"
    )
    parser.add_argument(
        "--send_dns_records",
        action="store_true",
        required=False,
        help="Replace all DNS records",
    )
    parser.add_argument(
        "--send_dns_diff",
        action="store_true",
        required=False,
        help="Send new DNS records",
    )
    parser.add_argument(
        "--send_all",
        action="store_true",
        required=False,
        help="Send all records",
    )
    parser.add_argument(
        "--date_diff",
        default=2,
        type=int,
        help="The number of days used for identifying new records in send_dns_diff",
    )
    args = parser.parse_args()

    send_all = False
    if len(sys.argv) == 1 or args.send_all:
        send_all = True

    mongo_connector = MongoConnector.MongoConnector()
    remote_mongo_connector = RemoteMongoConnector.RemoteMongoConnector()

    jobs_manager = JobsManager.JobsManager(mongo_connector, "send_remote_server")
    jobs_manager.record_job_start()

    if send_all or args.send_zones:
        try:
            zone_list = update_zones(
                logger, mongo_connector, remote_mongo_connector, True
            )
        except:
            logger.error(
                "Could not communicate with the remote database when sending zones"
            )
            jobs_manager.record_job_error()
            exit(1)
    else:
        zone_list = update_zones(logger, mongo_connector, remote_mongo_connector, False)

    if send_all or args.send_ip_zones:
        try:
            update_ip_zones(logger, mongo_connector, remote_mongo_connector)
        except:
            logger.error(
                "Could not communicate with the remote database when sending IP zones"
            )
            jobs_manager.record_job_error()
            exit(1)

    if send_all or args.send_third_party_zones:
        try:
            update_aws_cidrs(logger, mongo_connector, remote_mongo_connector)
            update_azure_cidrs(logger, mongo_connector, remote_mongo_connector)
            update_akamai_cidrs(logger, mongo_connector, remote_mongo_connector)
            update_gcp_cidrs(logger, mongo_connector, remote_mongo_connector)
        except:
            logger.error(
                "Could not communicate with the remote database when sending third-party zones"
            )
            jobs_manager.record_job_error()
            exit(1)

    if send_all or args.send_config:
        try:
            update_config(logger, mongo_connector, remote_mongo_connector)
        except:
            logger.error(
                "Could not communicate with the remote database when sending config data"
            )
            jobs_manager.record_job_error()
            exit(1)

    # Resend the entire DNS collection
    if args.send_dns_records is not False:
        try:
            update_all_dns(logger, mongo_connector, remote_mongo_connector, zone_list)
        except:
            logger.error(
                "Could not communicate with the remote database when sending DNS records"
            )
            jobs_manager.record_job_error()
            exit(1)

    # Only send DNS records that have recently changed.
    if send_all or args.send_dns_diff:
        try:
            update_all_dns_diff_mode(
                logger,
                mongo_connector,
                remote_mongo_connector,
                zone_list,
                args.date_diff,
            )
        except:
            logger.error(
                "Could not communicate with the remote database when sending DNS diff records"
            )
            jobs_manager.record_job_error()
            exit(1)

    # Record status
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
