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
This script will check AWS Route53 DNS services for a list of domain names.
The use of [:-1] is to remove the trailing dot that Route53 adds to its values.

In order to connect to Route53, boto3 needs credentials for the services. The possible methods for
providing credentials to the boto3 libary are detailed here:
https://boto3.amazonaws.com/v1/documentation/api/latest/guide/configuration.html#guide-configuration
"""

import copy
import logging
import time
from datetime import datetime

import boto3
from libs3 import DNSManager, JobsManager, MongoConnector, ZoneIngestor
from libs3.LoggingUtil import LoggingUtil
from libs3.ZoneManager import ZoneManager


def update_records(r53_client, dns_manager, zone_data, r53_source):
    """
    Update DNS records for the given zone_data
    """
    response = r53_client.list_resource_record_sets(HostedZoneId=zone_data["Id"])
    while response != {}:
        for record in response["ResourceRecordSets"]:
            new_entry = {}
            new_entry["fqdn"] = record["Name"][:-1]
            new_entry["zone"] = zone_data["Name"][:-1]
            new_entry["type"] = record["Type"].lower()
            new_entry["created"] = datetime.now()
            new_entry["status"] = "confirmed"
            for entry in record["ResourceRecords"]:
                temp_value = copy.deepcopy(new_entry)
                temp_value["value"] = entry["Value"]
                dns_manager.insert_record(temp_value, r53_source)

        if response["IsTruncated"] == False:
            response = {}
        else:
            response = r53_client.list_resource_record_sets(
                HostedZoneId=zone_data["Id"],
                NextRecordName=response["NextRecordName"],
                NextRecordType=response["NextRecordType"],
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

    mongo_connector = MongoConnector.MongoConnector()
    dns_manager = DNSManager.DNSManager(mongo_connector)
    zone_ingestor = ZoneIngestor.ZoneIngestor()

    jobs_manager = JobsManager.JobsManager(mongo_connector, "get_route53")
    jobs_manager.record_job_start()

    current_zones = ZoneManager.get_distinct_zones(mongo_connector)

    # For cases with multiple R53 accounts, include the account id for reference
    sts = boto3.client("sts")
    account_id = sts.get_caller_identity()["Arn"].split(":")[4]
    r53_source = "R53:" + str(account_id)

    r53_client = boto3.client("route53")

    r53_domains = r53_client.list_hosted_zones()
    r53_zone_list = []
    while r53_domains != {}:
        for zone_data in r53_domains["HostedZones"]:
            # Only add public zones
            if zone_data["Config"]["PrivateZone"] == False:
                r53_zone_list.append(zone_data)

        if r53_domains["IsTruncated"] == True:
            r53_domains = r53_client.list_domains(Marker=r53_domains["NextMarker"])
        else:
            r53_domains = {}

    for zone_data in r53_zone_list:
        # Double check that this is not a new zone
        zone_name = zone_data["Name"][:-1]
        if zone_name not in current_zones:
            logger.info("Creating zone: " + zone_name)
            zone_ingestor.add_zone(zone_data["Name"], r53_source)

        # Add hosts to the zone
        update_records(r53_client, dns_manager, zone_data, r53_source)

    # Record status
    jobs_manager.record_job_complete()

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
