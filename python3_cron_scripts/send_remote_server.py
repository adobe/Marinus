#!/usr/bin/python3

# Copyright 2018 Adobe. All rights reserved.
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
too large to process within the corporate network.

The scripts in the remote cloud environnment needed a local copy of the Marinus database
so that they knew what to look for in the data.

This script mirrors the necessary data to the remote cloud environment's MongoDB instance.
It does not create a full replica because that is unnecessary.

This script is only necessary if a remote MongoDB is deployed.
"""

from datetime import datetime

from libs3 import MongoConnector, RemoteMongoConnector


def update_zones(mongo_connector, rm_connector):
    """
    Copy all the currently known FLDs to the remote database.
    """
    print("Starting Zones..")
    zones_collection = mongo_connector.get_zone_connection()
    remote_zones_collection = rm_connector.get_zone_connection()

    zones = zones_collection.find({}, {"_id": 0})
    zone_list = []

    remote_zones_collection.remove({})
    for zone in zones:
        remote_zones_collection.insert(zone)
        zone_list.append(zone['zone'])

    return (zone_list)


def update_ip_zones(mongo_connector, rm_connector):
    """
    Copy all of the currently known CIDRs to the remote database.
    """
    print("Starting IPZones..")
    ipzones_collection = mongo_connector.get_ipzone_connection()
    remote_ipzones_collection = rm_connector.get_ipzone_connection()

    ipzones = ipzones_collection.find({}, {"_id": 0})

    remote_ipzones_collection.remove({})
    for zone in ipzones:
        remote_ipzones_collection.insert(zone)


def update_config(mongo_connector, rm_connector):
    """
    Copy the config data to the remote database
    """
    print("Starting Config..")
    config_collection = mongo_connector.get_config_connection()
    remote_config_collection = rm_connector.get_config_connection()

    configs = config_collection.find({}, {"_id": 0})

    remote_config_collection.remove({})
    for config in configs:
        remote_config_collection.insert(config)


def update_braas(mongo_connector, rm_connector):
    """
    Copy all of the public Braas IP addresses to the remote database.
    """
    print("Starting Public Braas..")
    braas_public_collection = mongo_connector.get_braas_public_connection()
    remote_braas_public_collection = rm_connector.get_braas_public_connection()

    braas_public = braas_public_collection.find({}, {"_id": 0})

    remote_braas_public_collection.remove({})
    for ip_addr in braas_public:
        remote_braas_public_collection.insert(ip_addr)


def update_aws_cidrs(mongo_connector, rm_connector):
    """
    Copy the list of AWS CIDRs to the remote database
    """
    print("Starting AWS CIDRs..")
    aws_ips_collection = mongo_connector.get_aws_ips_connection()
    remote_aws_ips_collection = rm_connector.get_aws_ips_connection()

    aws_ips = aws_ips_collection.find({}, {"_id": 0})

    remote_aws_ips_collection.remove({})
    for ip_addr in aws_ips:
        remote_aws_ips_collection.insert(ip_addr)


def update_azure_cidrs(mongo_connector, rm_connector):
    """
    Copy the list of Azure CIDRs to the remote database
    """
    print("Starting Azure IPs..")
    azure_ips_collection = mongo_connector.get_azure_ips_connection()
    remote_azure_ips_collection = rm_connector.get_azure_ips_connection()

    azure_ips = azure_ips_collection.find({}, {"_id": 0})

    remote_azure_ips_collection.remove({})
    for ip_addr in azure_ips:
        remote_azure_ips_collection.insert(ip_addr)


def update_all_dns(mongo_connector, rm_connector, zone_list):
    """
    Performing a zone by zone upload to minimize the chances of the zgrab script
    pulling a zone at the same time it is being deleted.
    """
    print("Starting All DNS..")
    all_dns_collection = mongo_connector.get_all_dns_connection()
    remote_all_dns_collection = rm_connector.get_all_dns_connection()

    for zone in zone_list:
        all_dns = all_dns_collection.find({'zone': zone}, {"_id": 0})

        remote_all_dns_collection.remove({'zone': zone})
        for ip_addr in all_dns:
            remote_all_dns_collection.insert(ip_addr)


def main():
    """
    Begin Main...
    """
    now = datetime.now()
    print("Starting: " + str(now))

    mongo_connector = MongoConnector.MongoConnector()
    remote_mongo_connector = RemoteMongoConnector.RemoteMongoConnector()

    jobs_collection = mongo_connector.get_jobs_connection()

    zone_list = update_zones(mongo_connector, remote_mongo_connector)
    update_ip_zones(mongo_connector, remote_mongo_connector)
    update_aws_cidrs(mongo_connector, remote_mongo_connector)
    update_azure_cidrs(mongo_connector, remote_mongo_connector)
    update_config(mongo_connector, remote_mongo_connector)
    update_braas(mongo_connector, remote_mongo_connector)
    update_all_dns(mongo_connector, remote_mongo_connector, zone_list)

    # Record status
    jobs_collection.update_one({'job_name': 'send_remote_server'},
                               {'$currentDate': {"updated": True},
                                "$set": {'status': 'COMPLETE'}})


    now = datetime.now()
    print ("Complete: " + str(now))

if __name__ == "__main__":
    main()
