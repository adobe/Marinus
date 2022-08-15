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
This script downloads updates from the remote MongoDB server that is used for larger jobs.
This script is only necessary if a remote MongoDB is set up.

This script can be run daily.
"""

import logging
import time
from datetime import datetime, timedelta

from libs3 import (
    DNSManager,
    GoogleDNS,
    JobsManager,
    MongoConnector,
    RemoteMongoConnector,
)
from libs3.LoggingUtil import LoggingUtil
from libs3.ZoneManager import ZoneManager


def download_censys_scan_info(logger, censys_collection, remote_censys_collection):
    """
    Download the latest censys scan information
    """
    logger.info("Beginning Censys inserts...")

    # Grab the new results from the remote server.
    results = remote_censys_collection.find({}, {"_id": 0})

    # Remove the previous results from the local Censys collection
    censys_collection.delete_many({})

    # Insert the new results from the remote server into the local server
    for result in results:
        censys_collection.insert_one(result)

    # Since the database is copied, we can clear the remote database.
    remote_censys_collection.delete_many({})


def download_zgrab_info(logger, zgrab_data_collection, remote_zgrab_data_collection):
    """
    Download the latest zgrab IP scan information.
    """
    # Grab more than 24 hours back to reduce risk of time diff bugs
    yesterday = datetime.now() - timedelta(days=1, hours=9)

    # Grab the new results from the remote server.
    ip_results = remote_zgrab_data_collection.find(
        {"domain": "<nil>", "timestamp": {"$gte": yesterday}}, {"_id": 0}
    ).batch_size(50)

    # Insert the new results from the remote server into the local server
    logger.info("Beginning ZGrab IP inserts...")
    for result in ip_results:
        zgrab_data_collection.replace_one({"ip": result["ip"]}, result, upsert=True)

    # Grab the new results from the remote server.
    domain_results = remote_zgrab_data_collection.find(
        {"ip": "<nil>", "timestamp": {"$gte": yesterday}}, {"_id": 0}
    ).batch_size(50)

    # Insert the new results from the remote server into the local server
    logger.info("Beginning ZGrab domain inserts...")
    for result in domain_results:
        zgrab_data_collection.replace_one(
            {"domain": result["domain"]}, result, upsert=True
        )

    # Remove results that are over four weeks old.
    # Four weeks is used to provide time in the event of a bug
    one_month_ago = datetime.now() - timedelta(days=30, hours=9)
    remote_zgrab_data_collection.delete_many({"timestamp": {"$lte": one_month_ago}})
    zgrab_data_collection.delete_many({"timestamp": {"$lte": one_month_ago}})


def download_zgrab_port_info(
    logger, zgrab_data_collection, remote_zgrab_data_collection
):
    """
    Download the latest zgrab IP scan information.
    """
    # Grab more than 24 hours back to reduce risk of time diff bugs
    yesterday = datetime.now() - timedelta(days=1, hours=9)

    # Grab the new results from the remote server.
    ip_results = remote_zgrab_data_collection.find(
        {"timestamp": {"$gte": yesterday}}, {"_id": 0}
    ).batch_size(50)

    # Insert the new results from the remote server into the local server
    logger.info("Beginning ZGrab port inserts...")
    for result in ip_results:
        zgrab_data_collection.replace_one({"ip": result["ip"]}, result, upsert=True)

    # Remove results that are over four weeks old.
    # Four weeks is used to provide time in the event of a bug
    one_month_ago = datetime.now() - timedelta(days=30, hours=9)
    remote_zgrab_data_collection.delete_many({"timestamp": {"$lte": one_month_ago}})
    zgrab_data_collection.delete_many({"timestamp": {"$lte": one_month_ago}})


def download_whois_data(logger, whois_collection, remote_whois_collection):
    """
    Download the latest whois information.
    """
    logger.info("Beginning Whois download")
    whois_results = remote_whois_collection.find({}, {"_id": 0}).batch_size(50)

    for result in whois_results:
        whois_collection.replace_one({"zone": result["zone"]}, result, upsert=True)

    # Establish a date four months back
    scrub_date = datetime.now() - timedelta(days=120, hours=9)

    # Remove data from four months back
    whois_collection.delete_many({"updated": {"$lte": scrub_date}})


def check_zones(domain, zones):
    """
    Check if the provided domain exists within the zone
    """
    for zone in zones:
        if domain == zone or domain.endswith("." + zone):
            return zone
    return None


def record_finding(logger, dns_manager, google_dns, zone, finding):
    """
    Results from amass squash the cname records and only provides the final IPs.
    Therefore, we have to re-do the DNS lookup to get the complete chain.
    """
    results = google_dns.fetch_DNS_records(finding["name"])

    inserted = False

    for result in results:
        if result["fqdn"].endswith("." + zone) or result["fqdn"] == zone:
            logger.debug("Inserting: " + finding["name"])
            result["created"] = datetime.now()
            result["status"] = "confirmed"
            result["zone"] = zone
            dns_manager.insert_record(result, "amass:" + finding["sources"][0])
            inserted = True

    return inserted


def download_amass_data(
    logger, amass_collection, remote_amass_collection, dns_manager, zones
):
    """
    Download the latest OWASP Amass information.
    """
    logger.info("Beginning Amass download")
    now = datetime.now()
    mirror_date = datetime.now() - timedelta(days=7, hours=9)
    amass_results = remote_amass_collection.find(
        {"timestamp": {"$gt": mirror_date}}, {"_id": 0}
    ).batch_size(50)

    google_dns = GoogleDNS.GoogleDNS()

    for result in amass_results:
        zone = check_zones(result["name"], zones)
        if zone is not None:
            time.sleep(1)
            if record_finding(logger, dns_manager, google_dns, zone, result):
                amass_collection.replace_one(
                    {"name": result["name"]}, result, upsert=True
                )

    # Establish a date four months back
    scrub_date = datetime.now() - timedelta(days=120, hours=9)

    # Remove data from scrub_date
    amass_collection.delete_many({"timestamp": {"$lte": scrub_date}})
    remote_amass_collection.delete_many({"timestamp": {"$lte": now}})


def download_jobs_status(logger, jobs_collection, remote_jobs_collection):
    """
    Download the latest whois information.
    """
    logger.info("Beginning Jobs status download")
    jobs_results = remote_jobs_collection.find({}, {"_id": 0})

    for result in jobs_results:
        jobs_collection.replace_one(
            {"job_name": result["job_name"]}, result, upsert=True
        )


def download_sonar_dns(logger, dns_manager, remote_mongo_connector):
    """
    The remote sonar_dns_colllection is temporary storage for the remote Sonar scripts
    """
    logger.info("Beginning Sonar DNS Download")

    # Calculate jobs
    scrub_date = datetime.now() - timedelta(days=2, hours=9)

    remote_sonar_dns_collection = remote_mongo_connector.get_sonar_data_dns()

    # Get all dns records where
    results = remote_sonar_dns_collection.find(
        {"updated": {"$gt": scrub_date}}, {"_id": 0, "sources": 0}
    ).batch_size(10)

    for result in results:
        new_record = {}
        new_record["zone"] = result["zone"]
        new_record["fqdn"] = result["fqdn"]
        new_record["status"] = result["status"]
        new_record["type"] = result["type"]
        new_record["value"] = result["value"]
        new_record["sonar_timestamp"] = result["sonar_timestamp"]
        new_record["created"] = result["created"]
        new_record["updated"] = result["updated"]
        dns_manager.insert_record(new_record, "sonar_dns")

    # Delete all DNS records not updated within 60 days?
    scrub_date = datetime.now() - timedelta(days=60, hours=9)
    remote_sonar_dns_collection.delete_many({"updated": {"$lt": scrub_date}})


def download_sonar_rdns(logger, mongo_connector, remote_mongo_connector):
    """
    The remote sonar_rdns_colllection is temporary storage for the remote Sonar scripts
    """
    logger.info("Beginning Sonar RDNS Download")

    # Calculate jobs
    scrub_date = datetime.now() - timedelta(days=2, hours=9)

    remote_sonar_rdns_collection = (
        remote_mongo_connector.get_sonar_reverse_dns_connection()
    )
    rdns_collection = mongo_connector.get_sonar_reverse_dns_connection()

    # Get all dns records where
    results = remote_mongo_connector.perform_find(
        remote_sonar_rdns_collection, {"updated": {"$gt": scrub_date}}, {"_id": 0}
    ).batch_size(50)

    for result in results:
        count = mongo_connector.perform_count(rdns_collection, {"ip": result["ip"]})

        if count == 0:
            mongo_connector.perform_insert(rdns_collection, result)
        else:
            rdns_collection.update_one(
                {"ip": result["ip"]},
                {"$set": {"fqdn": result["fqdn"]}, "$currentDate": {"updated": True}},
            )

    # Delete all DNS records not updated within 60 days?
    scrub_date = datetime.now() - timedelta(days=60, hours=9)
    remote_sonar_rdns_collection.delete_many({"updated": {"$lt": scrub_date}})


def main(logger=None):
    """
    Begin Main...
    """
    if logger is None:
        logger = LoggingUtil.create_log(__name__)

    now = datetime.now()
    print("Starting: " + str(now))
    logger.info("Starting...")

    # Connect to the remote databases
    mongo_connector = MongoConnector.MongoConnector()
    rm_connector = RemoteMongoConnector.RemoteMongoConnector()
    dns_manager = DNSManager.DNSManager(mongo_connector)
    zones = ZoneManager.get_distinct_zones(mongo_connector)

    jobs_manager = JobsManager.JobsManager(mongo_connector, "remote_download")
    jobs_manager.record_job_start()

    remote_jobs_collection = rm_connector.get_jobs_connection()

    # Check the status of the Censys job on the remote database
    try:
        status = remote_jobs_collection.find_one({"job_name": "censys"})
    except:
        logger.error("Can not connect to remote database")
        jobs_manager.record_job_error()
        exit(1)

    if (
        status is not None
        and "status" in status
        and status["status"] != jobs_manager.COMPLETE
    ):
        logger.info("Censys scans status is not COMPLETE")
    elif (
        status is not None
        and "status" in status
        and status["status"] == jobs_manager.COMPLETE
    ):
        # Get connections to the relevant collections.
        censys_collection = mongo_connector.get_zgrab_443_data_connection()
        remote_censys_collection = rm_connector.get_zgrab_443_data_connection()

        download_censys_scan_info(logger, censys_collection, remote_censys_collection)

        # Tell the remote database that is safe to start processing the next Censys file
        remote_jobs_collection.update_one(
            {"job_name": "censys"},
            {"$currentDate": {"updated": True}, "$set": {"status": jobs_manager.READY}},
        )

    # Get connections to the relevant HTTPS collections.
    zgrab_443_data_collection = mongo_connector.get_zgrab_443_data_connection()
    remote_zgrab_443_data_collection = rm_connector.get_zgrab_443_data_connection()

    download_zgrab_info(
        logger, zgrab_443_data_collection, remote_zgrab_443_data_collection
    )

    # Get connections to the relevant HTTP collections.
    zgrab_80_data_collection = mongo_connector.get_zgrab_80_data_connection()
    remote_zgrab_80_data_collection = rm_connector.get_zgrab_80_data_connection()

    download_zgrab_info(
        logger, zgrab_80_data_collection, remote_zgrab_80_data_collection
    )

    # Get connections to the relevant port collections.
    zgrab_port_data_collection = mongo_connector.get_zgrab_port_data_connection()
    remote_zgrab_port_data_collection = rm_connector.get_zgrab_port_data_connection()

    download_zgrab_port_info(
        logger, zgrab_port_data_collection, remote_zgrab_port_data_collection
    )

    # Download latest whois information
    status = remote_jobs_collection.find_one({"job_name": "whois_lookups"})
    if status["status"] == jobs_manager.COMPLETE:
        whois_collection = mongo_connector.get_whois_connection()
        remote_whois_collection = rm_connector.get_whois_connection()
        download_whois_data(logger, whois_collection, remote_whois_collection)
        remote_jobs_collection.update_one(
            {"job_name": "whois"}, {"$set": {"status": jobs_manager.READY}}
        )

    # Download Amass results
    amass_collection = mongo_connector.get_owasp_amass_connection()
    remote_amass_collection = rm_connector.get_owasp_amass_connection()
    download_amass_data(
        logger, amass_collection, remote_amass_collection, dns_manager, zones
    )

    # Download the status of the remote jobs
    download_jobs_status(logger, jobs_manager._jobs_collection, remote_jobs_collection)

    # Download remote sonar DNS findings
    # download_sonar_dns(logger, dns_manager, rm_connector)

    # Download remote sonar RDNS findings
    # download_sonar_rdns(logger, mongo_connector, rm_connector)

    # Update the local jobs database to done
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
