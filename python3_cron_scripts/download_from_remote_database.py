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
This script downloads updates from the remote MongoDB server that is used for larger jobs.
This script is only necessary if a remote MongoDB is set up.

This script can be run daily.
"""

import logging

from datetime import datetime, timedelta
from libs3 import MongoConnector, RemoteMongoConnector, JobsManager
from libs3.LoggingUtil import LoggingUtil

# Connect to the remote databases
mongo_connector = MongoConnector.MongoConnector()
rm_connector = RemoteMongoConnector.RemoteMongoConnector()


def download_censys_scan_info(censys_collection, remote_censys_collection):
    """
    Download the latest censys scan information
    """
    # Grab the new results from the remote server.
    results = remote_censys_collection.find({}, {"_id": 0})


    # Remove the previous results from the local Censys collection
    censys_collection.remove({})


    # Insert the new results from the remote server into the local server
    for result in results:
        censys_collection.insert(result)


    # Since the database is copied, we can clear the remote database.
    remote_censys_collection.remove({})


def download_zgrab_info(logger, zgrab_data_collection, remote_zgrab_data_collection):
    """
    Download the latest zgrab IP scan information.
    """
    # Grab more than 24 hours back to reduce risk of time diff bugs
    yesterday = datetime.now() - timedelta(days=1, hours=1)

    # Grab the new results from the remote server.
    ip_results = remote_zgrab_data_collection.find({'domain': "<nil>", 'timestamp': {"$gte": yesterday}}, {"_id": 0})

    # Insert the new results from the remote server into the local server
    logger.info("Beginning ZGrab IP inserts...")
    for result in ip_results:
        zgrab_data_collection.replace_one({'ip':result['ip']}, result, upsert=True)

    # Grab the new results from the remote server.
    domain_results = remote_zgrab_data_collection.find({'ip': "<nil>", 'timestamp': {"$gte": yesterday}}, {"_id": 0})

    # Insert the new results from the remote server into the local server
    logger.info("Beginning ZGrab domain inserts...")
    for result in domain_results:
        zgrab_data_collection.replace_one({'domain':result['domain']}, result, upsert=True)

    # Remove results that are over four weeks old.
    # Four weeks is used to provide time in the event of a bug
    one_month_ago = datetime.now() - timedelta(days=30, hours=1)
    remote_zgrab_data_collection.remove({'timestamp': {"$lte": one_month_ago}})
    zgrab_data_collection.remove({'timestamp': {"$lte": one_month_ago}})


def download_zgrab_port_info(logger, zgrab_data_collection, remote_zgrab_data_collection):
    """
    Download the latest zgrab IP scan information.
    """
    # Grab more than 24 hours back to reduce risk of time diff bugs
    yesterday = datetime.now() - timedelta(days=1, hours=1)

    # Grab the new results from the remote server.
    ip_results = remote_zgrab_data_collection.find({'timestamp': {"$gte": yesterday}}, {"_id": 0})

    # Insert the new results from the remote server into the local server
    logger.info("Beginning ZGrab port inserts...")
    for result in ip_results:
        zgrab_data_collection.replace_one({'ip':result['ip']}, result, upsert=True)

    # Remove results that are over four weeks old.
    # Four weeks is used to provide time in the event of a bug
    one_month_ago = datetime.now() - timedelta(days=30, hours=1)
    remote_zgrab_data_collection.remove({'timestamp': {"$lte": one_month_ago}})
    zgrab_data_collection.remove({'timestamp': {"$lte": one_month_ago}})


def download_whois_data(logger, whois_collection, remote_whois_collection):
    """
    Download the latest whois information.
    """
    logger.info("Beginning Whois download")
    whois_results = remote_whois_collection.find({}, {"_id": 0})

    for result in whois_results:
        whois_collection.replace_one({'zone': result['zone']}, result, upsert=True)

    # Establish a date four months back
    scrub_date = datetime.now() - timedelta(days=120, hours=1)

    # Remove data from four months back
    whois_collection.remove({'updated': {"$lte": scrub_date}})


def download_jobs_status(logger, jobs_collection, remote_jobs_collection):
    """
    Download the latest whois information.
    """
    logger.info("Beginning Jobs status download")
    jobs_results = remote_jobs_collection.find({}, {"_id": 0})

    for result in jobs_results:
        jobs_collection.replace_one({'job_name': result['job_name']}, result, upsert=True)


def main():
    """
    Begin Main...
    """
    logger = LoggingUtil.create_log(__name__)

    now = datetime.now()
    print("Starting: " + str(now))
    logger.info("Starting...")

    jobs_manager = JobsManager.JobsManager(mongo_connector, 'remote_download')
    jobs_manager.record_job_start()

    remote_jobs_collection = rm_connector.get_jobs_connection()

    # Check the status of the Censys job on the remote database
    status = remote_jobs_collection.find_one({'job_name': 'censys'})
    if status is not None and 'status' in status and status['status'] != jobs_manager.COMPLETE:
        logger.info("Censys scans status is not COMPLETE")
    elif status is not None and 'status' in status and status['status'] == jobs_manager.COMPLETE:
        # Get connections to the relevant collections.
        censys_collection = mongo_connector.get_zgrab_443_data_connection()
        remote_censys_collection = rm_connector.get_zgrab_443_data_connection()

        download_censys_scan_info(censys_collection, remote_censys_collection)

        # Tell the remote database that is safe to start processing the next Censys file
        remote_jobs_collection.update_one({'job_name': 'censys'},
                                          {'$currentDate': {"updated" : True},
                                           "$set": {'status': jobs_manager.READY}})

    # Get connections to the relevant HTTPS collections.
    zgrab_443_data_collection = mongo_connector.get_zgrab_443_data_connection()
    remote_zgrab_443_data_collection = rm_connector.get_zgrab_443_data_connection()

    download_zgrab_info(logger, zgrab_443_data_collection, remote_zgrab_443_data_collection)

    # Get connections to the relevant HTTP collections.
    zgrab_80_data_collection = mongo_connector.get_zgrab_80_data_connection()
    remote_zgrab_80_data_collection = rm_connector.get_zgrab_80_data_connection()

    download_zgrab_info(logger, zgrab_80_data_collection, remote_zgrab_80_data_collection)

    # Get connections to the relevant port collections.
    zgrab_port_data_collection = mongo_connector.get_zgrab_port_data_connection()
    remote_zgrab_port_data_collection = rm_connector.get_zgrab_port_data_connection()

    download_zgrab_port_info(logger, zgrab_port_data_collection, remote_zgrab_port_data_collection)

    # Download latest whois information
    status = remote_jobs_collection.find_one({'job_name': 'whois_lookups'})
    if status['status'] == jobs_manager.COMPLETE:
        whois_collection = mongo_connector.get_whois_connection()
        remote_whois_collection = rm_connector.get_whois_connection()
        download_whois_data(logger, whois_collection, remote_whois_collection)
        remote_jobs_collection.update({'job_name': 'whois'}, {'$set': {'status': jobs_manager.READY}})


    # Download the status of the remote jobs
    download_jobs_status(logger, jobs_manager._jobs_collection, remote_jobs_collection)

    # Update the local jobs database to done
    jobs_manager.record_job_complete()

    now = datetime.now()
    print("Ending: " + str(now))
    logger.info("Complete.")


if __name__ == "__main__":
    main()
