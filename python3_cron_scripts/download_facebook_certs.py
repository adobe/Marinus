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
This script pulls certificate information from the Facebook Graph API assuming that you
have a Facebook Graph account.

Unless otherwise specified, data is written to: /mnt/workspace/ct_facebook/
The hash_based_upload script is no longer necessary for this script.

https://developers.facebook.com/docs/certificate-transparency-api
"""

import argparse
import json
import logging
import os
import time
from datetime import datetime

import requests
from libs3 import (
    FacebookConnector,
    JobsManager,
    MongoConnector,
    StorageManager,
    X509Parser,
)
from libs3.LoggingUtil import LoggingUtil
from libs3.ZoneManager import ZoneManager
from requests.exceptions import Timeout


def make_https_request(logger, jobs_manager, fb_url, timeout_attempt=0):
    """
    Utility function so that the script can loop over paged results.
    """
    try:
        req = requests.get(fb_url)
        req.raise_for_status()
    except requests.exceptions.ConnectionError:
        logger.error("FATAL: Connection Error while fetching the cert list")
        jobs_manager.record_job_error()
        exit(1)
    except requests.exceptions.HTTPError:
        # This occasionally triggers on false domain names
        # For instance, we are holding .web but it isn't officially recognized yet.
        # Therefore, Facebook will error on it but it is safe to continue processing.
        logger.warning("HTTP Error while fetching the cert list")
        return None
    except Timeout:
        if timeout_attempt == 0:
            logger.warning("Timeout occurred. Attempting again...")
            result = make_https_request(logger, jobs_manager, fb_url, timeout_attempt=1)
            return result
        else:
            logger.error("FATAL: Too many timeouts. Exiting")
            jobs_manager.record_job_error()
            exit(1)
    except requests.exceptions.RequestException as err:
        logger.error("FATAL: Request exception while fetching the cert list")
        logger.error(str(err))
        jobs_manager.record_job_error()
        exit(1)

    if req.status_code != 200:
        return None

    return json.loads(req.text)


def fetch_domain(logger, jobs_manager, fbc, access_token, zone):
    """
    Fetch the results for the specified zone.
    """
    fb_url = (
        (fbc.BASE_URL + fbc.VERSION + "/certificates?query=")
        + zone
        + ("&access_token=" + access_token + "&limit=500" + "")
    )
    # "&fields=cert_hash_sha256,domains,issuer_name,certificate_pem"

    cert_results = []

    while fb_url is not None:
        result = make_https_request(logger, jobs_manager, fb_url)

        if result is None:
            logger.warning("Error querying: " + zone)
            return None

        cert_results = cert_results + result["data"]

        try:
            paging = result["paging"]
            fb_url = paging["next"]
        except:
            fb_url = None

    return cert_results


def check_save_location(storage_manager, save_location):
    """
    Check to see if the directory exists.
    If the directory does not exist, it will automatically create it.
    """
    storage_manager.create_folder(save_location)


def main(logger=None):
    """
    Begin Main...
    """
    if logger is None:
        logger = LoggingUtil.create_log(__name__)

    now = datetime.now()
    print("Starting: " + str(now))
    logger.info("Starting...")

    # Make database connections
    mongo_connector = MongoConnector.MongoConnector()
    ct_collection = mongo_connector.get_certificate_transparency_connection()
    jobs_manager = JobsManager.JobsManager(mongo_connector, "facebook_certs")

    jobs_manager.record_job_start()

    file_path = "ct-facebook"

    fb_connector = FacebookConnector.FacebookConnector()
    access_token = fb_connector.get_facebook_access_token()

    zones = ZoneManager.get_distinct_zones(mongo_connector)
    x509_parser = X509Parser.X509Parser()

    parser = argparse.ArgumentParser(
        description="Download DNS and/or certificate information from crt.sh."
    )
    parser.add_argument(
        "--fetch_cert_records",
        choices=["dbAndSave", "dbOnly"],
        default="dbAndSave",
        help="Indicates whether to download the raw files or just record in the database",
    )
    parser.add_argument(
        "--cert_save_location",
        required=False,
        default=file_path,
        help="Indicates the folder when choosing dbAndSave",
    )
    parser.add_argument(
        "--storage_system",
        choices=[
            StorageManager.StorageManager.AWS_S3,
            StorageManager.StorageManager.AZURE_BLOB,
            StorageManager.StorageManager.LOCAL_FILESYSTEM,
        ],
        default=StorageManager.StorageManager.LOCAL_FILESYSTEM,
        help="Indicates where to save the files when dbAndSave is chosen",
    )
    args = parser.parse_args()

    if args.cert_save_location:
        save_location = args.cert_save_location

        if args.storage_system == StorageManager.StorageManager.LOCAL_FILESYSTEM:
            if "/" not in save_location:
                save_location = "./" + save_location
                save_location = save_location + "/"

    storage_manager = StorageManager.StorageManager(location=args.storage_system)

    if args.fetch_cert_records == "dbAndSave":
        check_save_location(storage_manager, save_location)

    for zone in zones:
        time.sleep(15)
        results = fetch_domain(logger, jobs_manager, fb_connector, access_token, zone)

        if results is None:
            logger.warning("ERROR looking up: " + zone)
            continue

        logger.info(zone + ": " + str(len(results)))

        for result in results:
            if args.fetch_cert_records == "dbAndSave":
                storage_manager.write_file(
                    save_location,
                    zone + "_" + result["id"] + ".pem",
                    result["certificate_pem"],
                )

            cert = x509_parser.parse_data(result["certificate_pem"], "facebook")
            if cert is None:
                logger.error(
                    "Could not parse Facebook certificate: " + str(result["id"])
                )
                continue

            cert["facebook_id"] = result["id"]

            if (
                ct_collection.count_documents(
                    {"fingerprint_sha256": cert["fingerprint_sha256"]}
                )
                == 0
            ):
                mongo_connector.perform_insert(ct_collection, cert)
            else:
                if (
                    ct_collection.count_documents(
                        {
                            "fingerprint_sha256": cert["fingerprint_sha256"],
                            "facebook_id": result["id"],
                            "zones": zone,
                        }
                    )
                    == 0
                ):
                    ct_collection.update_one(
                        {"fingerprint_sha256": cert["fingerprint_sha256"]},
                        {
                            "$set": {
                                "marinus_updated": datetime.now(),
                                "facebook_id": result["id"],
                            },
                            "$addToSet": {"zones": zone},
                        },
                    )

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
