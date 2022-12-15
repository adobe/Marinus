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
NOTE: This script has been deprecated.

This script is responsible for downloading and unpacking the huge file from Censys.io.
This will take a little over 11 hours to download and unpack a one gig Censys file.
The second stage script, search_censys_files, takes approximately two days to run.
"""

import json
import logging
import re
import subprocess
import time
from datetime import datetime

import requests
from libs3 import RemoteMongoConnector
from libs3.LoggingUtil import LoggingUtil
from requests.auth import HTTPBasicAuth

# Censys authentication information
CENSYS_API = "https://www.censys.io/api/v1/"
CENSYS_APP_ID = "CENSYS_APP_ID"
CENSYS_SECRET = "CENSYS_SECRET"
TIMESTAMP_FILE = "timestamp.txt"
FILENAME_FILE = "filename.txt"
DECOMPRESSED_FILE = "ipv4.json"


def is_running(process):
    """
    Is the provided process name is currently running?
    """
    proc_list = subprocess.Popen(["ps", "axw"], stdout=subprocess.PIPE)
    for proc in proc_list.stdout:
        if re.search(process, str(proc)):
            return True

    return False


def download_file(logger, url):
    """
    Download the file from the provided URL.
    Use the filename in the URL as the name of the outputed file.
    """
    local_filename = url.split("/")[-1]
    logger.debug(local_filename)
    # NOTE the stream=True parameter
    req = requests.get(url, stream=True)
    with open(local_filename, "wb") as out_f:
        for chunk in req.iter_content(chunk_size=1024):
            if chunk:  # filter out keep-alive new chunks
                out_f.write(chunk)
    out_f.close()
    return local_filename


def main(logger=None):
    """
    Begin main...
    """
    if logger is None:
        logger = LoggingUtil.create_log(__name__)

    # Don't run if the search files script is working on the existing file.
    if is_running("search_censys_files_new.py"):
        now = datetime.now()
        logger.warning("File search running: " + str(now))
        exit(0)

    # Record the start in the logs
    now = datetime.now()
    print("Starting: " + str(now))
    logger.info("Starting...")

    RMC = RemoteMongoConnector.RemoteMongoConnector()
    jobs_collection = RMC.get_jobs_connection()

    # Obtain the timestamp of the last file that was downloaded.
    last_timestamp = "0"
    try:
        f_time = open(TIMESTAMP_FILE, "r")
        last_timestamp = f_time.readline()
        f_time.close()
    except FileNotFoundError:
        last_timestamp = "0"

    # Get the meta data for the currently available file.
    req = requests.get(
        CENSYS_API + "data/ipv4", auth=HTTPBasicAuth(CENSYS_APP_ID, CENSYS_SECRET)
    )

    if req.status_code != 200:
        logger.warning(
            "Error " + str(req.status_code) + ": Unable to query Censys Data API\n"
        )
        logger.warning(req.text)

        time.sleep(60)
        req = requests.get(
            CENSYS_API + "data/ipv4", auth=HTTPBasicAuth(CENSYS_APP_ID, CENSYS_SECRET)
        )
        if req.status_code != 200:
            logger.error("Error on IPv4 retry. Giving up...")
            exit(1)

    data_json = json.loads(req.text)

    # Get the timestamp for the currently available file
    timestamp = data_json["results"]["latest"]["timestamp"]

    # If it is the same file as last time, then don't download again.
    if last_timestamp == timestamp:
        logger.error("Already downloaded. Exiting...")
        exit(0)
    else:
        logger.info("Old timestamp: " + last_timestamp)
        logger.info("New timestamp: " + timestamp)

    # Get the location of the details for the new file
    details_url = data_json["results"]["latest"]["details_url"]

    req = requests.get(details_url, auth=HTTPBasicAuth(CENSYS_APP_ID, CENSYS_SECRET))

    if req.status_code != 200:
        logger.warning(
            "Error " + str(req.status_code) + ": Unable to query Censys Details API\n"
        )
        logger.warning(req.text)

        time.sleep(60)
        req = requests.get(
            details_url, auth=HTTPBasicAuth(CENSYS_APP_ID, CENSYS_SECRET)
        )
        if req.status_code != 200:
            logger.error("Error on details retry. Giving up...")
            exit(0)

    data_json = json.loads(req.text)

    compressed_path = data_json["primary_file"]["compressed_download_path"]
    logger.info(compressed_path)

    # Record the timestamp of the file that we are about to download.
    time_f = open(TIMESTAMP_FILE, "w")
    time_f.write(timestamp)
    time_f.close()

    # Remove any old files.
    subprocess.call(["rm", DECOMPRESSED_FILE])
    subprocess.call("rm *.lz4", shell=True)

    # Download the new file.
    filename = download_file(logger, compressed_path)

    # Decompress the new file into the file indicated by "DECOMPRESSED_FILE"
    subprocess.check_call(["lz4", "-d", filename, DECOMPRESSED_FILE])

    # Record the name of the filename that has the output
    dec_f = open(FILENAME_FILE, "w")
    dec_f.write(DECOMPRESSED_FILE)
    dec_f.close()

    # Record that we successfully downloaded the file and that search files can start.
    jobs_collection.update_one(
        {"job_name": "censys"},
        {"$currentDate": {"updated": True}, "$set": {"status": "DOWNLOADED"}},
    )

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

exit(0)
