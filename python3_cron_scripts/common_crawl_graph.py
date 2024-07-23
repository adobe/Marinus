#!/usr/bin/python3

# Copyright 2024 Adobe. All rights reserved.
# This file is licensed to you under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License. You may obtain a copy
# of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR REPRESENTATIONS
# OF ANY KIND, either express or implied. See the License for the specific language
# governing permissions and limitations under the License.

"""
This script is meant to parse the Common Crawl host graph data set.
Specifically, it parses the host-level-graph vertices.txt file found on pages such as:
http://commoncrawl.org/2018/08/webgraphs-may-june-july-2018/

This script does not run as a cron job because the vertices files are produced every few months
and the names and timing of the files are not guaranteed to be predictable. Therefore, it should
be updated with each new release.

Depending on the release, there are 40 - 100 vertices files. This script currently processes them one at a time
which means it can take some time to get through them depending on the number of zones. You may want to consider
augmenting this file for distributed networking.

Common_crawl data is not additive. In other words, just because it showed up in the last run does not
mean it will show up in this run. It is quite possible that the host still exists. However, the
Common Crawl methodology is not consistent from run to run.
"""

import argparse
import logging
import string
import subprocess
from datetime import datetime

import requests
from libs3 import DNSManager, GoogleDNS, JobsManager, MongoConnector
from libs3.LoggingUtil import LoggingUtil
from libs3.ZoneManager import ZoneManager

# NOTE: This can be overridden by the command-line parameter
# CURRENT_FILE_LIST = "http://commoncrawl.s3.amazonaws.com/projects/hyperlinkgraph/cc-main-2017-18-nov-dec-jan/host/cc-main-2017-18-nov-dec-jan-host-vertices.paths.gz"
# CURRENT_FILE_LIST = "http://commoncrawl.s3.amazonaws.com/projects/hyperlinkgraph/cc-main-2018-feb-mar-apr/host/cc-main-2018-feb-mar-apr-host-vertices.paths.gz"
# CURRENT_FILE_LIST = "http://commoncrawl.s3.amazonaws.com/projects/hyperlinkgraph/cc-main-2018-may-jun-jul/host/cc-main-2018-may-jun-jul-host-vertices.paths.gz"
# CURRENT_FILE_LIST = "http://commoncrawl.s3.amazonaws.com/projects/hyperlinkgraph/cc-main-2018-aug-sep-oct/host/cc-main-2018-aug-sep-oct-host-vertices.paths.gz"
# CURRENT_FILE_LIST = "http://commoncrawl.s3.amazonaws.com/projects/hyperlinkgraph/cc-main-2018-19-nov-dec-jan/host/cc-main-2018-19-nov-dec-jan-host-vertices.paths.gz"
# CURRENT_FILE_LIST = "https://commoncrawl.s3.amazonaws.com/projects/hyperlinkgraph/cc-main-2019-feb-mar-apr/host/cc-main-2019-feb-mar-apr-host-vertices.paths.gz"
# CURRENT_FILE_LIST = "https://commoncrawl.s3.amazonaws.com/projects/hyperlinkgraph/cc-main-2019-may-jun-jul/host/cc-main-2019-may-jun-jul-host-vertices.paths.gz"
# CURRENT_FILE_LIST = "https://commoncrawl.s3.amazonaws.com/projects/hyperlinkgraph/cc-main-2019-aug-sep-oct/host/cc-main-2019-aug-sep-oct-host-vertices.paths.gz"
# CURRENT_FILE_LIST = "https://commoncrawl.s3.amazonaws.com/projects/hyperlinkgraph/cc-main-2019-20-nov-dec-jan/host/cc-main-2019-20-nov-dec-jan-host-vertices.paths.gz"
# CURRENT_FILE_LIST = "https://commoncrawl.s3.amazonaws.com/projects/hyperlinkgraph/cc-main-2020-feb-mar-may/host/cc-main-2020-feb-mar-may-host-vertices.paths.gz"
# CURRENT_FILE_LIST = "https://commoncrawl.s3.amazonaws.com/projects/hyperlinkgraph/cc-main-2020-jul-aug-sep/host/cc-main-2020-jul-aug-sep-host-vertices.paths.gz"
# CURRENT_FILE_LIST = "https://commoncrawl.s3.amazonaws.com/projects/hyperlinkgraph/cc-main-2020-21-oct-nov-jan/host/cc-main-2020-21-oct-nov-jan-host-vertices.paths.gz"
# CURRENT_FILE_LIST = "https://commoncrawl.s3.amazonaws.com/projects/hyperlinkgraph/cc-main-2021-feb-apr-may/host/cc-main-2021-feb-apr-may-host-vertices.paths.gz"
# CURRENT_FILE_LIST = "https://commoncrawl.s3.amazonaws.com/projects/hyperlinkgraph/cc-main-2021-jun-jul-sep/host/cc-main-2021-jun-jul-sep-host-vertices.paths.gz"
# CURRENT_FILE_LIST = "https://data.commoncrawl.org/projects/hyperlinkgraph/cc-main-2021-jun-jul-sep/host/cc-main-2021-jun-jul-sep-host-vertices.paths.gz"
# CURRENT_FILE_LIST = "https://data.commoncrawl.org/projects/hyperlinkgraph/cc-main-2021-22-oct-nov-jan/host/cc-main-2021-22-oct-nov-jan-host-vertices.paths.gz"
# CURRENT_FILE_LIST = "https://data.commoncrawl.org/projects/hyperlinkgraph/cc-main-2022-may-jun-aug/host/cc-main-2022-may-jun-aug-host-vertices.paths.gz"
# CURRENT_FILE_LIST = "https://data.commoncrawl.org/projects/hyperlinkgraph/cc-main-2022-23-sep-nov-jan/host/cc-main-2022-23-sep-nov-jan-host-vertices.paths.gz"
# CURRENT_FILE_LIST = "https://data.commoncrawl.org/projects/hyperlinkgraph/cc-main-2023-24-sep-nov-feb/host/cc-main-2023-24-sep-nov-feb-host-vertices.paths.gz"
# CURRENT_FILE_LIST = "https://data.commoncrawl.org/projects/hyperlinkgraph/cc-main-2024-feb-apr-may/host/cc-main-2024-feb-apr-may-host-vertices.paths.gz"
CURRENT_FILE_LIST = "https://data.commoncrawl.org/projects/hyperlinkgraph/cc-main-2024-apr-may-jun/host/cc-main-2024-apr-may-jun-host-vertices.paths.gz"

ROOT_DOMAIN = "https://data.commoncrawl.org/"


def download_file(logger, url, save_location):
    """
    Download the file from the provided URL.
    Use the filename in the URL as the name of the outputed file.
    """
    local_filename = save_location + url.split("/")[-1]
    logger.debug(local_filename)
    # NOTE the stream=True parameter
    req = requests.get(url, stream=True)
    with open(local_filename, "wb") as out_f:
        for chunk in req.iter_content(chunk_size=1024):
            if chunk:  # filter out keep-alive new chunks
                out_f.write(chunk)
    out_f.close()
    return local_filename


def check_zones(domain, zones):
    """
    Check if the provided domain exists within the zone
    """
    for zone in zones:
        if domain == zone or domain.startswith(zone + "."):
            return zone
    return None


def swap_order(value):
    """
    Common crawl optimizes search by working back to front ("org.example.www")
    This is a utility function for swapping the order back to the expected value ("www.example.org")
    """
    parts = value.split(".")

    new_value = ""
    for part in parts:
        new_value = part + "." + new_value
    new_value = new_value[:-1]

    return new_value


def parse_file(logger, vertices_file, reversed_zones, dns_manager):
    """
    For each vertices files, iterate over the entries searching for matching zones.
    """
    vertices = open(vertices_file, "r")

    google_dns = GoogleDNS.GoogleDNS()

    for line in vertices:
        parts = line.split("\t")
        if len(parts) > 1:
            domain = parts[1].rstrip("\n")
            reversed_zone = check_zones(domain, reversed_zones)
            if reversed_zone is not None:
                matched_domain = swap_order(domain)
                matched_zone = swap_order(reversed_zone)

                results = google_dns.fetch_DNS_records(matched_domain)
                for result in results:
                    if (
                        result["fqdn"].endswith("." + matched_zone)
                        or result["fqdn"] == matched_zone
                    ):
                        logger.debug("Inserting: " + matched_domain)
                        result["created"] = datetime.now()
                        result["status"] = "confirmed"
                        result["zone"] = matched_zone
                        dns_manager.insert_record(result, "common_crawl")


def get_first_and_last_line(fname):
    """
    Get the first and last line of the file.
    Since the common_crawl files are alphabetical, we can use this information to determine the alphabetic
    range of entries covered by the file. This information will later be used to limit the zone comparison
    to only those zones that would be within that alphabetic range. This is a speed improvement.

    :param fname: The filename to examine for the first and last lines
    :return: Two strings representing the first and last lines, respectively.
    """
    with open(fname, "rb") as fh:
        first = next(fh)
        offs = -10
        while True:
            fh.seek(offs, 2)
            lines = fh.readlines()
            if len(lines) > 1:
                last = lines[-1]
                break
            offs *= 2
        # Return lines by converting bytes back to strings
        return (first.decode("utf-8"), last.decode("utf-8"))


def get_zone_sublist(logger, fc, lc, grouped_zones):
    """
    Comparing every single zone to every single line of the file is inefficient and slow.
    Common Crawl tracks over a billion entries and each line requires two comparisons per zone.
    Therefore, a speed increase can be made if the comparisons are limited to zones relevant to the file.
    The vast majority of Common Crawl files begin with the letter "c" (.cc, .cn, .com, etc.) so this mostly
    only provides significant help when dealing with the first few files and the last few files. That said,
    when dealing with 15GB of plain text, any speed increase is welcome.

    TODO: Increase performance by separating zones by TLD instead of alphabetically. There are multiple
    GB sized files which are completely ".cn". Speed could further be increased by eliminating the .com
    comparisons for those files.

    Given the provided first character and last character of the file, return only the zones that are
    relevant to that range.

    :param fc: The first character of the first line of the file.
    :param lc: The first character of the last line of the file.
    :param grouped_zones: The dictionary of zones grouped by their first letter
    :return: A list of zones limited to those between the first and last character.
    """
    if fc == lc:
        return grouped_zones[fc]

    chars = list(string.digits + string.ascii_lowercase)
    first_pos = chars.index(fc)
    last_pos = chars.index(lc)

    logger.debug(str(first_pos) + ": " + chars[first_pos])
    logger.debug(str(last_pos) + ": " + chars[last_pos])

    new_zone_list = []
    for i in range(first_pos, last_pos + 1):
        new_zone_list = new_zone_list + grouped_zones[chars[i]]

    return new_zone_list


def main(logger=None):
    """
    Begin main...
    """
    if logger is None:
        logger = LoggingUtil.create_log(__name__)

    parser = argparse.ArgumentParser(
        description="Search the Common Crawl graph dataset for new domains"
    )
    parser.add_argument(
        "--url", metavar="URL", help="The URL for the latest vertices file"
    )
    parser.add_argument(
        "--save_location",
        metavar="LOCATION",
        default="./files",
        help="The directory for saving files",
    )
    args = parser.parse_args()

    CURRENT_FILE = CURRENT_FILE_LIST

    if args.url != None:
        CURRENT_FILE = args.url

    now = datetime.now()
    print("Starting: " + str(now))
    logger.info("Starting...")

    mongo_connector = MongoConnector.MongoConnector()
    dns_manager = DNSManager.DNSManager(mongo_connector)
    jobs_manager = JobsManager.JobsManager(mongo_connector, "common_crawl_graph")
    jobs_manager.record_job_start()

    reversed_zones = ZoneManager.get_reversed_zones(mongo_connector)

    alphabet = list(string.digits + string.ascii_lowercase)

    # Create a dictionary of the zones grouped by their first letter
    # This will allow us to reduce the number of comparisons in the alphabetized CC files.
    grouped_zones = {}
    for letter in alphabet:
        grouped_zones[letter] = []

    for zone in reversed_zones:
        first_letter = zone[0]
        grouped_zones[first_letter].append(zone)

    save_location = args.save_location
    if not save_location.endswith("/"):
        save_location = save_location + "/"

    compressed_download_list = download_file(logger, CURRENT_FILE, save_location)
    try:
        subprocess.check_call(["gunzip", "-f", compressed_download_list])
    except Exception as e:
        logger.error("Could not unzip download list")
        logger.error(str(e))
        jobs_manager.record_job_error()
        exit(1)

    download_list = compressed_download_list.split(".")[:-1]
    list_file = ".".join(download_list)

    vertices_file_entries = open(list_file, "r")

    for entry in vertices_file_entries:
        # Download file
        vert_file_url = ROOT_DOMAIN + entry.rstrip("\n")
        compressed_vertices_file = download_file(logger, vert_file_url, save_location)

        # Decompress file
        try:
            subprocess.check_call(["gunzip", "-f", compressed_vertices_file])
        except Exception as e:
            logger.error("Could not unzip vertices file: " + compressed_vertices_file)
            logger.error(str(e))
            jobs_manager.record_job_error()
            exit(1)

        vertices_list = compressed_vertices_file.split(".")[:-1]
        vertices_file = ".".join(vertices_list)

        # Get the first and last line of the file
        (first_line, last_line) = get_first_and_last_line(vertices_file)

        # Get the first and last domain
        parts = first_line.split("\t")
        first_domain = parts[1].rstrip("\n")
        first_char = first_domain[0]

        parts = last_line.split("\t")
        last_domain = parts[1].rstrip("\n")
        last_char = last_domain[0]

        # Get the list of zones relevant to that range
        searchable_zones = get_zone_sublist(
            logger, first_char, last_char, grouped_zones
        )

        # Parse file and insert matches
        parse_file(logger, vertices_file, searchable_zones, dns_manager)
        subprocess.check_call(["rm", vertices_file])

    # Remove all entries more than two months old
    # Note: This commented out because Common Crawl graph data is not additive.
    # dns_manager.remove_all_by_source_and_date("common_crawl", -4)

    jobs_manager.record_job_complete()

    now = datetime.now()
    print("Ending: " + str(now))
    logger.info("Complete")


if __name__ == "__main__":
    logger = LoggingUtil.create_log(__name__)

    try:
        main(logger)
    except Exception as e:
        logger.error("FATAL: " + str(e), exc_info=True)
        exit(1)
