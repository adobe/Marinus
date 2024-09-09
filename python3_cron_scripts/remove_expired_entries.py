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
This expires records that haven't had a match in the last two months.

Two months was chosen because some scripts take a few weeks to run.
In addition, a lookup may fail in any given week due to an intermittent network or host.
A two month window ensures that the entry still hasn't shown up after multiple runs by the original source script.

If a record was identified by more than one source, only the expired source is removed from the record.
If an entry was only identified by one source, then this script will do its own lookup to see if it still exists.
If the entry still exists, then it will add "{source_name}_saved" as a source and remove the original source.
The original source is removed because it technically no longer exists there.
The "{source}_saved" indicates the original source while also indicating that Marinus is now tracking the entry its own.
"""
import argparse
import logging
import time
from datetime import datetime, timedelta

from libs3 import DNSManager, GoogleDNS, IPManager, JobsManager, MongoConnector
from libs3.LoggingUtil import LoggingUtil

# from libs3.ZoneManager import ZoneManager


def is_tracked_zone(fqdn, zone):
    """
    Is the root domain for the provided fqdn one of the known domains?
    """

    if fqdn.endswith("." + zone) or fqdn == zone:
        return True
    return False


def monthdelta(date, delta):
    """
    Get the date relevant to the delta from today's date
    """
    m, y = (date.month + delta) % 12, date.year + ((date.month) + delta - 1) // 12
    if not m:
        m = 12
    d = min(
        date.day,
        [
            31,
            29 if y % 4 == 0 and not y % 400 == 0 else 28,
            31,
            30,
            31,
            30,
            31,
            31,
            30,
            31,
            30,
            31,
        ][m - 1],
    )
    return date.replace(day=d, month=m, year=y)


def get_int_for_unk_type(dtype):
    """
    Returns the int for an unknown type from Sonar.
    The DNS type is the integer at the end of the "unk_in_{num}" string.
    """
    return int(dtype[7:])


def fix_unk_types(logger, dtype, g_dns):
    """
    This is to address issues with Sonar data for unknown values.
    This function will try to determine if Marinus is able to recognize the DNS type.
    """
    if dtype.startswith("unk_in_"):
        type_num = get_int_for_unk_type(dtype)
        for key, value in g_dns.DNS_TYPES.items():
            if value == type_num:
                dtype = key
                break

    if dtype.startswith("unk_in_"):
        logger.warning("Unknown type: " + dtype)

    return dtype


def get_lookup_int(logger, result, GDNS):
    """
    Get the DNS Type integer for the Google DNS query
    """
    if result["type"].startswith("unk_in_"):
        # Sonar didn't know what it was.

        new_type = fix_unk_types(logger, result["type"], GDNS)
        if new_type.startswith("unk_in"):
            # Marinus doesn't know what it is either.
            lookup_int = get_int_for_unk_type(result["type"])
        else:
            # Marinus was able to translate it.
            lookup_int = GDNS.DNS_TYPES[new_type]
    else:
        # Normal type
        lookup_int = GDNS.DNS_TYPES[result["type"]]

    return lookup_int


def insert_current_results(logger, dns_result, dns_manager, result, source):
    """
    Insert results so that their entries are current
    """
    for dns_entry in dns_result:
        if is_tracked_zone(dns_entry["fqdn"], result["zone"]):
            new_entry = {}
            new_entry["updated"] = datetime.now()
            new_entry["zone"] = result["zone"]
            new_entry["fqdn"] = dns_entry["fqdn"]
            if "created" in result:
                new_entry["created"] = result["created"]
            else:
                new_entry["created"] = datetime.now()
            new_entry["value"] = dns_entry["value"]
            new_entry["type"] = dns_entry["type"]
            new_entry["status"] = "confirmed"

            if "sonar_timestamp" in result:
                new_entry["sonar_timestamp"] = result["sonar_timestamp"]

            if source.endswith("_saved"):
                dns_manager.insert_record(new_entry, source)
            else:
                dns_manager.insert_record(new_entry, source + "_saved")
        else:
            logger.debug(
                "Failed to insert record for "
                + dns_entry["fqdn"]
                + " because it is not in the tracked zone:"
                + result["zone"]
                + " for the domain: "
                + result["fqdn"]
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
    all_dns_collection = mongo_connector.get_all_dns_connection()
    dns_manager = DNSManager.DNSManager(mongo_connector)
    GDNS = GoogleDNS.GoogleDNS()
    ip_manager = IPManager.IPManager(mongo_connector)

    jobs_manager = JobsManager.JobsManager(mongo_connector, "remove_expired_entries")
    jobs_manager.record_job_start()

    # zones = ZoneManager.get_distinct_zones(mongo_connector)

    parser = argparse.ArgumentParser(description="Remove expired entries from Marinus")
    parser.add_argument(
        "--source",
        required=False,
        help="Only run the script for a specific data source",
    )
    args = parser.parse_args()

    results = mongo_connector.perform_distinct(all_dns_collection, "sources.source")

    sources_list = None
    if args.source is not None and args.source != "":
        if args.source not in results:
            logger.error("FATAL: Unrecognized source value provided")
            exit(1)

        sources_list = [args.source]
    else:
        # The sources for which to remove expired entries
        sources_list = results

    sources = []
    for source in sources_list:
        temp = {}
        temp["name"] = source
        if "common_crawl" in source:
            temp["diff"] = -4
        else:
            temp["diff"] = -2

        sources.append(temp)

    # Before completely removing old entries, make an attempt to see if they are still valid.
    # Occasionally, a host name will still be valid but, for whatever reason, is no longer tracked by a source.
    # Rather than throw away valid information, this will archive it.
    for entry in sources:
        if "route53" in entry:
            removal_date = datetime.now() - timedelta(days=2)
        else:
            removal_date = monthdelta(datetime.now(), entry["diff"])

        source = entry["name"]
        logger.debug("Removing " + source + " as of: " + str(removal_date))

        last_domain = ""
        last_type = ""

        # Get the records that haven't been updated in the last two months
        #                 "sources": {"$size": 1},
        # Needs to be from the same sub-group
        results = mongo_connector.perform_find(
            all_dns_collection,
            {"sources.source": source, "updated": {"$lt": removal_date}},
            batch_size=10,
        )

        for result in results:
            # Some DNS fields have multiple entries for the same type.
            # When the Google DNS query is made, it will return all entries for that type.
            # To avoid making multiple queries for the same type, this will only make one query
            if result["fqdn"] != last_domain or result["type"] != last_type:
                last_domain = result["fqdn"]
                last_type = result["type"]

                # Find the DNS integer for the given type
                lookup_int = get_lookup_int(logger, result, GDNS)
                # Search for only those types of records
                dns_result = GDNS.fetch_DNS_records(result["fqdn"], lookup_int)

                # If Google DNS returns a result, then the record is still valid.
                if dns_result is not None and dns_result != []:
                    # Insert the current results by updating the record in place.
                    insert_current_results(
                        logger, dns_result, dns_manager, result, source
                    )
                    # Pause to ensure there is no rate limiting by Google
                    # Waiting a second also allows for updates to be reflected in DB.
                    time.sleep(1)

                    # Check if the insert updated the original record
                    # If the record was updated, then this will return None
                    # If the record was not updated, then this will return the original record
                    # which can now be removed since it is no longer valid.
                    test_result = mongo_connector.perform_find_one(
                        all_dns_collection,
                        {
                            "_id": result["_id"],
                            "updated": {"$lt": removal_date},
                        },
                    )
                elif dns_result == []:
                    # Allow space for next DNS query
                    time.sleep(1)

                    # The DNS record no longer exists because it was not found by Google DNS.
                    # Remove it in the next step by ensuring test_result is not None.
                    # If there were multiple sources that had reported it, then the record is
                    # still removed because GoogleDNS didn't find it.
                    test_result = {"foo": "bar"}
                    logger.debug(
                        "DNS lookup returned no results for : " + result["fqdn"]
                    )
                else:
                    # The DNS lookup had a failure. This could be due to a network issue or the host being down.
                    # Allow the record to persist until the next run to see if it is still valid.
                    test_result = None
                    logger.debug("DNS lookup failed for: " + result["fqdn"])

                # Test_result checks to see if the record was updated in place or
                # whether the DNS lookup resulted in brand new entries. If the DNS lookup
                # only added new entries, then the original record is removed.
                # Also, if Google DNS failed to find the record, then the record is removed
                # since it is no longer valid.
                if test_result is not None:
                    # This will only remove the source entry if the source entry is stale.
                    # If there was only one source entry, then the record will be removed.
                    # During the insert step, the source was updated to "{source}_saved" if
                    # the record was still valid but the source is no longer tracking it.
                    query_res = dns_manager.remove_by_object_id_and_source(
                        result["_id"], source
                    )
                    if query_res is True:
                        logger.warning(
                            "Removed entry for: "
                            + result["fqdn"]
                            + " and type "
                            + result["type"]
                            + " and updated "
                            + str(result["updated"])
                            + " from source "
                            + source
                        )
                    else:
                        logger.warning(
                            "Failed to remove entry for: "
                            + result["fqdn"]
                            + " and type "
                            + result["type"]
                            + " and updated "
                            + str(result["updated"])
                            + " from source "
                            + source
                        )

    # Get the date for today minus two months
    d_minus_2m = monthdelta(datetime.now(), -2)

    logger.info("Removing SRDNS as of: " + str(d_minus_2m))

    # Remove the old records
    srdns_collection = mongo_connector.get_sonar_reverse_dns_connection()
    srdns_collection.delete_many({"updated": {"$lt": d_minus_2m}})

    ip_manager.delete_records_by_date(d_minus_2m)

    # Record status
    jobs_manager.record_job_complete()

    now = datetime.now()
    print("Complete: " + str(now))
    logger.info("Complete")


if __name__ == "__main__":
    logger = LoggingUtil.create_log(__name__)

    try:
        main(logger)
    except Exception as e:
        logger.error("FATAL: " + str(e), exc_info=True)
        exit(1)
