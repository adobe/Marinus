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

from datetime import datetime

from libs3 import DNSManager, MongoConnector, GoogleDNS, JobsManager, IPManager
from libs3.ZoneManager import ZoneManager

def is_tracked_zone(cname, zones):
    """
    Is the root domain for the provided cname one of the known domains?
    """

    for zone in zones:
        if cname.endswith("." + zone) or cname == zone:
            return True
    return False


def monthdelta(date, delta):
    """
    Get the date relevant to the delta from today's date
    """
    m, y = (date.month+delta) % 12, date.year + ((date.month)+delta-1) // 12
    if not m:
        m = 12
    d = min(date.day, [31, 29 if y%4==0 and not y%400==0 else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][m-1])
    return date.replace(day=d, month=m, year=y)


def get_int_for_unk_type(dtype):
    """
    Returns the int for an unknown type from Sonar.
    The DNS type is the integer at the end of the "unk_in_{num}" string.
    """
    return int(dtype[7:])


def fix_unk_types(dtype, g_dns):
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
        print("Warning: Unknown type: " + dtype)

    return dtype


def get_lookup_int(result, GDNS):
    """
    Get the DNS Type integer for the Google DNS query
    """
    if result['type'].startswith("unk_in_"):
        # Sonar didn't know what it was.

        new_type = fix_unk_types(result['type'], GDNS)
        if new_type.startswith("unk_in"):
            # Marinus doesn't know what it is either.
            lookup_int = get_int_for_unk_type(result['type'])
        else:
            # Marinus was able to translate it.
            lookup_int = GDNS.DNS_TYPES[new_type]
    else:
        # Normal type
        lookup_int = GDNS.DNS_TYPES[result['type']]

    return lookup_int


def insert_current_results(dns_result, dns_manager, zones, result, source):
    """
    Insert results so that their entries are current
    """
    for dns_entry in dns_result:
        if is_tracked_zone(dns_entry['fqdn'], zones):
            new_entry={}
            new_entry['updated'] = datetime.now()
            new_entry['zone'] = result['zone']
            new_entry['fqdn'] = dns_entry['fqdn']
            new_entry['created'] = result['created']
            new_entry['value'] = dns_entry['value']
            new_entry['type'] = dns_entry['type']
            new_entry['status'] = 'confirmed'

            if 'sonar_timestamp' in result:
                new_entry['sonar_timestamp'] = result['sonar_timestamp']

            if source.endswith("_saved"):
                dns_manager.insert_record(new_entry, source)
            else:
                dns_manager.insert_record(new_entry, source + "_saved")


def main():
    """
    Begin Main...
    """

    # The sources for which to remove expired entries
    # Infoblox is handled separately
    # {"source_name": date_difference_in_months}
    sources = [{"name": "sonar_dns", "diff": -2},
               {"name": "sonar_dns_saved", "diff": -2},
               {"name": "sonar_rdns", "diff": -2},
               {"name": "sonar_rdns_saved", "diff": -2},
               {"name": "ssl", "diff": -2},
               {"name": "ssl_saved", "diff": -2},
               {"name": "virustotal", "diff": -2},
               {"name": "virustotal_saved", "diff": -2},
               {"name": "UltraDNS", "diff": -2},
               {"name": "UltraDNS_saved", "diff": -2},
               {"name": "marinus", "diff": -2},
               {"name": "marinus_saved", "diff": -2},
               {"name": "mx", "diff": -2},
               {"name": "mx_saved", "diff": -2},
               {"name": "common_crawl", "diff": -4},
               {"name": "common_crawl_saved", "diff": -4}]

    amass_diff = -2

    now = datetime.now()
    print ("Starting: " + str(now))

    mongo_connector = MongoConnector.MongoConnector()
    all_dns_collection = mongo_connector.get_all_dns_connection()
    dns_manager = DNSManager.DNSManager(mongo_connector)
    GDNS = GoogleDNS.GoogleDNS()
    ip_manager = IPManager.IPManager(mongo_connector)

    jobs_manager = JobsManager.JobsManager(mongo_connector, 'remove_expired_entries')
    jobs_manager.record_job_start()

    zones = ZoneManager.get_distinct_zones(mongo_connector)

    # Get the date for today minus two months
    d_minus_2m = monthdelta(datetime.now(), -2)

    print("Removing SRDNS as of: " + str(d_minus_2m))

    # Remove the old records
    srdns_collection = mongo_connector.get_sonar_reverse_dns_connection()
    srdns_collection.remove({'updated': {"$lt": d_minus_2m}})

    ip_manager.delete_records_by_date(d_minus_2m)

    # Before completely removing old entries, make an attempt to see if they are still valid.
    # Occasionally, a host name will still be valid but, for whatever reason, is no longer tracked by a source.
    # Rather than throw away valid information, this will archive it.
    for entry in sources:
        removal_date = monthdelta(datetime.now(), entry['diff'])
        source = entry['name']
        print("Removing " + source + " as of: " + str(removal_date))

        last_domain = ""
        results = all_dns_collection.find({'sources': {"$size": 1}, 'sources.source': source, 'sources.updated': {"$lt": removal_date}})
        for result in results:
            if result['fqdn'] != last_domain:
                last_domain = result['fqdn']

                lookup_int = get_lookup_int(result, GDNS)
                dns_result = GDNS.fetch_DNS_records(result['fqdn'], lookup_int)

                if dns_result != []:
                    insert_current_results(dns_result, dns_manager, zones, result, source)

        dns_manager.remove_all_by_source_and_date(source, entry['diff'])

    # Process amass entries
    temp_sources = mongo_connector.perform_distinct(all_dns_collection, 'sources.source')
    amass_sources = []
    for entry in temp_sources:
        if entry.startswith("amass:"):
            amass_sources.append(entry)

    for source in amass_sources:
        removal_date = monthdelta(datetime.now(), amass_diff)
        print("Removing " + source + " as of: " + str(removal_date))

        last_domain = ""
        results = mongo_connector.perform_find(all_dns_collection, {'sources': {"$size": 1}, 'sources.source': source, 'sources.updated': {"$lt": removal_date}})
        for result in results:
            if result['fqdn'] != last_domain:
                last_domain = result['fqdn']

                lookup_int = get_lookup_int(result, GDNS)
                dns_result = GDNS.fetch_DNS_records(result['fqdn'], lookup_int)

                if dns_result != []:
                    insert_current_results(dns_result, dns_manager, zones, result, source)

        dns_manager.remove_all_by_source_and_date(source, amass_diff)

    # Record status
    jobs_manager.record_job_complete()

    now = datetime.now()
    print("Complete: " + str(now))


if __name__ == "__main__":
    main()
