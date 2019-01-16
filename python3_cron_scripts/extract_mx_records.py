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
This script extracts domain names from all the MX certificates collected by Marinus.
The script will then use Google HTTPS over DNS to get their DNS records and store them.
"""

import json
import time
from datetime import datetime

import requests

from libs3 import DNSManager, MongoConnector, GoogleDNS
from libs3.ZoneManager import ZoneManager


def add_to_list(str_to_add, dns_names):
    """
    This will add a string to the dns_names array if it does not exist.
    It will then return the index of the string within the Array
    """
    if str_to_add not in dns_names:
        dns_names.append(str_to_add)
    return dns_names.index(str_to_add)


def add_to_round_two(str_to_add, round_two):
    """
    This will add a string to the round_two array if it does not exist.
    It will then return the index of the string within the Array
    """
    if str_to_add not in round_two:
        round_two.append(str_to_add)
    return round_two.index(str_to_add)


def is_tracked_zone(cname, zones):
    """
    Is the root domain for the provided cname one of the known domains?
    """

    for zone in zones:
        if cname.endswith("." + zone) or cname == zone:
            return True
    return False


def get_tracked_zone(name, zones):
    """
    What is the tracked zone for the provided hostname?
    """
    for zone in zones:
        if name.endswith("." + zone) or name == zone:
            return zone
    return None


def extract_mx_names(dns_names, dns_manager):
    """
    Extract the domain names from MX DNS records.
    """

    res = dns_manager.find_multiple({'type': 'mx'}, None)

    for result in res:
        name = result['value']
        if " " in result['value']:
            parts = result['value'].split(" ")
            name = parts[1]
            if name.endswith("."):
                name = name[:-1]

        add_to_list(name, dns_names)


def lookup_hostname(host, round_two, zones):
    """
    Use the Google DNS over HTTPS API to look up the provided host.
    This script uses Google because internal DNS servers may return different data.
    The zones are used to determine whether the DNS record is a CNAME to another tracked host.
    """
    try:
        req = requests.get("https://dns.google.com/resolve?name=" + host)
    except:
        print("Requests attempt failed!")
        return []

    if req.status_code != 200:
        print("Error looking up: " + host)
        return []

    nslookup_results = json.loads(req.text)

    if nslookup_results['Status'] != 0:
        print("Status error looking up: " + host)
        return []

    if "Answer" not in nslookup_results:
        print("Could not find Answer in DNS result for " + host)
        print(req.text)
        return []

    results = []
    for answer in nslookup_results['Answer']:
        if answer['type'] == 5:
            results.append({'type': 'cname', 'value': answer['data'][:-1]})
            if is_tracked_zone(answer['data'][:-1], zones):
                add_to_round_two(answer['data'][:-1], round_two)
        elif answer['type'] == 1:
            results.append({'type': 'a', 'value': answer['data']})
        elif answer['type'] == 28:
            results.append({'type': 'aaaa', 'value': answer['data']})
        else:
            print("Unrecognized type: " + str(answer['type']))

    return results


def main():
    """
    Begin Main...
    """

    now = datetime.now()
    print("Starting: " + str(now))

    mongo_connector = MongoConnector.MongoConnector()
    dns_manager = DNSManager.DNSManager(mongo_connector)
    google_dns = GoogleDNS.GoogleDNS()

    jobs_collection = mongo_connector.get_jobs_connection()

    dns_names = []
    round_two = []

    zones = ZoneManager.get_distinct_zones(mongo_connector)

    # Collect the list of domains from the MX Records
    extract_mx_names(dns_names, dns_manager)

    input_list = []

    # Some MX records point to the third-party domains.
    # Therefore, we filter to only the root domains that belong to the tracked company.
    print("Pre-filter list: " + str(len(dns_names)))
    for hostname in dns_names:
        zone = get_tracked_zone(hostname, zones)
        if zone != None:
            ips = google_dns.fetch_DNS_records(hostname)

            # Pause to prevent DoS-ing of Google's HTTPS DNS Service
            time.sleep(1)

            if ips != []:
                for ip_addr in ips:
                    temp_zone = get_tracked_zone(ip_addr['fqdn'], zones)
                    if temp_zone is not None:
                        record = {"fqdn": ip_addr['fqdn']}
                        record['zone'] = temp_zone
                        record['created'] = datetime.now()
                        record['type'] = ip_addr['type']
                        record['value'] = ip_addr['value']
                        record['status'] = 'unknown'
                        input_list.append(record)

                    if ip_addr['type'] == "cname" and is_tracked_zone(ip_addr['value'], zones):
                        add_to_round_two(ip_addr['value'], round_two)
            else:
                print("Failed IP Lookup for: " + hostname)
        else:
            print("Failed match on zone for: " + hostname)

    dead_dns_collection = mongo_connector.get_dead_dns_connection()

    # Some DNS records will be CNAME records pointing to other tracked domains.
    # This is a single level recursion to lookup those domains.
    print("Round Two list: " + str(len(round_two)))
    for hostname in round_two:
        zone = get_tracked_zone(hostname, zones)
        if zone != None:
            ips = google_dns.fetch_DNS_records(hostname)
            time.sleep(1)
            if ips != []:
                for ip_addr in ips:
                    temp_zone = get_tracked_zone(ip_addr['fqdn'], zones)
                    if temp_zone is not None:
                        record = {"fqdn": ip_addr['fqdn']}
                        record['zone'] = temp_zone
                        record['created'] = datetime.now()
                        record['type'] = ip_addr['type']
                        record['value'] = ip_addr['value']
                        record['status'] = 'unknown'
                        input_list.append(record)
            else:
                print("Failed IP Lookup for: " + hostname)
                original_record = dns_manager.find_one({"fqdn": hostname}, "mx")
                if original_record != None:
                    original_record.pop("_id")
                    dead_dns_collection.insert(original_record)
        else:
            print("Failed match on zone for: " + hostname)


    # Record all the results.
    dns_manager.remove_by_source("mx")
    print("List length: " + str(len(input_list)))
    for final_result in input_list:
        dns_manager.insert_record(final_result, "mx")

    # Record status
    jobs_collection.update_one({'job_name': 'extract_mx_domains'},
                               {'$currentDate': {"updated": True},
                                "$set": {'status': 'COMPLETE'}})

    now = datetime.now()
    print ("Ending: " + str(now))


if __name__ == "__main__":
    main()
