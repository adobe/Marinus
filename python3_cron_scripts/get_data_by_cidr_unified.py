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
This script pulls records from Sonar files provided by the Rapid7 Open Data project.
This script searches the records using the CIDRs related to the tracked organization.
"""

import argparse
import ipaddress
import json
import os.path
import subprocess
import sys
import time
from datetime import datetime

import requests
from libs3 import DNSManager, MongoConnector, Rapid7, JobsManager, GoogleDNS
from libs3.ZoneManager import ZoneManager
from netaddr import IPAddress, IPNetwork

mongo_connection = MongoConnector.MongoConnector()
global_dns_manager = DNSManager.DNSManager(mongo_connection)

rdns_collection = mongo_connection.get_sonar_reverse_dns_connection()

global_data_dir = "./files/"


def is_running(process):
    """
    Is the provided process name is currently running?
    """
    proc_list = subprocess.Popen(["pgrep", "-f", process], stdout=subprocess.PIPE)
    for proc in proc_list.stdout:
        if proc.decode('utf-8').rstrip() != str(os.getpid()) and proc.decode('utf-8').rstrip() != str(os.getppid()):
            return True
    return False


def download_file(s, url, data_dir):
    """
    Download the provided file and place it in data_dir
    """
    local_filename = data_dir + url.split('/')[-1]
    # NOTE the stream=True parameter
    req = s.get(url, stream=True)
    with open(local_filename, 'wb') as local_f:
        for chunk in req.iter_content(chunk_size=128*1024):
            if chunk: # filter out keep-alive new chunks
                local_f.write(chunk)
                local_f.flush()
    return local_filename


def check_in_cidr(ip_addr, cidrs):
    """
    Check if the provided IP exists in the given CIDR
    """
    try:
        local_ip = IPAddress(ip_addr)
        for network in cidrs:
            if local_ip in network:
                return True
    except:
        return False
    return False


def get_cidrs(mongo_connection):
    """
    Get the list of CIDRs from the Marinus database
    """
    cidr_collection = mongo_connection.get_ipzone_connection()

    results = cidr_collection.find({'status': {"$ne": "false_positive"}})
    cidrs = []
    for result in results:
        cidrs.append(IPNetwork(result['zone']))

    return cidrs


def get_ipv6_cidrs(mongo_connection):
    """
    Get the list of IPv6 CIDRs from the Marinus database
    """
    cidr_collection = mongo_connection.get_ipv6_zone_connection()

    results = cidr_collection.find({'status': {"$ne": "false_positive"}})
    cidrs = []
    for result in results:
        cidrs.append(IPNetwork(result['zone']))

    return cidrs


def get_sonar_rdns_ips():
    """
    Get the list of Sonar RDNS IPs from the Marinus database
    """
    ips = []
    results = rdns_collection.find({}, {"ip": 1})
    for result in results:
        ips.append(result['ip'])
    return ips


def get_sonar_dns_ips():
    """
    Get the list of Sonar IP records from the Marinus database
    """
    ips = []
    results = global_dns_manager.find_multiple({"type": "a"}, "sonar_dns")
    for result in results:
        ips.append(result['value'])
    return ips


def find_zone(domain, zones):
    """
    Does the domain exist in a tracked zone?
    """
    if domain is None:
        return ""

    for zone in zones:
        if domain.endswith("." + zone) or domain == zone:
            return zone
    return ""


def update_dns(dns_file, cidrs, zones):
    """
    Search DNS file and insert relevant records into the database.
    """
    with open(dns_file, "r") as dns_f:
        for line in dns_f:
            try:
                data = json.loads(line)
            except ValueError:
                continue
            except:
                raise

            try:
                domain = data['name']
            except:
                print("Error with line: " + line)
                domain = ""

            dtype = data['type']

            try:
                value = data['value']
            except KeyError:
                print("Error with line: " + line)
                value = ""
            timestamp = data['timestamp']

            if dtype == "a" and value != "" and domain != "" and check_in_cidr(value, cidrs):
                print("Matched DNS " + value)
                zone = find_zone(domain, zones)
                insert_json = {}
                insert_json['fqdn'] = domain
                insert_json['zone'] = zone
                insert_json['type'] = dtype
                insert_json['status'] = 'unknown'
                insert_json['value'] = value
                insert_json['sonar_timestamp'] = int(timestamp)
                insert_json['created'] = datetime.now()
                global_dns_manager.insert_record(insert_json, "sonar_dns")


def check_for_ptr_record(ipaddr, g_dns, zones):
    """
    For an identified Sonar RDNS record, confirm that there
    is a related PTR record for the IP address. If confirmed,
    add the record to the all_dns collection.
    """
    arpa_record = ipaddress.ip_address(ipaddr).reverse_pointer
    dns_result = g_dns.fetch_DNS_records(arpa_record, g_dns.DNS_TYPES['ptr'])
    if dns_result == []:
        # Lookup failed
        return

    rdns_zone = find_zone(dns_result[0]['value'], zones)

    if rdns_zone != "":
        new_record = dns_result[0]
        new_record['zone'] = rdns_zone
        new_record['created'] = datetime.now()
        new_record['status'] = 'unknown'
        global_dns_manager.insert_record(new_record, "sonar_rdns")


def update_rdns(rdns_file, cidrs, zones):
    """
    Search RDNS file and insert relevant records into the database.
    """
    g_dns = GoogleDNS.GoogleDNS()
    with open(rdns_file, "r") as rdns_f:
        for line in rdns_f:
            try:
                data = json.loads(line)
            except ValueError:
                continue
            except:
                raise

            try:
                ip_addr = data['name']
            except:
                ip_addr = None

            try:
                domain = data['value']
            except KeyError:
                domain = None

            timestamp = data['timestamp']

            if domain != None and ip_addr != None and check_in_cidr(ip_addr, cidrs):
                print("Matched RDNS " + ip_addr)
                zone = find_zone(domain, zones)
                result = rdns_collection.find({'ip': ip_addr}).count()
                if result == 0:
                    insert_json = {}
                    insert_json['ip'] = ip_addr
                    insert_json['zone'] = zone
                    insert_json['fqdn'] = domain
                    insert_json['status'] = 'unknown'
                    insert_json['sonar_timestamp'] = int(timestamp)
                    insert_json['created'] = datetime.now()
                    insert_json['updated'] = datetime.now()
                    rdns_collection.insert(insert_json)
                else:
                    rdns_collection.update({"ip": ip_addr},
                                           {'$set': {"fqdn": domain},
                                            '$currentDate': {"updated" : True}})


                check_for_ptr_record(ip_addr, g_dns, zones)


def download_remote_files(s, file_reference, data_dir, jobs_manager):
    """
    Download and unzip the given file reference.
    """
    subprocess.run("rm " + data_dir + "*", shell=True)

    dns_file = download_file(s, file_reference, data_dir)

    now = datetime.now()
    print ("File downloaded: " + str(now))

    try:
        subprocess.run(["gunzip", dns_file], check=True)
    except:
        print("Could not unzip file: " + dns_file)
        jobs_manager.record_job_error()
        exit(1)

    unzipped_dns = dns_file.replace(".gz", "")

    return unzipped_dns


def main():
    """
    Begin Main...
    """

    if is_running(os.path.basename(__file__)):
        print("Already running...")
        exit(0)

    now = datetime.now()
    print("Starting: " + str(now))

    r7 = Rapid7.Rapid7()

    cidrs = get_cidrs(mongo_connection)
    print ("IPv4 CIDR length: " + str(len(cidrs)))
    cidrs = cidrs + get_ipv6_cidrs(mongo_connection)
    print ("IPv4 + IPv6 CIDR length: " + str(len(cidrs)))
    zones = ZoneManager.get_distinct_zones(mongo_connection)
    print ("Zone length: " + str(len(zones)))

    parser = argparse.ArgumentParser(description='Parse Sonar files based on domain zones.')
    parser.add_argument('--sonar_file_type', required=True, help='Specify "dns" or "rdns"')
    args = parser.parse_args()

    # A session is necessary for the multi-step log-in process
    s = requests.Session()

    if args.sonar_file_type == "rdns":
        jobs_manager = JobsManager.JobsManager(mongo_connection, 'get_data_by_cidr_rdns')
        jobs_manager.record_job_start()

        try:
            html_parser = r7.find_file_locations(s, "rdns", jobs_manager)
            if html_parser.rdns_url == "":
                now = datetime.now()
                print ("Unknown Error: " + str(now))
                jobs_manager.record_job_error()
                exit(0)

            unzipped_rdns = download_remote_files(s, html_parser.rdns_url, global_data_dir, jobs_manager)
            update_rdns(unzipped_rdns, cidrs, zones)
        except Exception as ex:
            now = datetime.now()
            print ("Unknown error occured at: " + str(now))
            print ("Unexpected error: " + str(ex))
            jobs_manager.record_job_error()
            exit(0)

        now = datetime.now()
        print ("RDNS Complete: " + str(now))
        jobs_manager.record_job_complete()

    elif args.sonar_file_type == "dns":
        jobs_manager = JobsManager.JobsManager(mongo_connection, 'get_data_by_cidr_dns')
        jobs_manager.record_job_start()

        try:
            html_parser = r7.find_file_locations(s, "fdns", jobs_manager)
            if html_parser.any_url != "":
                unzipped_dns = download_remote_files(s, html_parser.any_url, global_data_dir, jobs_manager)
                update_dns(unzipped_dns, cidrs, zones)
            if html_parser.a_url != "":
                unzipped_dns = download_remote_files(s, html_parser.a_url, global_data_dir, jobs_manager)
                update_dns(unzipped_dns, cidrs, zones)
            if html_parser.aaaa_url != "":
                unzipped_dns = download_remote_files(s, html_parser.aaaa_url, global_data_dir, jobs_manager)
                update_dns(unzipped_dns, cidrs, zones)
        except Exception as ex:
            now = datetime.now()
            print ("Unknown error occured at: " + str(now))
            print ("Unexpected error: " + str(ex))

            jobs_manager.record_job_error()
            exit(0)

        now = datetime.now()
        print ("DNS Complete: " + str(now))

        jobs_manager.record_job_complete()

    else:
        print ("Unrecognized sonar_file_type option. Exiting...")

    now = datetime.now()
    print ("Complete: " + str(now))


if __name__ == "__main__":
    main()
