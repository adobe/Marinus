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
This script will use the ZGrab utility to make HTTP and HTTPS connections to IP addresses.
This script is different than zgrab_port because it supports HTTP-specific features such as following redirects.
It will log the full HTTP response along including both the headers and the web page that is returned.

The original ZGrab has been deprecated and replaced with ZGrab 2.0. This script will support using either version.
However, the version that you use in the Python scripts should match the version that you have specified in the
web server configuration. The schemas between ZGrab and ZGrab 2.0 are not compatible.

You can specify the location of ZGrab using the command line. The script assumes that paths with "zgrab2"
in them indicates that you're running ZGrab 2.0. Otherwise, it will assume that you are running the original
ZGrab.

Please note that this script assumes that a "./json_p{#}" directory exists for the port that you are scanning.
If it does not, then this script will create the directory.

https://github.com/zmap/zgrab
https://github.com/zmap/zgrab2
"""

import os
import subprocess
import threading
import queue
import json
import time
import random
import argparse
from dateutil.parser import parse
from datetime import datetime, timedelta
from netaddr import IPNetwork, IPAddress

from libs3 import RemoteMongoConnector, JobsManager
from libs3.ZoneManager import ZoneManager


global_exit_flag = 0
global_queue_lock = threading.Lock()
global_work_queue = queue.Queue()
global_zgrab_path = "./zgrab/src/github.com/zmap/zgrab2/zgrab2"


def is_running(process):
    """
    Is the provided process name is currently running?
    """
    proc_list = subprocess.Popen(["pgrep", "-f", process], stdout=subprocess.PIPE)
    for proc in proc_list.stdout:
        if proc.decode('utf-8').rstrip() != str(os.getpid()) and proc.decode('utf-8').rstrip() != str(os.getppid()):
            return True
    return False


def get_aws_ips(rm_connector):
    """
    Get the list of AWS CIDRs.
    """
    aws_ips = []
    aws_ips_collection = rm_connector.get_aws_ips_connection()

    results = aws_ips_collection.find({})
    for result in results[0]['prefixes']:
        aws_ips.append(IPNetwork(result['ip_prefix']))

    return aws_ips


def get_azure_ips(rm_connector):
    """
    Get the list of AWS CIDRs.
    """
    azure_ips = []
    azure_ips_collection = rm_connector.get_azure_ips_connection()

    results = azure_ips_collection.find({})
    for result in results[0]['prefixes']:
        azure_ips.append(IPNetwork(result['ip_prefix']))

    return azure_ips


def check_in_cidr(ip_addr, cidrs):
    """
    Is the provided IP in one of the provided CIDRs?
    """
    try:
        local_ip = IPAddress(ip_addr)
        for network in cidrs:
            if local_ip in network:
                return True
    except:
        return False
    return False


def is_aws_ip(ip_addr, aws_ips):
    """
    Is the provided IP within one of the AWS CIDRs?
    """
    return check_in_cidr(ip_addr, aws_ips)


def is_azure_ip(ip_addr, azure_ips):
    """
    Is the provided IP within one of the AWS CIDRs?
    """
    return check_in_cidr(ip_addr, azure_ips)


def is_tracked_ip(ip_addr, tracked_ips):
    """
    Is the provided IP within one of the tracked CIDRs?
    """
    return check_in_cidr(ip_addr, tracked_ips)


def get_ip_zones(rm_connector):
    """
    Get the list of IP Zones
    """
    ip_zones_collection = rm_connector.get_ipzone_connection()
    ipz_results = ip_zones_collection.find({'status': {"$ne": 'false_positive'}})

    ip_zones = []
    for ipz in ipz_results:
        ip_zones.append(IPNetwork(ipz['zone']))

    return ip_zones


def get_ips(ip_zones, all_dns_collection):
    """
    Get the list of IPs
    """
    ips = set([])
    ip_context = []

    domain_results = all_dns_collection.find({'type': 'a'})
    for result in domain_results:
        if not check_in_cidr(result['value'], [IPNetwork("10.0.0.0/8"), IPNetwork("172.16.0.0/12"), IPNetwork("192.168.0.0/16"), IPNetwork("127.0.0.0/8")]) and result['value'] is not "255.255.255.255":
            ips.add(result['value'])
            ip_context.append({'ip': result['value'], 'domain': result['fqdn'], 'source':'all_dns', 'zone': result['zone']})


    for ipz in ip_zones:
        for ip in ipz:
            if ip != ipz.network and ip != ipz.broadcast:
                ips.add(str(ip))
                # ip_context.append({'ip': str(ip), 'source': 'ip_zone'})


    # Don't want to look like a network scan
    # Set doesn't support random.shuffle
    ips_list = list(ips)
    random.shuffle(ips_list)

    return (ips_list, ip_context)


def check_ip_context(ip, ip_context):
    """
    Check for matching ip_context records
    """
    matches = []

    for entry in ip_context:
        if entry['ip'] == ip:
             matches.append(entry)

    return matches


def zone_compare(value, zones):
    """
    Determines whether value is in a known zone
    """
    for zone in zones:
        if value.endswith("." + zone) or value == zone:
            return zone
    return None


def check_in_zone(entry, zones):
    """
    Obtain the DNS names from the common_name and dns_zones from the entry's SSL certificate.
    Determine if the entry's DNS names is in the list of provided zones.
    Return the matched zone.
    """

    if 'zgrab2' in global_zgrab_path:
        if "redirect_response_chain" in entry['data']['http']['result']:
            try:
                certificate = entry['data']['http']['result']['redirect_response_chain'][0]['request']['tls_log']['handshake_log']['server_certificates']['certificate']
            except:
                return []
        else:
            try:
                certificate = entry['data']['http']['result']['response']['request']['tls_log']['handshake_log']['server_certificates']['certificate']
            except:
                return []
    else:
        if "redirect_response_chain" in entry['data']['http']:
            try:
                certificate = entry['data']['http']['redirect_response_chain'][0]['request']['tls_handshake']['server_certificates']['certificate']
            except:
                return []
        else:
            try:
                certificate = entry['data']['http']['response']['request']['tls_handshake']['server_certificates']['certificate']
            except:
                return []

    try:
        temp1 = certificate["parsed"]["subject"]["common_name"]
    except KeyError:
        temp1 = []

    try:
        temp2 = certificate["parsed"]["extensions"]["subject_alt_name"]["dns_names"]
    except KeyError:
        temp2 = []

    cert_zones = []
    value_array = temp1 + temp2
    for value in value_array:
        zone = zone_compare(value, zones)
        if zone is not None and zone not in cert_zones:
            cert_zones.append(zone)

    return cert_zones


def insert_result(entry, port, ip_context, zones, results_collection):
    """
    Insert the matched domain into the collection of positive results.
    """
    if 'zgrab2' in global_zgrab_path:
        temp_date = entry['data']['http']['timestamp']
        new_date = parse(temp_date)
        entry["timestamp"] = new_date
        entry['data']['http']['timestamp'] = new_date
    else:
        temp_date = entry["timestamp"]
        new_date = parse(temp_date)
        entry["timestamp"] = new_date

    entry['domain'] = "<nil>"

    matches = check_ip_context(entry['ip'], ip_context)

    zones = []
    if len(matches) > 0:
        for match in matches:
            if match['zone'] not in zones:
                zones.append(match['zone'])
    if port == "443":
        cert_zones = check_in_zone(entry, zones)
        for zone in cert_zones:
            if zone not in zones:
                zones.append(zone)

    entry['zones'] = zones

    results_collection.update({"ip": entry['ip']}, entry, upsert=True)


def run_port_80_command(target_list, tnum):
    targets = ""
    for ip in target_list:
        targets = targets + ip + "\\n"
    targets = targets[:-2]
    p1 = subprocess.Popen(["echo", "-e", targets], stdout=subprocess.PIPE)
    if 'zgrab2' in global_zgrab_path:
        p2 = subprocess.Popen([global_zgrab_path, "http", "--port=80", "--max-redirects=10", "--user-agent='Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36'", "--timeout=30", "--output-file=./json_p80/p80-" + str(tnum) + ".json"], stdin=p1.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        p1.stdout.close()
        output, _ = p2.communicate()
        parts = _.decode("utf-8").split("\n")
        for entry in parts:
            if entry.startswith("{"):
                json_output = json.loads(entry)
                return json_output
        return json.loads("{}")
    else:
        p2 = subprocess.Popen([global_zgrab_path, "--port=80", "--http=/", "--http-max-redirects=10", "--http-user-agent='Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36'", "--timeout=30", "--output-file=./json_p80/p80-" + str(tnum) + ".json"], stdin=p1.stdout, stdout=subprocess.PIPE)
        p1.stdout.close()
        output, _ = p2.communicate()
        json_output = json.loads(output.decode("utf-8"))
        return json_output


def run_port_443_command(target_list, tnum):
    targets = ""
    for ip in target_list:
        targets = targets + ip + "\\n"
    targets = targets[:-2]
    p1 = subprocess.Popen(["echo", "-e", targets], stdout=subprocess.PIPE)
    if 'zgrab2' in global_zgrab_path:
        p2 = subprocess.Popen([global_zgrab_path, "http", "--port=443", "--use-https", "--max-redirects=10", "--user-agent='Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36'", "--timeout=30", "--output-file=./json_p443/p443-" + str(tnum) + ".json"], stdin=p1.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        p1.stdout.close()
        output, _ = p2.communicate()
        parts = _.decode("utf-8").split("\n")
        for entry in parts:
            if entry.startswith("{"):
                json_output = json.loads(entry)
                return json_output
        return json.loads("{}")
    else:
        p2 = subprocess.Popen([global_zgrab_path, "--port=443", "--tls", "--chrome-ciphers", "--http=/", "--http-max-redirects=10", "--http-user-agent='Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36'", "--timeout=30", "--output-file=./json_p443/p443-" + str(tnum) + ".json"], stdin=p1.stdout, stdout=subprocess.PIPE)
        p1.stdout.close()
        output, _ = p2.communicate()
        json_output = json.loads(output.decode("utf-8"))
        return json_output


def process_thread(ips, port, run_command, zones_struct, zgrab_collection, tnum):
    """
    Runs zgrab and stores the result if necessary
    """
    json_output = run_command(ips, tnum)
    if ('success_count' in json_output and json_output['success_count'] > 0) or \
        ('statuses' in json_output and json_output['statuses']['http']['successes'] > 0):
        result_file = open("./json_p" + port + "/p" + port + "-" + str(tnum) + ".json", "r")
        results=[]
        for result in result_file:
            results.append(json.loads(result))
        result_file.close()
        for result in results:
            if ('zgrab2' in global_zgrab_path and "error" in result['data']['http']) or \
                'error' in result:
                print("Failed " + port + ": " + str(result['ip']))
            else:
                result['aws'] = is_aws_ip(result['ip'], zones_struct['aws_ips'])
                result['azure'] = is_azure_ip(result['ip'], zones_struct['azure_ips'])
                result['tracked'] = is_tracked_ip(result['ip'], zones_struct['ip_zones'])
                insert_result(result, port, zones_struct['ip_context'], zones_struct['zones'], zgrab_collection)
                print("Inserted " + port + ": " + result['ip'])
    else:
        print("Failed " + port + ": " + str(ips))


def process_data(tnum, q, port, command, zones_struct, zgrab_collection):
    """
    Does the per-thread getting of a value, running the sub-function, and marking a completion.
    """
    while not global_exit_flag:
        global_queue_lock.acquire()
        if not global_work_queue.empty():
            data = []
            i = 0
            while i < 50:
                data.append(q.get())
                i = i + 1
                if global_work_queue.empty():
                    break
            global_queue_lock.release()
            print ("Thread %s processing %s" % (str(tnum), data))
            try:
                process_thread(data, port, command, zones_struct, zgrab_collection, tnum)
            except Exception as ex:
                print("Thread error processing: " + str(data))
                print(str(ex))
            for _ in range(0,i):
                q.task_done()
        else:
            global_queue_lock.release()
            time.sleep(1)


class ZgrabThread (threading.Thread):
    """
    The thread class which stores the constants for each thread.
    """
    def __init__(self, thread_id, q, port, command, zones_struct, zgrab_collection):
        threading.Thread.__init__(self)
        self.thread_id = thread_id
        self.port = port
        self.zones_struct = zones_struct
        self.zgrab_collection = zgrab_collection
        self.run_command = command
        self.q = q
    def run(self):
        print ("Starting Thread-" + str(self.thread_id))
        process_data(self.thread_id, self.q, self.port, self.run_command, self.zones_struct, self.zgrab_collection)
        print ("Exiting Thread-" + str(self.thread_id))


def check_save_location(save_location):
    """
    Check to see if the directory exists.
    If the directory does not exist, it will automatically create it.
    """
    if not os.path.exists(save_location):
        os.makedirs(save_location)


def main():
    global global_exit_flag
    global global_zgrab_path

    parser = argparse.ArgumentParser(description='Launch zgrab against IPs using port 80 or 443.')
    parser.add_argument('-p',  choices=['443', '80'], metavar="port", help='The web port: 80 or 443')
    parser.add_argument('-t',  default=5, type=int, metavar="threadCount", help='The number of threads')
    parser.add_argument('--zgrab_path', default=global_zgrab_path, metavar='zgrabVersion', help='The version of ZGrab to use')
    args = parser.parse_args()

    if args.p == None:
       print("A port value (80 or 443) must be provided.")
       exit(0)

    if is_running(os.path.basename(__file__)):
        """
        Check to see if a previous attempt to parse is still running...
        """
        now = datetime.now()
        print(str(now) + ": I am already running! Goodbye!")
        exit(0)

    now = datetime.now()
    print("Starting: " + str(now))

    rm_connector = RemoteMongoConnector.RemoteMongoConnector()
    all_dns_collection = rm_connector.get_all_dns_connection()
    jobs_manager = JobsManager.JobsManager(rm_connector, "zgrab_http_ip-" + args.p)
    jobs_manager.record_job_start()

    zones_struct = {}
    zones_struct['zones'] = ZoneManager.get_distinct_zones(rm_connector)

    zones_struct['ip_zones'] = get_ip_zones(rm_connector)

    # Collect the list of AWS CIDRs
    zones_struct['aws_ips'] = get_aws_ips(rm_connector)

    # Collect the list of Azure CIDRs
    zones_struct['azure_ips'] = get_azure_ips(rm_connector)

    (ips, ip_context) = get_ips(zones_struct['ip_zones'], all_dns_collection)
    print("Got IPs: " + str(len(ips)))
    zones_struct['ip_context'] = ip_context

    if args.p == "443":
        zgrab_collection = rm_connector.get_zgrab_443_data_connection()
        run_command = run_port_443_command
    else:
        zgrab_collection = rm_connector.get_zgrab_80_data_connection()
        run_command = run_port_80_command

    check_save_location("./json_p" + args.p)

    global_zgrab_path = args.zgrab_path

    threads = []

    print ("Creating " + str(args.t) + " threads")
    for thread_id in range (1, args.t + 1):
        thread = ZgrabThread(thread_id, global_work_queue, args.p, run_command, zones_struct, zgrab_collection)
        thread.start()
        threads.append(thread)
        thread_id += 1

    print("Populating Queue")
    global_queue_lock.acquire()
    for ip in ips:
        global_work_queue.put(ip)
    global_queue_lock.release()

    # Wait for queue to empty
    while not global_work_queue.empty():
        pass

    # Notify threads it's time to exit
    global_exit_flag = 1

    # Wait for all threads to complete
    for t in threads:
        t.join()

    print ("Exiting Main Thread")

    # Remove last week's old entries
    lastweek = datetime.now() - timedelta(days=7)
    zgrab_collection.remove({'ip': {"$ne": "<nil>"}, 'timestamp': {"$lt": lastweek}})

    jobs_manager.record_job_complete()

    now = datetime.now()
    print("Complete: " + str(now))


if __name__ == "__main__":
    main()
