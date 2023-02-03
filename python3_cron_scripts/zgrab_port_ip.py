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
This script will use ZGrab or ZGrab 2.0 for port scans of the specified ports.
It is different than the zgrab_http scripts in that it is a more basic look at the connection.
For instance, it does not follow HTTP redirects and it does not support domains as input.

With regards to sleep and batch size, the sleep is how long it will wait between batches.
Therefore, if the batch size is 50 and the sleep time is 10, then it will sleep for 10 seconds, process 50 hosts
from the queue, sleep 10 seconds, test another 50 hosts, etc.  The sleep time does not refer to how long it sleeps
between individual host connections.

The original ZGrab has been deprecated and replaced with ZGrab 2.0. This script will support using either version.
However, the version that you use in the Python scripts should match the version that you have specified in the
web server configuration. The schemas between ZGrab and ZGrab 2.0 are not compatible.

You can specify the location of ZGrab using the command line. The script assumes that paths with "zgrab2"
in them indicates that you're running ZGrab 2.0. Otherwise, it will assume that you are running the original
ZGrab.

Please note that this script assumes that a "./json_p{#}" directory exists for the port that you are scanning.
If it does not exist, then this script will create it.

https://github.com/zmap/zgrab
https://github.com/zmap/zgrab2
"""

import argparse
import json
import logging
import os
import queue
import random
import subprocess
import threading
import time
from datetime import datetime, timedelta

from bson.objectid import ObjectId
from dateutil.parser import parse
from libs3 import IPManager, JobsManager, RemoteMongoConnector
from libs3.LoggingUtil import LoggingUtil
from libs3.ZoneManager import ZoneManager

# Globals that need to maintain consistency between threads.
global_exit_flag = 0
global_queue_lock = threading.Lock()
global_work_queue = queue.Queue()
global_queue_size = 50
global_sleep_time = 0
global_zgrab_path = "./zgrab/src/github.com/zmap/zgrab2/zgrab2"
global_port_names = {
    "22": "ssh",
    "25": "smtp",
    "80": "http",
    "443": "tls",
    "465": "smtp",
}


def is_running(process):
    """
    Is the provided process name is currently running?
    """
    proc_list = subprocess.Popen(["pgrep", "-f", process], stdout=subprocess.PIPE)
    for proc in proc_list.stdout:
        if proc.decode("utf-8").rstrip() != str(os.getpid()) and proc.decode(
            "utf-8"
        ).rstrip() != str(os.getppid()):
            return True
    return False


def get_mx_ips(zones, ip_manager, all_dns_collection):
    """
    Get hosts identified via MX records for SMTP scans.
    Zgrab works on IPs and MX records are typically domain names.
    Therefore, we use the all_dns table to lookup up the IP address for the record.
    """

    ips = set([])
    ip_context = []

    mx_results = all_dns_collection.find({"type": "mx", "zone": {"$ne": ""}})

    for result in mx_results:
        record = result["value"]
        if " " in result["value"]:
            parts = result["value"].split(" ")
            record = parts[1]
            if record.endswith("."):
                record = record[:-1]

        if zone_compare(record, zones) is not None:
            ip_results = all_dns_collection.find({"fqdn": record})
            for result in ip_results:
                if result["type"] == "a":
                    if not ip_manager.is_local_ip(result["value"]):
                        ips.add(result["value"])
                        ip_context.append(
                            {
                                "ip": result["value"],
                                "domain": result["fqdn"],
                                "source": "all_dns",
                                "zone": result["zone"],
                            }
                        )
                elif result["type"] == "cname":
                    if zone_compare(result["value"], zones):
                        second_results = all_dns_collection.find(
                            {"fqdn": result["value"]}
                        )
                        for s_result in second_results:
                            if s_result["type"] == "a":
                                if not ip_manager.is_local_ip(s_result["value"]):
                                    ips.add(s_result["value"])
                                    ip_context.append(
                                        {
                                            "ip": s_result["value"],
                                            "domain": s_result["fqdn"],
                                            "source": "all_dns",
                                            "zone": s_result["zone"],
                                        }
                                    )

    # Don't want to look like a network scan
    # Set doesn't support random.shuffle
    ips_list = list(ips)
    random.shuffle(ips_list)

    return (ips_list, ip_context)


def get_only_ipzones(ip_zones):
    """
    Get the list of IPs from IP zones to limit the scans to data centers
    """
    ips = set([])
    ip_context = []

    for ipz in ip_zones:
        if ipz.version == 4:
            for ip in ipz:
                if ip != ipz.network and ip != ipz.broadcast:
                    ips.add(str(ip))

    # Don't want to look like a network scan
    # Set doesn't support random.shuffle
    ips_list = list(ips)
    random.shuffle(ips_list)

    return (ips_list, ip_context)


def get_ips(ip_manager, all_dns_collection):
    """
    Get the list of all IPs that are being tracked by Marinus.
    """
    ips = set([])
    ip_context = []

    domain_results = all_dns_collection.find({"type": "a", "zone": {"$ne": ""}})
    for result in domain_results:
        if not ip_manager.is_local_ip(result["value"]):
            ips.add(result["value"])
            ip_context.append(
                {
                    "ip": result["value"],
                    "domain": result["fqdn"],
                    "source": "all_dns",
                    "zone": result["zone"],
                }
            )

    for ipz in ip_manager.Tracked_CIDRs:
        if ipz.version == 4:
            for ip in ipz:
                if ip != ipz.network and ip != ipz.broadcast:
                    ips.add(str(ip))

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
        if entry["ip"] == ip:
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

    try:
        certificate = entry["server_certificates"]["certificate"]
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


def insert_result(entry, port, ip_context, all_zones, results_collection):
    """
    Insert the matched domain into the collection of positive results.
    """
    if "zgrab2" in global_zgrab_path:
        temp_date = entry["data"][global_port_names[port]]["timestamp"]
        new_date = parse(temp_date)
        entry["timestamp"] = new_date
        entry["data"][global_port_names[port]]["timestamp"] = new_date
    else:
        temp_date = entry["timestamp"]
        new_date = parse(temp_date)
        entry["timestamp"] = new_date

    # Returns all entries in ip_context that contain the given IP
    matches = check_ip_context(entry["ip"], ip_context)

    # Grab the zones from the ip_context
    zones = []
    domains = []
    if len(matches) > 0:
        for match in matches:
            if match["zone"] not in zones:
                zones.append(match["zone"])
            if match["domain"] not in domains:
                domains.append(match["domain"])

    # Append the zones from the TLS certificate
    if port == "443":
        # Make the timestamp an actual date instead of a string
        entry["data"]["tls"]["timestamp"] = new_date

        if "zgrab2" in global_zgrab_path:
            cert_zones = check_in_zone(
                entry["data"]["tls"]["result"]["handshake_log"], all_zones
            )
        else:
            cert_zones = check_in_zone(entry["data"]["tls"], all_zones)
        for zone in cert_zones:
            if zone not in zones:
                zones.append(zone)
    elif port == "22":
        if "zgrab2" in global_zgrab_path:
            entry["data"]["ssh"]["timestamp"] = new_date
        else:
            entry["data"]["xssh"]["timestamp"] = new_date
    elif port == "25":
        if "zgrab2" in global_zgrab_path:
            if "tls" in entry["data"]["smtp"]["result"]:
                cert_zones = check_in_zone(
                    entry["data"]["smtp"]["result"]["tls"]["handshake_log"], all_zones
                )
                for zone in cert_zones:
                    if zone not in zones:
                        zones.append(zone)
        else:
            temp = entry["data"]
            entry["data"] = {}
            entry["data"]["smtp"] = temp
            entry["data"]["smtp"]["timestamp"] = new_date

            if "tls" in entry["data"]["smtp"]:
                cert_zones = check_in_zone(
                    entry["data"]["smtp"]["tls"]["response"], all_zones
                )
                for zone in cert_zones:
                    if zone not in zones:
                        zones.append(zone)
    elif port == "465":
        temp = entry["data"].pop("smtp")
        entry["data"]["smtps"] = temp

        if "zgrab2" in global_zgrab_path:
            if "tls" in entry["data"]["smtps"]["result"]:
                cert_zones = check_in_zone(
                    entry["data"]["smtps"]["result"]["tls"]["handshake_log"], all_zones
                )
                for zone in cert_zones:
                    if zone not in zones:
                        zones.append(zone)
        else:
            temp = entry["data"]
            entry["data"] = {}
            entry["data"]["smtps"] = temp
            entry["data"]["smtps"]["timestamp"] = new_date
            if "tls" in entry["data"]["smtps"]:
                cert_zones = check_in_zone(entry["data"]["smtps"]["tls"], all_zones)
                for zone in cert_zones:
                    if zone not in zones:
                        zones.append(zone)

    entry["zones"] = zones
    entry["domains"] = domains

    exists = results_collection.count_documents({"ip": entry["ip"]})

    if exists == 0:
        results_collection.insert_one(entry)
    elif port == "443":
        results_collection.update_one(
            {"ip": entry["ip"]},
            {
                "$set": {
                    "data.tls": entry["data"]["tls"],
                    "timestamp": entry["timestamp"],
                }
            },
        )
    elif port == "22":
        if "zgrab2" in global_zgrab_path:
            results_collection.update_one(
                {"ip": entry["ip"]},
                {
                    "$set": {
                        "data.ssh": entry["data"]["ssh"],
                        "timestamp": entry["timestamp"],
                    }
                },
            )
        else:
            results_collection.update_one(
                {"ip": entry["ip"]},
                {
                    "$set": {
                        "data.xssh": entry["data"]["xssh"],
                        "timestamp": entry["timestamp"],
                    }
                },
            )
    elif port == "25":
        results_collection.update_one(
            {"ip": entry["ip"]},
            {
                "$set": {
                    "data.smtp": entry["data"]["smtp"],
                    "timestamp": entry["timestamp"],
                }
            },
        )
    elif port == "465":
        results_collection.update_one(
            {"ip": entry["ip"]},
            {
                "$set": {
                    "data.smtps": entry["data"]["smtps"],
                    "timestamp": entry["timestamp"],
                }
            },
        )


def run_port_22_command(target_list, tnum):
    """
    Use Zgrab to make an SSH connection
    """
    if global_sleep_time > 0:
        time.sleep(global_sleep_time)

    targets = ""
    for ip in target_list:
        targets = targets + ip + "\\n"
    targets = targets[:-2]
    p1 = subprocess.Popen(["echo", "-e", targets], stdout=subprocess.PIPE)
    if "zgrab2" in global_zgrab_path:
        p2 = subprocess.Popen(
            [
                global_zgrab_path,
                "ssh",
                "--port=22",
                "--verbose",
                "--timeout=30",
                "--output-file=./json_p22/p22-" + str(tnum) + ".json",
            ],
            stdin=p1.stdout,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        p1.stdout.close()
        output, _ = p2.communicate()
        parts = _.decode("utf-8").split("\n")
        for entry in parts:
            if entry.startswith("{"):
                json_output = json.loads(entry)
                return json_output
        return json.loads("{}")
    else:
        p2 = subprocess.Popen(
            [
                global_zgrab_path,
                "--port=22",
                "--xssh",
                "--xssh-verbose",
                "-banners",
                "--timeout=30",
                "--output-file=./json_p22/p22-" + str(tnum) + ".json",
            ],
            stdin=p1.stdout,
            stdout=subprocess.PIPE,
        )
        p1.stdout.close()
        output, _ = p2.communicate()
        json_output = json.loads(output.decode("utf-8"))
        return json_output


def run_port_25_command(target_list, tnum):
    """
    Use Zgrab to attempt an SMTP connection with StartTLS
    """
    if global_sleep_time > 0:
        time.sleep(global_sleep_time)

    targets = ""
    for ip in target_list:
        targets = targets + ip + "\\n"
    targets = targets[:-2]
    p1 = subprocess.Popen(["echo", "-e", targets], stdout=subprocess.PIPE)
    if "zgrab2" in global_zgrab_path:
        p2 = subprocess.Popen(
            [
                global_zgrab_path,
                "smtp",
                "--port=25",
                "--starttls",
                "--timeout=30",
                "--output-file=./json_p25/p25-" + str(tnum) + ".json",
            ],
            stdin=p1.stdout,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        p1.stdout.close()
        output, _ = p2.communicate()
        parts = _.decode("utf-8").split("\n")
        for entry in parts:
            if entry.startswith("{"):
                json_output = json.loads(entry)
                return json_output
        return json.loads("{}")
    else:
        p2 = subprocess.Popen(
            [
                global_zgrab_path,
                "--port=25",
                "--smtp",
                "--starttls",
                "--banners",
                "--timeout=30",
                "--output-file=./json_p25/p25-" + str(tnum) + ".json",
            ],
            stdin=p1.stdout,
            stdout=subprocess.PIPE,
        )
        p1.stdout.close()
        output, _ = p2.communicate()
        json_output = json.loads(output.decode("utf-8"))
        return json_output


def run_port_25_no_tls_command(target_list, tnum):
    """
    Use Zgrab to attempt an connection on port 25 without using StartTLS
    """
    if global_sleep_time > 0:
        time.sleep(global_sleep_time)

    targets = ""
    for ip in target_list:
        targets = targets + ip + "\\n"
    targets = targets[:-2]
    p1 = subprocess.Popen(["echo", "-e", targets], stdout=subprocess.PIPE)
    if "zgrab2" in global_zgrab_path:
        p2 = subprocess.Popen(
            [
                global_zgrab_path,
                "smtp",
                "--port=25",
                "--timeout=30",
                "--output-file=./json_p25/p25-" + str(tnum) + ".json",
            ],
            stdin=p1.stdout,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        p1.stdout.close()
        output, _ = p2.communicate()
        parts = _.decode("utf-8").split("\n")
        for entry in parts:
            if entry.startswith("{"):
                json_output = json.loads(entry)
                return json_output
        return json.loads("{}")
    else:
        p2 = subprocess.Popen(
            [
                global_zgrab_path,
                "--port=25",
                "--smtp",
                "--banners",
                "--timeout=30",
                "--output-file=./json_p25/p25-" + str(tnum) + ".json",
            ],
            stdin=p1.stdout,
            stdout=subprocess.PIPE,
        )
        p1.stdout.close()
        output, _ = p2.communicate()
        json_output = json.loads(output.decode("utf-8"))
        return json_output


def run_port_443_command(target_list, tnum):
    """
    Use ZGrab to do a simple HTTPS connection.
    None of the fancier HTTP connection options are used (e.g. follow redirects)
    """
    if global_sleep_time > 0:
        time.sleep(global_sleep_time)

    targets = ""
    for ip in target_list:
        targets = targets + ip + "\\n"
    targets = targets[:-2]
    p1 = subprocess.Popen(["echo", "-e", targets], stdout=subprocess.PIPE)
    if "zgrab2" in global_zgrab_path:
        p2 = subprocess.Popen(
            [
                global_zgrab_path,
                "tls",
                "--port=443",
                "--timeout=30",
                "--output-file=./json_p443/p443-" + str(tnum) + ".json",
            ],
            stdin=p1.stdout,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        p1.stdout.close()
        output, _ = p2.communicate()
        parts = _.decode("utf-8").split("\n")
        for entry in parts:
            if entry.startswith("{"):
                json_output = json.loads(entry)
                return json_output
        return json.loads("{}")
    else:
        p2 = subprocess.Popen(
            [
                global_zgrab_path,
                "--port=443",
                "--tls",
                "--chrome-ciphers",
                "--timeout=30",
                "--output-file=./json_p443/p443-" + str(tnum) + ".json",
            ],
            stdin=p1.stdout,
            stdout=subprocess.PIPE,
        )
        p1.stdout.close()
        output, _ = p2.communicate()
        json_output = json.loads(output.decode("utf-8"))
        return json_output


def run_port_465_command(target_list, tnum):
    """
    Use ZGrab to test for SMTPS on port 465
    """
    if global_sleep_time > 0:
        time.sleep(global_sleep_time)

    targets = ""
    for ip in target_list:
        targets = targets + ip + "\\n"
    targets = targets[:-2]
    p1 = subprocess.Popen(["echo", "-e", targets], stdout=subprocess.PIPE)
    if "zgrab2" in global_zgrab_path:
        p2 = subprocess.Popen(
            [
                global_zgrab_path,
                "smtp",
                "--port=465",
                "--smtps",
                "--timeout=30",
                "--output-file=./json_p465/p465-" + str(tnum) + ".json",
            ],
            stdin=p1.stdout,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        p1.stdout.close()
        output, _ = p2.communicate()
        parts = _.decode("utf-8").split("\n")
        for entry in parts:
            if entry.startswith("{"):
                json_output = json.loads(entry)
                return json_output
        return json.loads("{}")
    else:
        p2 = subprocess.Popen(
            [
                global_zgrab_path,
                "--port=465",
                "--smtp",
                "--tls",
                "--banners",
                "--timeout=30",
                "--output-file=./json_p465/p465-" + str(tnum) + ".json",
            ],
            stdin=p1.stdout,
            stdout=subprocess.PIPE,
        )
        p1.stdout.close()
        output, _ = p2.communicate()
        json_output = json.loads(output.decode("utf-8"))
        return json_output


def process_thread(
    logger, ips, port, run_command, zones_struct, zgrab_collection, tnum
):
    """
    Runs zgrab and stores the result if necessary
    """
    json_output = run_command(ips, tnum)

    if ("success_count" in json_output and json_output["success_count"] > 0) or (
        "statuses" in json_output
        and json_output["statuses"][global_port_names[port]]["successes"] > 0
    ):
        result_file = open(
            "./json_p" + port + "/p" + port + "-" + str(tnum) + ".json", "r"
        )
        results = []
        for result in result_file:
            results.append(json.loads(result))
        result_file.close()
        for result in results:
            if (
                "zgrab2" in global_zgrab_path
                and "error" in result["data"][global_port_names[port]]
            ) or "error" in result:
                if port == "25":
                    if (
                        (
                            "zgrab2" in global_zgrab_path
                            and "result" in result["data"]["smtp"]
                            and "starttls" in result["data"]["smtp"]["result"]
                        )
                        or "error_component" in result
                        and result["error_component"] == "starttls"
                    ):
                        logger.debug("Adding " + str(result["ip"]) + " to retest list")
                        global_retest_list.append(result["ip"])
                    else:
                        logger.warning("Failed " + port + ": " + str(result["ip"]))
                else:
                    logger.warning("Failed " + port + ": " + str(result["ip"]))
            else:
                result["aws"] = zones_struct["ip_manager"].is_aws_ip(result["ip"])
                result["azure"] = zones_struct["ip_manager"].is_azure_ip(result["ip"])
                result["gcp"] = zones_struct["ip_manager"].is_gcp_ip(result["ip"])
                result["tracked"] = zones_struct["ip_manager"].is_tracked_ip(
                    result["ip"]
                )
                insert_result(
                    result,
                    port,
                    zones_struct["ip_context"],
                    zones_struct["zones"],
                    zgrab_collection,
                )
                logger.debug("Inserted " + port + ": " + result["ip"])
    else:
        logger.warning("Failed " + port + ": " + str(ips))


def process_data(logger, tnum, q, port, command, zones_struct, zgrab_collection):
    """
    Does the per-thread getting of a value, running the sub-function, and marking a completion.
    None of the global variables are assigned locally in order to ensure a global reference.
    """

    while not global_exit_flag:
        global_queue_lock.acquire()
        if not global_work_queue.empty():
            data = []
            i = 0
            while i < global_queue_size:
                data.append(q.get())
                i = i + 1
                if global_work_queue.empty():
                    break
            global_queue_lock.release()
            logger.debug("Thread %s processing %s" % (str(tnum), data))
            try:
                process_thread(
                    logger, data, port, command, zones_struct, zgrab_collection, tnum
                )
            except Exception as ex:
                logger.warning("Thread error processing: " + str(data))
                logger.warning(str(ex))
            for _ in range(0, i):
                q.task_done()
        else:
            global_queue_lock.release()
            time.sleep(1)


class ZgrabThread(threading.Thread):
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
        self.logger = LoggingUtil.create_log(__name__)

    def run(self):
        self.logger.debug("Starting Thread-" + str(self.thread_id))
        process_data(
            self.logger,
            self.thread_id,
            self.q,
            self.port,
            self.run_command,
            self.zones_struct,
            self.zgrab_collection,
        )
        self.logger.debug("Exiting Thread-" + str(self.thread_id))


def check_save_location(save_location):
    """
    Check to see if the directory exists.
    If the directory does not exist, it will automatically create it.
    """
    if not os.path.exists(save_location):
        os.makedirs(save_location)


def main(logger=None):
    """
    Beging Main...
    """
    global global_exit_flag
    global global_retest_list
    global global_sleep_time
    global global_queue_size
    global global_zgrab_path

    if logger is None:
        logger = LoggingUtil.create_log(__name__)

    global_retest_list = []

    parser = argparse.ArgumentParser(
        description="Launch zgrab against IPs using port 22, 25, 443, or 465."
    )
    parser.add_argument(
        "-p",
        choices=["22", "25", "443", "465"],
        metavar="port",
        help="The port to scan: 22, 25, 443, or 465",
    )
    parser.add_argument(
        "-t", default=5, type=int, metavar="threadCount", help="The number of threads"
    )
    parser.add_argument(
        "--mx",
        action="store_true",
        help="Scan only IPs from MX records. Useful for SMTP scans.",
    )
    parser.add_argument(
        "-s",
        default=0,
        type=int,
        metavar="sleepTime",
        help="Sleep time in order to spread out the batches",
    )
    parser.add_argument(
        "--qs",
        default=0,
        type=int,
        metavar="queueSize",
        help="How many hosts to scan in a batch",
    )
    parser.add_argument(
        "--zones_only", action="store_true", help="Scan only IPs from IP zones."
    )
    parser.add_argument(
        "--zgrab_path",
        default=global_zgrab_path,
        metavar="zgrabVersion",
        help="The version of ZGrab to use",
    )
    args = parser.parse_args()

    if args.p == None:
        logger.error("A port value (22, 25, 443, or 465) must be provided.")
        exit(1)

    if is_running(os.path.basename(__file__)):
        """
        Check to see if a previous attempt to parse is still running...
        """
        now = datetime.now()
        logger.warning(str(now) + ": I am already running! Goodbye!")
        exit(0)

    now = datetime.now()
    print("Starting: " + str(now))
    logger.info("Starting...")

    rm_connector = RemoteMongoConnector.RemoteMongoConnector()
    all_dns_collection = rm_connector.get_all_dns_connection()
    ip_manager = IPManager.IPManager(rm_connector, True)

    jobs_manager = JobsManager.JobsManager(rm_connector, "zgrab_port_ip-" + args.p)
    jobs_manager.record_job_start()

    zones_struct = {}
    zones_struct["zones"] = ZoneManager.get_distinct_zones(rm_connector)

    # Not pretty but works
    zones_struct["ip_manager"] = ip_manager

    if args.mx:
        (ips, ip_context) = get_mx_ips(
            zones_struct["zones"], ip_manager, all_dns_collection
        )
    elif args.zones_only:
        (ips, ip_context) = get_only_ipzones(ip_manager.Tracked_CIDRs)
    else:
        (ips, ip_context) = get_ips(ip_manager, all_dns_collection)

    if args.s and int(args.s) > 0:
        global_sleep_time = int(args.s)

    if args.qs and int(args.qs) > 0:
        global_queue_size = int(args.qs)

    logger.info("Got IPs: " + str(len(ips)))
    zones_struct["ip_context"] = ip_context

    zgrab_collection = rm_connector.get_zgrab_port_data_connection()
    if args.p == "443":
        run_command = run_port_443_command
    elif args.p == "22":
        run_command = run_port_22_command
    elif args.p == "25":
        run_command = run_port_25_command
    elif args.p == "465":
        run_command = run_port_465_command

    check_save_location("./json_p" + args.p)

    global_zgrab_path = args.zgrab_path

    threads = []

    logger.debug("Creating " + str(args.t) + " threads")
    for thread_id in range(1, args.t + 1):
        thread = ZgrabThread(
            thread_id,
            global_work_queue,
            args.p,
            run_command,
            zones_struct,
            zgrab_collection,
        )
        thread.start()
        threads.append(thread)
        thread_id += 1

    logger.info("Populating Queue")
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

    logger.info("Exiting Main Thread")

    logger.info("Global retest list: " + str(len(global_retest_list)))

    # Retest any SMTP hosts that did not respond to the StartTLS handshake
    if args.p == "25" and len(global_retest_list) > 0:
        process_thread(
            logger,
            global_retest_list,
            args.p,
            run_port_25_no_tls_command,
            zones_struct,
            zgrab_collection,
            "retest",
        )

    # Remove old entries from before the scan
    if args.p == "443":
        other_results = zgrab_collection.find(
            {"data.tls": {"$exists": True}, "data.tls.timestamp": {"$lt": now}}
        )
        for result in other_results:
            zgrab_collection.update_one(
                {"_id": ObjectId(result["_id"])}, {"$unset": {"data.tls": ""}}
            )
    elif args.p == "22":
        if "zgrab2" in global_zgrab_path:
            other_results = zgrab_collection.find(
                {"data.ssh": {"$exists": True}, "data.ssh.timestamp": {"$lt": now}}
            )
            for result in other_results:
                zgrab_collection.update_one(
                    {"_id": ObjectId(result["_id"])}, {"$unset": {"data.ssh": ""}}
                )
        else:
            other_results = zgrab_collection.find(
                {"data.xssh": {"$exists": True}, "data.xssh.timestamp": {"$lt": now}}
            )
            for result in other_results:
                zgrab_collection.update_one(
                    {"_id": ObjectId(result["_id"])}, {"$unset": {"data.xssh": ""}}
                )
    elif args.p == "25":
        other_results = zgrab_collection.find(
            {"data.smtp": {"$exists": True}, "data.smtp.timestamp": {"$lt": now}}
        )
        for result in other_results:
            zgrab_collection.update_one(
                {"_id": ObjectId(result["_id"])}, {"$unset": {"data.smtp": ""}}
            )
    elif args.p == "465":
        other_results = zgrab_collection.find(
            {"data.smtps": {"$exists": True}, "data.smtps.timestamp": {"$lt": now}}
        )
        for result in other_results:
            zgrab_collection.update_one(
                {"_id": ObjectId(result["_id"])}, {"$unset": {"data.smtps": ""}}
            )

    # Remove any completely empty entries
    zgrab_collection.delete_many({"data": {}})

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
