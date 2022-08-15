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
This script leverages the ZGrab or ZGrab 2.0 tool to record responses of HTTP requests made to domains.
It is a complement to the zgrab_http_ip tool which records responses of HTTP requests made to IPs.
This script attempts HTTP connections over port 80 and HTTPS connections over port 443.

This script was originally based on the "ZGrab" project which has been deprecated and replaced
with "ZGrab 2.0". When building ZGrab 2.0, you may also need to install: "go get gopkg.in/mgo.v2/bson"
in addition to "go get github.com/zmap/zgrab2."

Please note that this script assumes that a "./json_p{#}" directory exists for the port that you are scanning.
If it does not exist, then this script will create the directory.

You can specify the location of ZGrab using the command line. The script assumes that paths with "zgrab2"
in them indicates that you're running ZGrab 2.0. Otherwise, it will assume that you are running the original
ZGrab.

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

from dateutil.parser import parse
from libs3 import IPManager, JobsManager, RemoteMongoConnector
from libs3.LoggingUtil import LoggingUtil
from libs3.ZoneManager import ZoneManager

# Constants for the threads
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
        if proc.decode("utf-8").rstrip() != str(os.getpid()) and proc.decode(
            "utf-8"
        ).rstrip() != str(os.getppid()):
            return True
    return False


def get_domains(all_dns_collection, ip_manager, zone):
    """
    Get the list of domains based on zones
    """
    zone_results = all_dns_collection.find({"zone": zone, "type": "a"})

    domains = []
    for result in zone_results:
        if result["fqdn"] not in domains and not ip_manager.is_local_ip(
            result["value"]
        ):
            domains.append(result["fqdn"])

    random.shuffle(domains)
    return domains


def insert_result(entry, results_collection):
    """
    Insert the matched domain into the collection of positive results.
    """
    if "zgrab2" in global_zgrab_path:
        temp_date = entry["data"]["http"]["timestamp"]
        new_date = parse(temp_date)
        entry["timestamp"] = new_date
        entry["data"]["http"]["timestamp"] = new_date
        entry["ip"] = "<nil>"
    else:
        temp_date = entry["timestamp"]
        new_date = parse(temp_date)
        entry["timestamp"] = new_date

    results_collection.replace_one({"domain": entry["domain"]}, entry, upsert=True)


def run_port_80_command(target_list, tnum):
    """
    Run Zgrab using HTTP on port 80
    """
    targets = ""
    for domain in target_list:
        targets = targets + domain + "\\n"
    targets = targets[:-2]

    p1 = subprocess.Popen(["echo", "-e", targets], stdout=subprocess.PIPE)
    if "zgrab2" in global_zgrab_path:
        p2 = subprocess.Popen(
            [
                global_zgrab_path,
                "http",
                "--port=80",
                "--max-redirects=10",
                "--timeout=30",
                "--output-file=./json_p80/p80-" + str(tnum) + ".json",
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
                "--port=80",
                "--http=/",
                "--http-max-redirects=10",
                "--lookup-domain",
                "--timeout=30",
                "--output-file=./json_p80/p80-" + str(tnum) + ".json",
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
    Run Zgrab using HTTPS on port 443
    """
    targets = ""
    for domain in target_list:
        targets = targets + domain + "\\n"
    targets = targets[:-2]

    p1 = subprocess.Popen(["echo", "-e", targets], stdout=subprocess.PIPE)
    if "zgrab2" in global_zgrab_path:
        p2 = subprocess.Popen(
            [
                global_zgrab_path,
                "http",
                "--port=443",
                "--use-https",
                "--max-redirects=10",
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
                "--http=/",
                "--http-max-redirects=10",
                "--lookup-domain",
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


def process_thread(logger, domains, port, run_command, zone, zgrab_collection, tnum):
    """
    Runs zgrab and stores the result if necessary
    """
    json_output = run_command(domains, tnum)
    if ("success_count" in json_output and json_output["success_count"] > 0) or (
        "statuses" in json_output and json_output["statuses"]["http"]["successes"] > 0
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
                "zgrab2" in global_zgrab_path and "error" in result["data"]["http"]
            ) or "error" in result:
                logger.warning("Failed " + port + ": " + str(result["domain"]))
            else:
                result["zones"] = [zone]
                insert_result(result, zgrab_collection)
                logger.debug("Inserted " + port + ": " + result["domain"])
    else:
        logger.warning("Failed " + port + ": " + str(domains))


def process_data(logger, tnum, q, port, command, zone, zgrab_collection):
    """
    Does the per-thread getting of value, running the sub-function, and marking a completion.
    """
    while not global_exit_flag:
        global_queue_lock.acquire()
        if not global_work_queue.empty():
            data = []
            i = 0
            while i < 5:
                data.append(q.get())
                i = i + 1
                if global_work_queue.empty():
                    break
            global_queue_lock.release()
            logger.debug("Thread %s processing %s" % (str(tnum), str(data)))
            try:
                process_thread(
                    logger, data, port, command, zone, zgrab_collection, tnum
                )
            except Exception as ex:
                logger.error("Thread error processing: " + str(data))
                logger.error(str(ex))
            for _ in range(0, i):
                q.task_done()
        else:
            global_queue_lock.release()
            time.sleep(1)


class ZgrabThread(threading.Thread):
    """
    The thread class which stores the constants for each thread.
    """

    def __init__(self, thread_id, q, port, command, zone, zgrab_collection):
        threading.Thread.__init__(self)
        self.thread_id = thread_id
        self.port = port
        self.zgrab_collection = zgrab_collection
        self.zone = zone
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
            self.zone,
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
    Begin Main...
    """
    global global_exit_flag
    global global_zgrab_path

    if logger is None:
        logger = LoggingUtil.create_log(__name__)

    parser = argparse.ArgumentParser(
        description="Launch zgrab against domains using port 80 or 443."
    )
    parser.add_argument(
        "-p", choices=["443", "80"], metavar="port", help="The web port: 80 or 443"
    )
    parser.add_argument(
        "-t", default=5, type=int, metavar="threadCount", help="The number of threads"
    )
    parser.add_argument(
        "--zgrab_path",
        default=global_zgrab_path,
        metavar="zgrabVersion",
        help="The version of ZGrab to use",
    )
    args = parser.parse_args()

    if args.p == None:
        logger.error("A port value (80 or 443) must be provided.")
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
    jobs_manager = JobsManager.JobsManager(rm_connector, "zgrab_http_domain-" + args.p)
    jobs_manager.record_job_start()

    if args.p == "443":
        zgrab_collection = rm_connector.get_zgrab_443_data_connection()
        run_command = run_port_443_command
    else:
        zgrab_collection = rm_connector.get_zgrab_80_data_connection()
        run_command = run_port_80_command

    check_save_location("./json_p" + args.p)

    global_zgrab_path = args.zgrab_path

    zones = ZoneManager.get_distinct_zones(rm_connector)
    ip_manager = IPManager.IPManager(rm_connector)

    for zone in zones:
        global_exit_flag = 0

        domains = get_domains(all_dns_collection, ip_manager, zone)

        if len(domains) == 0:
            continue

        num_threads = args.t
        if len(domains) < args.t:
            num_threads = len(domains)

        logger.debug("Creating " + str(num_threads) + " threads")

        threads = []
        for thread_id in range(1, num_threads + 1):
            thread = ZgrabThread(
                thread_id,
                global_work_queue,
                args.p,
                run_command,
                zone,
                zgrab_collection,
            )
            thread.start()
            threads.append(thread)
            thread_id += 1

        logger.debug(zone + " length: " + str(len(domains)))

        logger.info("Populating Queue")
        global_queue_lock.acquire()
        for domain in domains:
            global_work_queue.put(domain)
        global_queue_lock.release()

        # Wait for queue to empty
        while not global_work_queue.empty():
            pass

        logger.info("Queue empty")
        # Notify threads it's time to exit
        global_exit_flag = 1

        # Wait for all threads to complete
        for t in threads:
            t.join()

    # Remove last week's old entries
    lastweek = datetime.now() - timedelta(days=7)
    zgrab_collection.delete_many(
        {"domain": {"$ne": "<nil>"}, "timestamp": {"$lt": lastweek}}
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
