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
This script is responsible for creating the visual graphs of tracked networks.
The networkx library is responsible for de-duplicating entries and creating the structure.
There is additional properties that are attached for the downstream d3.js code for code rendering.
It could use some clean up but it needs to be done in conjection with the d3.js rendering code.
This code is just for tracked domains. It does not do graphs of third party domains.

Note: Technically, a TLD is ".com" or ".org". However, the python module used in other scripts
originally considered a TLD to be "example.org". For that legacy reason, "tld" is used to refer
to the root domain.

This script should be run after all the data generating scripts have completed.
"""
import json
import logging
import math
import re
import time
from datetime import datetime, timedelta

import networkx as nx
from libs3 import DNSManager, IPManager, JobsManager, MongoConnector
from libs3.LoggingUtil import LoggingUtil
from libs3.ZoneManager import ZoneManager
from networkx.readwrite import json_graph

# Constant for dealing with Mongo not allowing "." in key names
REPLACE_CHAR = "!"


def add_to_list(str_to_add, groups):
    """
    This will add a string to the groups array if it does not exist.
    It will then return the index of the string within the Array
    """
    if str_to_add.replace(".", REPLACE_CHAR) not in groups:
        groups.append(str_to_add.replace(".", REPLACE_CHAR))
    return groups.index(str_to_add.replace(".", REPLACE_CHAR))


def create_list_of_cidrs(groups, mongo_connector, dns_manager):
    """
    Get the list of all Class C Networks known by Marinus
    """
    srdns_collection = mongo_connector.get_sonar_reverse_dns_connection()
    rdns_results = srdns_collection.find({}, {"ip": 1})
    for result in rdns_results:
        temp = result["ip"].split(".")
        ip_group = ".".join(temp[:-1])
        add_to_list(ip_group, groups)

    dns_results = dns_manager.find_multiple({"type": "a"}, None)
    for result in dns_results:
        temp = result["value"].split(".")
        ip_group = ".".join(temp[:-1])
        add_to_list(ip_group, groups)

    censys_collection = mongo_connector.get_censys_connection()
    censys_results = censys_collection.find({}, {"ip": 1})
    for result in censys_results:
        temp = result["ip"].split(".")
        ip_group = ".".join(temp[:-1])
        add_to_list(ip_group, groups)


def create_network_data_sets(groups, mongo_connector):
    """
    Group results based on network type ("Tracked", "AWS", or "Akamai")
    """
    group_data = {}
    group_data["aws_count"] = 0
    group_data["tracked_count"] = 0
    group_data["akamai_count"] = 0
    group_data["azure_count"] = 0
    group_data["gcp_count"] = 0

    ip_manager = IPManager.IPManager(mongo_connector)

    for group in groups:
        cidr = group.replace(REPLACE_CHAR, ".")
        fake_ip = cidr + ".1"
        group_data[group] = {}
        group_data[group]["class_c"] = cidr
        if ip_manager.is_aws_ip(fake_ip):
            group_data[group]["aws"] = True
            group_data["aws_count"] = group_data["aws_count"] + 1
        else:
            group_data[group]["aws"] = False

        if ip_manager.is_azure_ip(fake_ip):
            group_data[group]["azure"] = True
            group_data["azure_count"] = group_data["azure_count"] + 1
        else:
            group_data[group]["azure"] = False

        if ip_manager.is_akamai_ip(fake_ip):
            group_data["akamai_count"] = group_data["akamai_count"] + 1
            group_data[group]["akamai"] = True
        else:
            group_data[group]["akamai"] = False

        if ip_manager.is_tracked_ip(fake_ip):
            group_data[group]["tracked"] = True
            group_data["tracked_count"] = group_data["tracked_count"] + 1
        else:
            group_data[group]["tracked"] = False

        if ip_manager.is_gcp_ip(fake_ip):
            group_data[group]["gcp"] = True
            group_data["gcp_count"] = group_data["gcp_count"] + 1
        else:
            group_data[group]["gcp"] = False

    return group_data


def find_all_dns_by_zone(graph, ipzone, groups, dns_manager):
    """
    Collect all the DNS records for the provided zone and add them to NetworkX graph
    """
    temp = ipzone.split(".")
    regex_str = "^" + temp[0] + "\\." + temp[1] + "\\." + temp[2] + ".*"
    regx = re.compile(regex_str)
    dns_results = dns_manager.find_multiple(
        {"type": "a", "value": {"$regex": regx}}, None
    )

    for result in dns_results:
        zone = result["zone"]
        zone_g_index = add_to_list(zone, groups)

        graph.add_node(
            result["value"],
            data_type="ip",
            type=0,
            depends=[ipzone],
            dependedOnBy=[result["fqdn"]],
            docs="",
        )

        if str(result["fqdn"]) != zone and zone != "":
            graph.add_node(
                zone,
                data_type="tld",
                type=zone_g_index,
                depends=[result["fqdn"].replace("." + zone, "")],
                dependedOnBy=[],
                docs="",
            )
            graph.add_node(
                result["fqdn"].replace("." + zone, ""),
                data_type="domain",
                type=zone_g_index,
                depends=[result["value"]],
                dependedOnBy=[zone],
                docs="",
            )
        elif zone == "":
            graph.add_node(
                result["fqdn"],
                data_type="domain",
                type=zone_g_index,
                depends=[result["value"]],
                dependedOnBy=[],
                docs="",
            )
        else:
            graph.add_node(
                zone,
                data_type="tld",
                type=zone_g_index,
                depends=[result["value"]],
                dependedOnBy=[],
                docs="",
            )

        graph.add_edge(ipzone, result["value"], value=2)
        if zone != "":
            graph.add_edge(
                result["value"], result["fqdn"].replace("." + zone, ""), value=1
            )
            graph.add_edge(result["fqdn"].replace("." + zone, ""), zone, value=1)
        else:
            graph.add_edge(result["value"], result["fqdn"], value=1)


def find_srdns_by_zone(graph, ipzone, groups, mongo_connector):
    """
    Collect all the Sonar Reverse DNS records for the provided zone and add them to NetworkX graph
    """
    temp = ipzone.split(".")
    regex_str = "^" + temp[0] + "\\." + temp[1] + "\\." + temp[2] + ".*"
    regx = re.compile(regex_str)

    srdns_collection = mongo_connector.get_sonar_reverse_dns_connection()
    rdns_results = srdns_collection.find({"ip": {"$regex": regx}})

    for result in rdns_results:
        zone = result["zone"]
        zone_g_index = add_to_list(zone, groups)

        if result["fqdn"] != zone and zone != "":
            graph.add_node(
                zone,
                data_type="tld",
                type=zone_g_index,
                depends=[result["fqdn"].replace("." + zone, "")],
                dependedOnBy=[],
                docs="",
            )
            graph.add_node(
                result["fqdn"].replace("." + zone, ""),
                data_type="domain",
                type=zone_g_index,
                depends=[result["ip"]],
                dependedOnBy=[zone],
                docs="",
            )
        elif zone == "":
            graph.add_node(
                result["fqdn"],
                data_type="domain",
                type=zone_g_index,
                depends=[result["ip"]],
                dependedOnBy=[],
                docs="",
            )
        else:
            graph.add_node(
                result["fqdn"],
                data_type="tld",
                type=zone_g_index,
                depends=[result["ip"]],
                dependedOnBy=[],
                docs="",
            )

        graph.add_node(
            result["ip"],
            data_type="ip",
            type=0,
            depends=[ipzone],
            dependedOnBy=[result["fqdn"].replace("." + zone, "")],
            docs="",
        )

        graph.add_edge(ipzone, result["ip"], value=2)
        if zone != "":
            graph.add_edge(
                result["ip"], result["fqdn"].replace("." + zone, ""), value=1
            )
            graph.add_edge(result["fqdn"].replace("." + zone, ""), zone, value=2)
        else:
            graph.add_edge(result["ip"], result["fqdn"], value=1)


def build_docs(node, zone, groups):
    """
    Build the docs that are shown in the Graph UI when you click on a node
    """

    html = "<h3>" + node["id"] + "</h3><br/>"

    html += "<b>Type:</b> " + node["data_type"] + "<br/>"

    html += "<b>Group:</b> " + groups[node["type"]].replace(REPLACE_CHAR, ".") + "<br/>"

    html += "<b>Depends:</b><br/>"
    if node["depends"] == []:
        html += "None<br/>"
    else:
        for dependency in node["depends"]:
            html += " " + dependency + ","
    html = html[:-1] + "<br>"

    html += "<b>Depended on by:</b><br>"
    if node["dependedOnBy"] == []:
        html += "None<br/>"
    else:
        for dependency in node["dependedOnBy"]:
            html += " " + dependency + ","

    html = html[:-1] + "<br><br>"

    if node["data_type"] == "ip":
        html += (
            '<a href="/ip?search='
            + node["id"]
            + '" target="_blank">Link to full IP details</a>'
        )
    elif node["data_type"] == "tld":
        html += (
            '<a href="/zone?search='
            + node["id"]
            + '" target="_blank">Link to full zone details</a>'
        )
    else:
        if groups[node["type"]].replace(REPLACE_CHAR, ".") != node["id"]:
            html += (
                '<a href="/domain?search='
                + node["id"]
                + "."
                + groups[node["type"]].replace(REPLACE_CHAR, ".")
                + '" target="_blank">Link to full host details</a>'
            )
        else:
            html += (
                '<a href="/domain?search='
                + node["id"]
                + '" target="_blank">Link to full host details</a>'
            )

    return html


def reformat_data(data, cidr, groups):
    """
    Reformat the data object and add the docs properties for d3.js compliance
    """
    for i in range(0, len(data["nodes"])):
        data["nodes"][i]["name"] = data["nodes"][i]["id"]

        # Build relationships
        for tmp_links in data["links"]:
            if (
                data["nodes"][i]["id"] == tmp_links["target"]
                and tmp_links["source"] not in data["nodes"][i]["depends"]
                and tmp_links["source"] != data["nodes"][i]["id"]
            ):
                data["nodes"][i]["depends"].append(tmp_links["source"])

            if (
                data["nodes"][i]["id"] == tmp_links["source"]
                and tmp_links["target"] not in data["nodes"][i]["dependedOnBy"]
                and tmp_links["target"] != data["nodes"][i]["id"]
            ):
                data["nodes"][i]["dependedOnBy"].append(tmp_links["target"])

        # Create docs
        data["nodes"][i]["docs"] = build_docs(data["nodes"][i], cidr, groups)
        data["nodes"][i]["group"] = groups[data["nodes"][i]["type"]]


def main(logger=None):
    """
    Begin Main
    """
    if logger is None:
        logger = LoggingUtil.create_log(__name__)

    now = datetime.now()
    print("Starting: " + str(now))
    logger.info("Starting...")

    # Set up all the database connections
    mongo_connector = MongoConnector.MongoConnector()
    dns_manager = DNSManager.DNSManager(mongo_connector)
    jobs_manager = JobsManager.JobsManager(mongo_connector, "create_netaddr_graphs")
    jobs_manager.record_job_start()

    # Get the list of the all Class C's in Marinus
    groups = []
    create_list_of_cidrs(groups, mongo_connector, dns_manager)

    # Create a separate copy of the class C list since groups will be modified later
    cidr_list = groups + []

    # Create the stats on the network data
    group_data = create_network_data_sets(groups, mongo_connector)

    logger.info("Number of Tracked Class C's: " + str(group_data["tracked_count"]))
    logger.info("Number of AWS Class C's: " + str(group_data["aws_count"]))
    logger.info("Number of Azure Class C's: " + str(group_data["azure_count"]))
    logger.info("Number of Akamai Class C's: " + str(group_data["akamai_count"]))
    logger.info("Number of Class C's: " + str(len(groups)))

    # Get the current list of zones
    zones = ZoneManager.get_distinct_zones(mongo_connector)

    # For each Class C that was identified in Marinus...
    for tcidr in cidr_list:
        cidr = tcidr.replace(REPLACE_CHAR, ".")
        groups = []
        graph = nx.Graph()
        add_to_list(cidr, groups)
        graph.add_node(
            cidr,
            data_type="class_c",
            type=0,
            depends=[],
            dependedOnBy=[],
            docs="<h1>Parent</h1>",
        )
        find_all_dns_by_zone(graph, cidr, groups, dns_manager)
        find_srdns_by_zone(graph, cidr, groups, mongo_connector)

        data = json_graph.node_link_data(graph)

        reformat_data(data, cidr, groups)

        new_data = {}
        new_data["directed"] = data["directed"]
        new_data["graph"] = data["graph"]
        new_data["multigraph"] = data["multigraph"]
        new_data["errs"] = []
        new_data["links"] = data["links"]
        new_data["data"] = {}
        for i in range(0, len(data["nodes"])):
            new_data["data"][data["nodes"][i]["id"].replace(".", REPLACE_CHAR)] = data[
                "nodes"
            ][i]

        config = {}
        config["title"] = cidr + " Network Map"
        config["graph"] = {}
        config["graph"]["linkDistance"] = 150
        config["graph"]["charge"] = -400
        config["graph"]["height"] = 800
        config["graph"]["numColors"] = len(groups)
        config["graph"]["labelPadding"] = {"left": 3, "right": 3, "top": 2, "bottom": 2}
        config["graph"]["labelMargin"] = {"left": 3, "right": 3, "top": 2, "bottom": 2}
        config["graph"]["ticksWithoutCollisions"] = 50
        config["graph_type"] = "cidr"

        config["types"] = {}
        regex_str = "^[0-9]+\\.[0-9]+\\.[0-9]+$"
        regx = re.compile(regex_str)
        for tgroup in groups:
            group = tgroup.replace(REPLACE_CHAR, ".")
            data_type = "tpd"
            if group in zones:
                data_type = "tracked_domain"
            elif re.match(regx, group):
                data_type = "cidr"
            config["types"][tgroup] = {
                "short": group,
                "long": "A group from the network: " + group,
                "data_type": data_type,
            }

        config["constraints"] = []
        tmp = int(math.ceil(math.sqrt(len(groups)))) + 1
        x = []
        y = []
        for i in range(1, tmp):
            val = round((i * 1.0) / tmp, 2)
            x.append(str(val))
            y.append(str(val))
        x_pos = 0
        y_pos = 0
        for group in groups:
            config["constraints"].append(
                {
                    "has": {"type": group},
                    "type": "position",
                    "x": x[x_pos],
                    "y": y[y_pos],
                }
            )
            x_pos = x_pos + 1
            if x_pos >= len(x):
                x_pos = 0
                y_pos = y_pos + 1

        config["jsonUrl"] = "/api/v1.0/cidr_graphs/" + cidr

        new_data["config"] = config
        new_data["created"] = datetime.now()
        new_data["zone"] = cidr

        cidr_graphs_collection = mongo_connector.get_cidr_graphs_connection()
        cidr_graphs_collection.delete_one({"zone": cidr})
        mongo_connector.perform_insert(cidr_graphs_collection, new_data)

        time.sleep(1)

    # Remove last week's old entries
    lastweek = datetime.now() - timedelta(days=7)
    cidr_graphs_collection.delete_many({"created": {"$lt": lastweek}})

    # Record status
    jobs_manager.record_job_complete()

    now = datetime.now()
    print("Ending: " + str(now))
    logger.info("Complete.")


if __name__ == "__main__":
    logger = LoggingUtil.create_log(__name__)

    try:
        main(logger)
    except Exception as e:
        logger.error("FATAL: " + str(e), exc_info=True)
        exit(1)
