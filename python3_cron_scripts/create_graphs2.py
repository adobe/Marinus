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
This script is responsible for creating the visual graphs of tracked root domains.
The networkx library is responsible for de-duplicating entries and creating the structure.
There are additional properties that are attached for the downstream d3.js code rendering code.
This code is just for tracked root domains. It does not handle the networks of third-party domains.
This script should be run after all the data generating scripts have completed.

The data is split up across three collections because graphs for large domains can exceed
the maximum size of allowed JSON objects in MongoDB.
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
from tld import get_fld

# Constant for dealing with Mongo not allowing "." in key names
REPLACE_CHAR = "!"


def add_to_list(str_to_add, groups):
    """
    This will add a string to the GROUPS array if it does not exist.
    It will then return the index of the string within the Array
    """
    if str_to_add.replace(".", REPLACE_CHAR) not in groups:
        groups.append(str_to_add.replace(".", REPLACE_CHAR))
    return groups.index(str_to_add.replace(".", REPLACE_CHAR))


def is_aws_domain(domain):
    """
    Is the provided domain within the amazonaws.com zone?
    """
    return domain.endswith(".amazonaws.com")


def is_akamai_domain(domain):
    """
    Is the provided domain within akamai.net?
    """
    return domain.endswith(".akamai.net")


def get_fld_from_value(value, zone):
    """
    Get the First Level Domain (FLD) for the provided value
    """
    res = get_fld(value, fix_protocol=True, fail_silently=True)
    if res is None:
        return zone

    return res


def find_all_dns_by_zone(graph, zone, groups, dns_manager, ip_manager):
    """
    Collect all the All DNS records for the provided zone and add them to NetworkX graph
    """
    dns_results = dns_manager.find_multiple({"zone": zone}, None)

    for result in dns_results:
        zone_g_index = add_to_list(zone, groups)
        if result["type"] == "a":
            temp = result["value"].split(".")
            ip_group = ".".join(temp[:-1])
            if ip_manager.is_aws_ip(result["value"]):
                ip_group = "aws"
            elif ip_manager.is_akamai_ip(result["value"]):
                ip_group = "akamai"
            elif ip_manager.is_azure_ip(result["value"]):
                ip_group = "azure"
            elif ip_manager.is_gcp_ip(result["value"]):
                ip_group = "gcp"

            ip_g_index = add_to_list(ip_group, groups)
            if str(result["fqdn"]) != zone:
                graph.add_node(
                    result["fqdn"].replace("." + zone, ""),
                    data_type="domain",
                    type=zone_g_index,
                    depends=[zone],
                    dependedOnBy=[result["value"]],
                    docs="",
                )
            else:
                graph.add_node(
                    result["fqdn"],
                    data_type="tld",
                    type=zone_g_index,
                    depends=[],
                    dependedOnBy=[result["value"]],
                    docs="",
                )
            graph.add_node(
                result["value"],
                data_type="ip",
                type=ip_g_index,
                depends=[result["fqdn"].replace("." + zone, "")],
                dependedOnBy=[],
                docs="",
            )
            graph.add_edge(zone, result["fqdn"].replace("." + zone, ""), value=2)
            graph.add_edge(
                result["fqdn"].replace("." + zone, ""), result["value"], value=1
            )
        elif result["type"] == "cname":
            dns_group = zone
            if is_akamai_domain(result["value"]):
                dns_group = "akamai.net"
            elif result["value"].endswith(zone) is False:
                dns_group = get_fld_from_value(result["value"], zone)

            cname_g_index = add_to_list(dns_group, groups)

            if result["fqdn"] != zone:
                graph.add_node(
                    result["fqdn"].replace("." + zone, ""),
                    data_type="domain",
                    type=zone_g_index,
                    depends=[zone],
                    dependedOnBy=[result["value"].replace("." + zone, "")],
                    docs="",
                )
            else:
                graph.add_node(
                    result["fqdn"],
                    data_type="tld",
                    type=zone_g_index,
                    depends=[],
                    dependedOnBy=[result["value"].replace("." + zone, "")],
                    docs="",
                )
            graph.add_node(
                result["value"].replace("." + zone, ""),
                data_type="cname",
                type=cname_g_index,
                depends=[result["fqdn"].replace("." + zone, "")],
                dependedOnBy=[],
                docs="",
            )
            graph.add_edge(zone, result["fqdn"].replace("." + zone, ""), value=2)
            graph.add_edge(
                result["fqdn"].replace("." + zone, ""),
                result["value"].replace("." + zone, ""),
                value=1,
            )


def find_srdns_by_zone(graph, zone, groups, mongo_connector, ip_manager):
    """
    Collect all the Sonar Reverse DNS records for the provided zone and add them to NetworkX graph
    """
    srdns_collection = mongo_connector.get_sonar_reverse_dns_connection()
    rdns_results = srdns_collection.find({"zone": zone})

    for result in rdns_results:
        zone_g_index = add_to_list(zone, groups)
        if result["fqdn"] != zone:
            graph.add_node(
                result["fqdn"].replace("." + zone, ""),
                data_type="domain",
                type=zone_g_index,
                depends=[zone],
                dependedOnBy=[result["ip"]],
                docs="",
            )
        else:
            graph.add_node(
                result["fqdn"],
                data_type="tld",
                type=zone_g_index,
                depends=[],
                dependedOnBy=[result["ip"]],
                docs="",
            )
        temp = result["ip"].split(".")

        ip_group = ".".join(temp[:-1])
        if ip_manager.is_aws_ip(result["ip"]):
            ip_group = "aws"
        elif ip_manager.is_akamai_ip(result["ip"]):
            ip_group = "akamai"
        elif ip_manager.is_azure_ip(result["ip"]):
            ip_group = "azure"
        elif ip_manager.is_gcp_ip(result["ip"]):
            ip_group = "gcp"

        ip_g_index = add_to_list(ip_group, groups)
        graph.add_node(
            result["ip"],
            data_type="ip",
            type=ip_g_index,
            depends=[result["fqdn"].replace("." + zone, "")],
            dependedOnBy=[],
            docs="",
        )
        graph.add_edge(zone, result["fqdn"].replace("." + zone, ""), value=2)
        graph.add_edge(result["fqdn"].replace("." + zone, ""), result["ip"], value=1)


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
        if groups[node["type"]].replace(REPLACE_CHAR, ".") == zone:
            html += (
                '<a href="/domain?search='
                + node["id"]
                + "."
                + zone
                + '" target="_blank">Link to full host details</a>'
            )
        else:
            html += (
                '<a href="/domain?search='
                + node["id"]
                + '" target="_blank">Link to full host details</a>'
            )

    return html


def reformat_data(data, zone, groups):
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
        data["nodes"][i]["docs"] = build_docs(data["nodes"][i], zone, groups)
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

    mongo_connector = MongoConnector.MongoConnector()
    dns_manager = DNSManager.DNSManager(mongo_connector)
    graphs_collection = mongo_connector.get_graphs_connection()
    graphs_data_collection = mongo_connector.get_graphs_data_connection()
    graphs_links_collection = mongo_connector.get_graphs_links_connection()
    graphs_docs_collection = mongo_connector.get_graphs_docs_connection()
    ip_manager = IPManager.IPManager(mongo_connector)

    jobs_manager = JobsManager.JobsManager(mongo_connector, "create_graphs2")
    jobs_manager.record_job_start()

    zones = ZoneManager.get_distinct_zones(mongo_connector)

    for zone in zones:
        groups = []
        graph = nx.Graph()
        add_to_list(zone, groups)
        graph.add_node(
            zone,
            data_type="tld",
            type=0,
            depends=[],
            dependedOnBy=[],
            docs="<h1>Parent</h1>",
        )
        find_all_dns_by_zone(graph, zone, groups, dns_manager, ip_manager)
        find_srdns_by_zone(graph, zone, groups, mongo_connector, ip_manager)

        data = json_graph.node_link_data(graph)

        reformat_data(data, zone, groups)

        new_data = {}
        new_data["directed"] = data["directed"]
        new_data["graph"] = data["graph"]
        new_data["multigraph"] = data["multigraph"]
        new_data["errs"] = []

        config = {}
        config["title"] = zone + " Network Map"
        config["graph"] = {}
        config["graph"]["linkDistance"] = 150
        config["graph"]["charge"] = -400
        config["graph"]["height"] = 800
        config["graph"]["numColors"] = len(groups)
        config["graph"]["labelPadding"] = {"left": 3, "right": 3, "top": 2, "bottom": 2}
        config["graph"]["labelMargin"] = {"left": 3, "right": 3, "top": 2, "bottom": 2}
        config["graph"]["ticksWithoutCollisions"] = 50
        config["graph_type"] = "tracked_domain"

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

        config["jsonUrl"] = "/api/v1.0/graphs/" + zone

        new_data["config"] = config
        new_data["created"] = datetime.now()
        new_data["zone"] = zone

        new_docs_data = {}
        new_docs_data["docs"] = {}
        new_docs_data["zone"] = zone
        new_docs_data["created"] = datetime.now()

        new_graph_data = {}
        new_graph_data["data"] = {}
        for i in range(0, len(data["nodes"])):
            new_graph_data["data"][
                data["nodes"][i]["id"].replace(".", REPLACE_CHAR)
            ] = data["nodes"][i]
            new_docs_data["docs"][
                data["nodes"][i]["id"].replace(".", REPLACE_CHAR)
            ] = data["nodes"][i]["docs"]
            del new_graph_data["data"][
                data["nodes"][i]["id"].replace(".", REPLACE_CHAR)
            ]["docs"]
        new_graph_data["created"] = datetime.now()
        new_graph_data["zone"] = zone
        new_graph_data["directed"] = data["directed"]
        new_graph_data["multigraph"] = data["multigraph"]
        new_graph_data["errs"] = []

        new_links_data = {}
        new_links_data["links"] = data["links"]
        new_links_data["created"] = datetime.now()
        new_links_data["zone"] = zone
        new_links_data["directed"] = data["directed"]
        new_links_data["multigraph"] = data["multigraph"]
        new_links_data["errs"] = []

        try:
            graphs_collection.delete_one({"zone": zone})
            mongo_connector.perform_insert(graphs_collection, new_data)

            graphs_data_collection.delete_one({"zone": zone})
            mongo_connector.perform_insert(graphs_data_collection, new_graph_data)

            graphs_links_collection.delete_one({"zone": zone})
            mongo_connector.perform_insert(graphs_links_collection, new_links_data)

            graphs_docs_collection.delete_one({"zone": zone})
            mongo_connector.perform_insert(graphs_docs_collection, new_docs_data)
        except:
            logger.error("ERROR: Can't insert: " + zone)

        time.sleep(1)

    # Remove last week's old entries
    # In theory, shouldn't do anything but being complete
    lastweek = datetime.now() - timedelta(days=7)
    graphs_collection.delete_many({"created": {"$lt": lastweek}})
    graphs_data_collection.delete_many({"created": {"$lt": lastweek}})
    graphs_links_collection.delete_many({"created": {"$lt": lastweek}})
    graphs_docs_collection.delete_many({"created": {"$lt": lastweek}})

    # Record status
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
