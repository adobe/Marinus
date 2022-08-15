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
This script assumes that the following scripts have already been run:

- Core scripts (zones, infoblox, sonar)
- extract_ssl_names
- extract_vt_names
- get_external_cnames

ERRATA:
  "TPD" in this case means root domain ("example.org") and not the traditional usage of TPD
which refers to ".net", ".com", ".co.uk", etc.
"""

import json
import logging
import math
import re
import time
from datetime import datetime, timedelta

import networkx as nx
from libs3 import JobsManager, MongoConnector
from libs3.LoggingUtil import LoggingUtil
from libs3.ZoneManager import ZoneManager
from netaddr import IPAddress, IPNetwork
from networkx.readwrite import json_graph

REPLACE_CHAR = "!"


def add_to_list(str_to_add, groups):
    """
    This will add a string to the groups array if it does not exist.
    It will then return the index of the string within the Array
    """
    if str_to_add.replace(".", REPLACE_CHAR) not in groups:
        groups.append(str_to_add.replace(".", REPLACE_CHAR))
    return groups.index(str_to_add.replace(".", REPLACE_CHAR))


def find_zones_by_tld(graph, tpd, groups, mongo_connector):
    """
    Technically, a "tld" is ".org" or ".com".
    However, tld library that I use considers TLDs to be "example.org".
    This code just rolls with that.
    For the provided third-party-domain, find the zones that are associated with that tpd.
    """
    tpds_collection = mongo_connector.get_tpds_connection()
    tpds_results = tpds_collection.find({"tld": tpd})

    for result in tpds_results:
        for zone in result["zones"]:
            zone_g_index = add_to_list(zone["zone"], groups)

            # A space is added because sometimes the tpd is the same as the target
            graph.add_node(
                zone["zone"],
                data_type="zone",
                type=zone_g_index,
                depends=[tpd + " "],
                dependedOnBy=[],
                docs="",
            )
            graph.add_edge(tpd + " ", zone["zone"], value=2)

            for entry in zone["records"]:
                graph.add_node(
                    entry["host"],
                    data_type="domain",
                    type=zone_g_index,
                    depends=[zone["zone"]],
                    dependedOnBy=[entry["target"]],
                    docs="",
                )
                graph.add_node(
                    entry["target"],
                    data_type="domain",
                    type=zone_g_index,
                    depends=[entry["host"]],
                    dependedOnBy=[],
                    docs="",
                )
                graph.add_edge(zone["zone"], entry["host"], value=1)
                graph.add_edge(entry["host"], entry["target"], value=1)


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

    html = html[:-1] + "<br>"

    if node["data_type"] == "tld":
        # <a href=\"/zone?search=" + node['id'] +
        # "\" target=\"_blank\">Link to full zone details</a>"
        html += ""
    else:
        if groups[node["type"]].replace(REPLACE_CHAR, ".") != zone:
            html += (
                '<a href="/domain?search='
                + node["id"]
                + '" target="_blank">Link to full host details</a>'
            )
        else:
            html += (
                '<a href="/zone?search='
                + node["id"]
                + '" target="_blank">Link to full host details</a>'
            )

    return html


def reformat_data(data, tpd, groups):
    """
    Reformat the data object and add the docs properties for d3.js compliance
    """
    for i in range(0, len(data["nodes"])):
        data["nodes"][i]["name"] = data["nodes"][i]["id"]
        data["nodes"][i]["group"] = groups[data["nodes"][i]["type"]]


def get_tpds(mongo_connector):
    """
    Create the list of third-party domains
    """
    tpds_collection = mongo_connector.get_tpds_connection()
    tpd_results = tpds_collection.find({})

    tpds = []
    for rec in tpd_results:
        tpds.append(rec["tld"])

    return tpds


def main(logger=None):
    """
    The main thread for this program.
    """
    if logger is None:
        logger = LoggingUtil.create_log(__name__)

    now = datetime.now()
    print("Starting: " + str(now))
    logger.info("Starting...")

    mongo_connector = MongoConnector.MongoConnector()
    jobs_manager = JobsManager.JobsManager(mongo_connector, "create_tpd_graphs")
    jobs_manager.record_job_start()

    zones = ZoneManager.get_distinct_zones(mongo_connector)

    tpds = get_tpds(mongo_connector)

    # For third-party-domain in the list of third-party-domains
    for tpd in tpds:
        groups = []
        graph = nx.DiGraph()
        add_to_list(tpd, groups)

        # A space is added because sometimes the tpd is the same as the end target node
        graph.add_node(
            tpd + " ",
            data_type="tld",
            type=0,
            depends=[],
            dependedOnBy=[],
            docs="<h1>Parent</h1>",
        )

        # Get the zones associated with the tpd
        find_zones_by_tld(graph, tpd, groups, mongo_connector)

        data = json_graph.node_link_data(graph)

        reformat_data(data, tpd, groups)

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

        for entry in new_data["data"]:
            for dep in new_data["data"][entry]["depends"]:
                if (
                    new_data["data"][entry]["name"]
                    not in new_data["data"][dep.replace(".", REPLACE_CHAR)][
                        "dependedOnBy"
                    ]
                ):
                    new_data["data"][dep.replace(".", REPLACE_CHAR)][
                        "dependedOnBy"
                    ].append(new_data["data"][entry]["name"])
            for dep in new_data["data"][entry]["dependedOnBy"]:
                if (
                    new_data["data"][entry]["name"]
                    not in new_data["data"][dep.replace(".", REPLACE_CHAR)]["depends"]
                ):
                    new_data["data"][dep.replace(".", REPLACE_CHAR)]["depends"].append(
                        new_data["data"][entry]["name"]
                    )

        for entry in new_data["data"]:
            new_data["data"][entry]["docs"] = build_docs(
                new_data["data"][entry], tpd, groups
            )

        config = {}
        config["title"] = tpd + " Network Map"
        config["graph"] = {}
        config["graph"]["linkDistance"] = 150
        config["graph"]["charge"] = -400
        config["graph"]["height"] = 800
        config["graph"]["numColors"] = len(groups)
        config["graph"]["labelPadding"] = {"left": 3, "right": 3, "top": 2, "bottom": 2}
        config["graph"]["labelMargin"] = {"left": 3, "right": 3, "top": 2, "bottom": 2}
        config["graph"]["ticksWithoutCollisions"] = 50
        config["graph_type"] = "tpd"

        config["types"] = {}
        regex_str = "^[0-9]+\\.[0-9]+\\.[0-9]+$"
        regx = re.compile(regex_str)
        for tgroup in groups:
            data_type = "tpd"
            group = tgroup.replace(REPLACE_CHAR, ".")
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

        config["jsonUrl"] = "/api/v1.0/tpd_graphs/" + tpd

        new_data["config"] = config
        new_data["created"] = datetime.now()
        new_data["zone"] = tpd

        tpd_graphs_collection = mongo_connector.get_tpd_graphs_connection()
        tpd_graphs_collection.delete_one({"zone": tpd})
        try:
            mongo_connector.perform_insert(tpd_graphs_collection, new_data)
        except:
            logger.error("ERROR: Could not insert " + tpd)

        time.sleep(1)

    # Remove last week's old entries
    lastweek = datetime.now() - timedelta(days=7)
    tpd_graphs_collection.delete_many({"created": {"$lt": lastweek}})

    # Record status
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
