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
This script creates d3.js maps of the certificates stored within Marinus.
It stores the graphs within the Marinus database for later retrieval by the UI.
This assumes that you have already collected data from either Censys, CT Logs, or zgrab sans.
Use the command line to specify which of those sources exist.
You can specify multiple sources on the command line.
"""

import argparse
import json
import logging
from datetime import datetime

import networkx as nx
from libs3 import DNSManager, JobsManager, MongoConnector
from libs3.LoggingUtil import LoggingUtil
from libs3.ZoneManager import ZoneManager
from networkx.readwrite import json_graph


def get_current_ct_certificates(ct_connection, zone):
    """
    Get the list of non-expired certificate transparency certificates for the indicated zone.
    """

    results = ct_connection.find(
        {
            "isExpired": False,
            "subject_common_names": {"$regex": r"^(.+\.)*" + zone + "$"},
            "subject_dns_names": {"$regex": r"^(.+\.)*" + zone + "$"},
        },
        {"fingerprint_sha256": 1, "subject_common_names": 1, "subject_dns_names": 1},
    )

    collection = []
    for result in results:
        item = {"id": result["fingerprint_sha256"]}
        item["dns_entries"] = (
            result["subject_common_names"] + result["subject_dns_names"]
        )
        item["sources"] = ["ct_logs"]
        collection.append(item)

    return collection


def get_censys_count(censys_collection, sha256_hash):
    """
    Get the count of matching certificates for the provided hash
    """
    result_count = censys_collection.count_documents(
        {"p443.https.tls.certificate.parsed.fingerprint_sha256": sha256_hash}
    )
    return result_count


def add_censys_certificates(censys_collection, zone, current_certs):
    """
    Get the list of current certificates from censys for the specified zones.
    Append any new entries to the provided array of current_certs.
    """

    results = censys_collection.find(
        {
            "$or": [
                {
                    "p443.https.tls.certificate.parsed.subject.common_name": {
                        "$regex": r"^(.+\.)*" + zone + "$"
                    }
                },
                {
                    "p443.https.tls.certificate.parsed.extensions.subject_alt_name.dns_names": {
                        "$regex": r"^(.+\.)*" + zone + "$"
                    }
                },
            ]
        },
        {
            "p443.https.tls.certificate.parsed.subject.common_name": 1,
            "p443.https.tls.certificate.parsed.extensions.subject_alt_name.dns_names": 1,
            "p443.https.tls.certificate.parsed.fingerprint_sha256": 1,
        },
    )

    for result in results:
        i = next(
            (
                index
                for (index, item) in enumerate(current_certs)
                if item["id"]
                == result["p443"]["https"]["tls"]["certificate"]["parsed"][
                    "fingerprint_sha256"
                ]
            ),
            None,
        )
        if i is None:
            item = {
                "id": result["p443"]["https"]["tls"]["certificate"]["parsed"][
                    "fingerprint_sha256"
                ]
            }
            dns_list = []
            try:
                for dns_name in result["p443"]["https"]["tls"]["certificate"]["parsed"][
                    "subject"
                ]["common_name"]:
                    if dns_name not in dns_list:
                        dns_list.append(dns_name)
            except KeyError:
                pass

            # Not all certificates contain alternative names.
            try:
                for dns_name in result["p443"]["https"]["tls"]["certificate"]["parsed"][
                    "extensions"
                ]["subject_alt_name"]["dns_names"]:
                    if dns_name not in dns_list:
                        dns_list.append(dns_name)
            except KeyError:
                # "ALT Name key not found."
                pass

            item["dns_entries"] = dns_list
            item["sources"] = ["censys"]
            item["censys_count"] = get_censys_count(
                censys_collection,
                result["p443"]["https"]["tls"]["certificate"]["parsed"][
                    "fingerprint_sha256"
                ],
            )
            current_certs.append(item)
        else:
            # The certificate is already stored so there is nothing more to add.
            if "censys" not in current_certs[i]["sources"]:
                current_certs[i]["sources"].append("censys")
            if "censys_count" not in current_certs[i]:
                current_certs[i]["censys_count"] = get_censys_count(
                    censys_collection,
                    result["p443"]["https"]["tls"]["certificate"]["parsed"][
                        "fingerprint_sha256"
                    ],
                )

    return current_certs


def get_scan_count(zgrab_collection, sha256_hash, version):
    """
    Get the count of matching certificates for the provided hash
    """
    if version == 1:
        result_count = zgrab_collection.count_documents(
            {
                "$or": [
                    {
                        "data.http.response.request.tls_handshake.server_certificates.certificate.parsed.fingerprint_sha256": sha256_hash
                    },
                    {
                        "data.http.response.redirect_response_chain.0.request.tls_handshake.server_certificates.certificate.parsed.fingerprint_sha256": sha256_hash
                    },
                ]
            }
        )
    else:
        result_count = zgrab_collection.count_documents(
            {
                "$or": [
                    {
                        "data.http.result.response.request.tls_log.handshake_log.server_certificates.certificate.parsed.fingerprint_sha256": sha256_hash
                    },
                    {
                        "data.http.result.redirect_response_chain.0.request.tls_log.handshake_log.server_certificates.certificate.parsed.fingerprint_sha256": sha256_hash
                    },
                ]
            }
        )
    return result_count


def add_terminal_zgrab_certificates(
    mongo_connector, zgrab_collection, zone, current_certs
):
    """
    Get the list of current certificates from zgrab scans for the specified zones.
    Append any new entries to the provided array of current_certs.
    This currently does not check
    """

    results = mongo_connector.perform_find(
        zgrab_collection,
        {
            "$or": [
                {
                    "data.http.response.request.tls_handshake.server_certificates.certificate.parsed.subject.common_name": {
                        "$regex": r"^(.+\.)*" + zone + "$"
                    }
                },
                {
                    "data.http.response.request.tls_handshake.server_certificates.certificate.parsed.extensions.subject_alt_name.dns_names": {
                        "$regex": r"^(.+\.)*" + zone + "$"
                    }
                },
            ]
        },
        filter={
            "data.http.response.request.tls_handshake.server_certificates.certificate.parsed.subject.common_name": 1,
            "data.http.response.request.tls_handshake.server_certificates.certificate.parsed.extensions.subject_alt_name.dns_names": 1,
            "data.http.response.request.tls_handshake.server_certificates.certificate.parsed.fingerprint_sha256": 1,
        },
        batch_size=40,
    )

    for result in results:
        i = next(
            (
                index
                for (index, item) in enumerate(current_certs)
                if item["id"]
                == result["data"]["http"]["response"]["request"]["tls_handshake"][
                    "server_certificates"
                ]["certificate"]["parsed"]["fingerprint_sha256"]
            ),
            None,
        )
        if i is None:
            item = {
                "id": result["data"]["http"]["response"]["request"]["tls_handshake"][
                    "server_certificates"
                ]["certificate"]["parsed"]["fingerprint_sha256"]
            }
            dns_list = []
            try:
                for dns_name in result["data"]["http"]["response"]["request"][
                    "tls_handshake"
                ]["server_certificates"]["certificate"]["parsed"]["subject"][
                    "common_name"
                ]:
                    if dns_name not in dns_list:
                        dns_list.append(dns_name)
            except KeyError:
                pass

            # Not all certificates contain alternative names.
            try:
                for dns_name in result["data"]["http"]["response"]["request"][
                    "tls_handshake"
                ]["server_certificates"]["certificate"]["parsed"]["extensions"][
                    "subject_alt_name"
                ][
                    "dns_names"
                ]:
                    if dns_name not in dns_list:
                        dns_list.append(dns_name)
            except KeyError:
                # "ALT Name key not found."
                pass

            item["dns_entries"] = dns_list
            item["sources"] = ["zgrab_443_scan"]
            item["zgrab_count"] = get_scan_count(
                zgrab_collection,
                result["data"]["http"]["response"]["request"]["tls_handshake"][
                    "server_certificates"
                ]["certificate"]["parsed"]["fingerprint_sha256"],
                1,
            )
            current_certs.append(item)
        else:
            # The certificate is already stored so there is nothing more to add.
            if "zgrab_443_scan" not in current_certs[i]["sources"]:
                current_certs[i]["sources"].append("zgrab_443_scan")
            if "zgrab_count" not in current_certs[i]:
                current_certs[i]["zgrab_count"] = get_scan_count(
                    zgrab_collection,
                    result["data"]["http"]["response"]["request"]["tls_handshake"][
                        "server_certificates"
                    ]["certificate"]["parsed"]["fingerprint_sha256"],
                    1,
                )

    return current_certs


def add_initial_zgrab_certificates(
    mongo_connector, zgrab_collection, zone, current_certs
):
    """
    Get the list of current certificates from zgrab scans for the specified zones.
    Append any new entries to the provided array of current_certs.
    This currently does not check
    """

    results = mongo_connector.perform_find(
        zgrab_collection,
        {
            "$or": [
                {
                    "data.http.redirect_response_chain.0.request.tls_handshake.server_certificates.certificate.parsed.subject.common_name": {
                        "$regex": r"^(.+\.)*" + zone + "$"
                    }
                },
                {
                    "data.http.redirect_response_chain.0.request.tls_handshake.server_certificates.certificate.parsed.extensions.subject_alt_name.dns_names": {
                        "$regex": r"^(.+\.)*" + zone + "$"
                    }
                },
            ]
        },
        filter={"data.http.redirect_response_chain": 1},
    )

    for result in results:
        i = next(
            (
                index
                for (index, item) in enumerate(current_certs)
                if item["id"]
                == result["data"]["http"]["redirect_response_chain"][0]["request"][
                    "tls_handshake"
                ]["server_certificates"]["certificate"]["parsed"]["fingerprint_sha256"]
            ),
            None,
        )
        if i is None:
            item = {
                "id": result["data"]["http"]["redirect_response_chain"][0]["request"][
                    "tls_handshake"
                ]["server_certificates"]["certificate"]["parsed"]["fingerprint_sha256"]
            }
            dns_list = []
            try:
                for dns_name in result["data"]["http"]["redirect_response_chain"][0][
                    "request"
                ]["tls_handshake"]["server_certificates"]["certificate"]["parsed"][
                    "subject"
                ][
                    "common_name"
                ]:
                    if dns_name not in dns_list:
                        dns_list.append(dns_name)
            except KeyError:
                pass

            # Not all certificates contain alternative names.
            try:
                for dns_name in result["data"]["http"]["redirect_response_chain"][0][
                    "request"
                ]["tls_handshake"]["server_certificates"]["certificate"]["parsed"][
                    "extensions"
                ][
                    "subject_alt_name"
                ][
                    "dns_names"
                ]:
                    if dns_name not in dns_list:
                        dns_list.append(dns_name)
            except KeyError:
                # "ALT Name key not found."
                pass

            item["dns_entries"] = dns_list
            item["sources"] = ["zgrab_443_scan"]
            item["zgrab_count"] = get_scan_count(
                zgrab_collection,
                result["data"]["http"]["redirect_response_chain"][0]["request"][
                    "tls_handshake"
                ]["server_certificates"]["certificate"]["parsed"]["fingerprint_sha256"],
                1,
            )
            current_certs.append(item)
        else:
            # The certificate is already stored so there is nothing more to add.
            if "zgrab_443_scan" not in current_certs[i]["sources"]:
                current_certs[i]["sources"].append("zgrab_443_scan")
            if "zgrab_count" not in current_certs[i]:
                current_certs[i]["zgrab_count"] = get_scan_count(
                    zgrab_collection,
                    result["data"]["http"]["redirect_response_chain"][0]["request"][
                        "tls_handshake"
                    ]["server_certificates"]["certificate"]["parsed"][
                        "fingerprint_sha256"
                    ],
                    1,
                )

    return current_certs


def add_terminal_zgrab2_certificates(
    mongo_connector, zgrab_collection, zone, current_certs
):
    """
    Get the list of current certificates from zgrab scans for the specified zones.
    Append any new entries to the provided array of current_certs.
    This currently does not check
    """

    results = mongo_connector.perform_find(
        zgrab_collection,
        {
            "$or": [
                {
                    "data.http.result.response.request.tls_log.handshake_log.server_certificates.certificate.parsed.subject.common_name": {
                        "$regex": r"^(.+\.)*" + zone + "$"
                    }
                },
                {
                    "data.http.result.response.request.tls_log.handshake_log.server_certificates.certificate.parsed.extensions.subject_alt_name.dns_names": {
                        "$regex": r"^(.+\.)*" + zone + "$"
                    }
                },
            ]
        },
        filter={
            "data.http.result.response.request.tls_log.handshake_log.server_certificates.certificate.parsed.subject.common_name": 1,
            "data.http.result.response.request.tls_log.handshake_log.server_certificates.certificate.parsed.extensions.subject_alt_name.dns_names": 1,
            "data.http.result.response.request.tls_log.handshake_log.server_certificates.certificate.parsed.fingerprint_sha256": 1,
        },
        batch_size=40,
    )

    for result in results:
        i = next(
            (
                index
                for (index, item) in enumerate(current_certs)
                if item["id"]
                == result["data"]["http"]["result"]["response"]["request"]["tls_log"][
                    "handshake_log"
                ]["server_certificates"]["certificate"]["parsed"]["fingerprint_sha256"]
            ),
            None,
        )
        if i is None:
            item = {
                "id": result["data"]["http"]["result"]["response"]["request"][
                    "tls_log"
                ]["handshake_log"]["server_certificates"]["certificate"]["parsed"][
                    "fingerprint_sha256"
                ]
            }
            dns_list = []
            try:
                for dns_name in result["data"]["http"]["result"]["response"]["request"][
                    "tls_log"
                ]["handshake_log"]["server_certificates"]["certificate"]["parsed"][
                    "subject"
                ][
                    "common_name"
                ]:
                    if dns_name not in dns_list:
                        dns_list.append(dns_name)
            except KeyError:
                pass

            # Not all certificates contain alternative names.
            try:
                for dns_name in result["data"]["http"]["result"]["response"]["request"][
                    "tls_log"
                ]["handshake_log"]["server_certificates"]["certificate"]["parsed"][
                    "extensions"
                ][
                    "subject_alt_name"
                ][
                    "dns_names"
                ]:
                    if dns_name not in dns_list:
                        dns_list.append(dns_name)
            except KeyError:
                # "ALT Name key not found."
                pass

            item["dns_entries"] = dns_list
            item["sources"] = ["zgrab_443_scan"]
            item["zgrab_count"] = get_scan_count(
                zgrab_collection,
                result["data"]["http"]["result"]["response"]["request"]["tls_log"][
                    "handshake_log"
                ]["server_certificates"]["certificate"]["parsed"]["fingerprint_sha256"],
                2,
            )
            current_certs.append(item)
        else:
            # The certificate is already stored so there is nothing more to add.
            if "zgrab_443_scan" not in current_certs[i]["sources"]:
                current_certs[i]["sources"].append("zgrab_443_scan")
            if "zgrab_count" not in current_certs[i]:
                current_certs[i]["zgrab_count"] = get_scan_count(
                    zgrab_collection,
                    result["data"]["http"]["result"]["response"]["request"]["tls_log"][
                        "handshake_log"
                    ]["server_certificates"]["certificate"]["parsed"][
                        "fingerprint_sha256"
                    ],
                    2,
                )

    return current_certs


def add_initial_zgrab2_certificates(
    mongo_connector, zgrab_collection, zone, current_certs
):
    """
    Get the list of current certificates from zgrab scans for the specified zones.
    Append any new entries to the provided array of current_certs.
    This currently does not check
    """

    results = mongo_connector.perform_find(
        zgrab_collection,
        {
            "$or": [
                {
                    "data.http.result.redirect_response_chain.0.request.tls_log.handshake_log.server_certificates.certificate.parsed.subject.common_name": {
                        "$regex": r"^(.+\.)*" + zone + "$"
                    }
                },
                {
                    "data.http.result.redirect_response_chain.0.request.tls_log.handshake_log.server_certificates.certificate.parsed.extensions.subject_alt_name.dns_names": {
                        "$regex": r"^(.+\.)*" + zone + "$"
                    }
                },
            ]
        },
        filter={"data.http.result.redirect_response_chain": 1},
    )

    for result in results:
        i = next(
            (
                index
                for (index, item) in enumerate(current_certs)
                if item["id"]
                == result["data"]["http"]["result"]["redirect_response_chain"][0][
                    "request"
                ]["tls_log"]["handshake_log"]["server_certificates"]["certificate"][
                    "parsed"
                ][
                    "fingerprint_sha256"
                ]
            ),
            None,
        )
        if i is None:
            item = {
                "id": result["data"]["http"]["result"]["redirect_response_chain"][0][
                    "request"
                ]["tls_log"]["handshake_log"]["server_certificates"]["certificate"][
                    "parsed"
                ][
                    "fingerprint_sha256"
                ]
            }
            dns_list = []
            try:
                for dns_name in result["data"]["http"]["result"][
                    "redirect_response_chain"
                ][0]["request"]["tls_log"]["handshake_log"]["server_certificates"][
                    "certificate"
                ][
                    "parsed"
                ][
                    "subject"
                ][
                    "common_name"
                ]:
                    if dns_name not in dns_list:
                        dns_list.append(dns_name)
            except KeyError:
                pass

            # Not all certificates contain alternative names.
            try:
                for dns_name in result["data"]["http"]["result"][
                    "redirect_response_chain"
                ][0]["request"]["tls_log"]["handshake_log"]["server_certificates"][
                    "certificate"
                ][
                    "parsed"
                ][
                    "extensions"
                ][
                    "subject_alt_name"
                ][
                    "dns_names"
                ]:
                    if dns_name not in dns_list:
                        dns_list.append(dns_name)
            except KeyError:
                # "ALT Name key not found."
                pass

            item["dns_entries"] = dns_list
            item["sources"] = ["zgrab_443_scan"]
            item["zgrab_count"] = get_scan_count(
                zgrab_collection,
                result["data"]["http"]["result"]["redirect_response_chain"][0][
                    "request"
                ]["tls_log"]["handshake_log"]["server_certificates"]["certificate"][
                    "parsed"
                ][
                    "fingerprint_sha256"
                ],
                2,
            )
            current_certs.append(item)
        else:
            # The certificate is already stored so there is nothing more to add.
            if "zgrab_443_scan" not in current_certs[i]["sources"]:
                current_certs[i]["sources"].append("zgrab_443_scan")
            if "zgrab_count" not in current_certs[i]:
                current_certs[i]["zgrab_count"] = get_scan_count(
                    zgrab_collection,
                    result["data"]["http"]["result"]["redirect_response_chain"][0][
                        "request"
                    ]["tls_log"]["handshake_log"]["server_certificates"]["certificate"][
                        "parsed"
                    ][
                        "fingerprint_sha256"
                    ],
                    2,
                )

    return current_certs


def create_nodes(graph, mongo_connector, zone, all_certs):
    """
    Create the list of D3.js nodes and links based on the collected certificates
    """
    DNS_MGR = DNSManager.DNSManager(mongo_connector)

    for cert in all_certs:
        matched_count = 0
        if "censys_count" in cert:
            matched_count = cert["censys_count"]

        if "zgrab_count" in cert:
            matched_count = matched_count + cert["zgrab_count"]

        graph.add_node(
            cert["id"],
            type="certificate",
            sources=cert["sources"],
            total_count=matched_count,
        )
        for dns_entry in cert["dns_entries"]:
            lookup = DNS_MGR.find_one({"fqdn": dns_entry}, None)

            root_flag = "false"
            if dns_entry == zone:
                root_flag = "true"

            if lookup is None:
                graph.add_node(
                    dns_entry,
                    root=root_flag,
                    status="No Host",
                    type="domain",
                    sources=cert["sources"],
                )
            else:
                graph.add_node(
                    dns_entry,
                    root=root_flag,
                    status="Resolves",
                    type="domain",
                    sources=cert["sources"],
                )

            graph.add_edge(cert["id"], dns_entry, type="sans")
            graph.add_edge(dns_entry, cert["id"], type="uses")

    return graph


def main(logger=None):
    """
    Begin Main()
    """
    if logger is None:
        logger = LoggingUtil.create_log(__name__)

    now = datetime.now()
    print("Starting: " + str(now))
    logger.info("Starting...")

    mongo_connector = MongoConnector.MongoConnector()
    mongo_ct = mongo_connector.get_certificate_transparency_connection()
    cert_graphs_collection = mongo_connector.get_cert_graphs_connection()
    jobs_manager = JobsManager.JobsManager(mongo_connector, "create_cert_graphs")
    jobs_manager.record_job_start()

    zones = ZoneManager.get_distinct_zones(mongo_connector)

    parser = argparse.ArgumentParser(
        description="Creates and stores certificate graphs in the database based on one or more sources."
    )
    parser.add_argument(
        "--check_censys",
        action="store_true",
        default=False,
        required=False,
        help="Whether to check the Censys collection in the database",
    )
    parser.add_argument(
        "--check_443_scans",
        action="store_true",
        default=False,
        required=False,
        help="Whether to check the zgrab collection in the database",
    )
    parser.add_argument(
        "--check_ct_scans",
        action="store_true",
        default=False,
        required=False,
        help="Whether to check the CT collection in the database",
    )
    parser.add_argument(
        "--zgrab_version",
        default=2,
        type=int,
        choices=[1, 2],
        metavar="version",
        help="The version of ZGrab used to collect data",
    )
    args = parser.parse_args()

    if args.check_censys is True:
        censys_collection = mongo_connector.get_censys_connection()

    if args.check_443_scans is True:
        zgrab_collection = mongo_connector.get_zgrab_443_data_connection()

    for zone in zones:
        logger.info("Creating: " + zone)
        graph = nx.DiGraph()

        certs_list = {}

        if args.check_ct_scans:
            certs_list = get_current_ct_certificates(mongo_ct, zone)
        if args.check_censys:
            certs_list = add_censys_certificates(censys_collection, zone, certs_list)
        if args.check_443_scans:
            if args.zgrab_version == 1:
                certs_list = add_terminal_zgrab_certificates(
                    mongo_connector, zgrab_collection, zone, certs_list
                )
                certs_list = add_initial_zgrab_certificates(
                    mongo_connector, zgrab_collection, zone, certs_list
                )
            else:
                certs_list = add_terminal_zgrab2_certificates(
                    mongo_connector, zgrab_collection, zone, certs_list
                )
                certs_list = add_initial_zgrab2_certificates(
                    mongo_connector, zgrab_collection, zone, certs_list
                )

        graph = create_nodes(graph, mongo_connector, zone, certs_list)
        data = json_graph.node_link_data(graph)

        my_data = {}
        my_data["links"] = data["links"]
        my_data["nodes"] = data["nodes"]
        my_data["zone"] = zone
        my_data["created"] = datetime.now()

        cert_graphs_collection.delete_one({"zone": zone})
        mongo_connector.perform_insert(cert_graphs_collection, my_data)

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
