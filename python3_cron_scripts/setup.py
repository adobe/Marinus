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
This script is for one time tasks related to the configuration of the Marinus MongoDB.
It can assist in the configuration of Marinus users, zones, and organization information.
The connector.config file must exist and contain the information for the primary Marinus database.
This script is not intended to be run as a cron task.
"""

import argparse
import ipaddress
import random
import string
from datetime import datetime

from libs3 import JobsManager, MongoConnector, ZoneIngestor


def create_collections(m_connection):
    """
    MongoDB won't create a collection until data is inserted.
    Therefore, this function just warns if the setup has been run before.
    """
    collections = [
        "akamai_ips",
        "all_dns",
        "all_ips",
        "aws_ips",
        "censys",
        "cert_graphs",
        "cidr_graphs",
        "config",
        "ct_certs",
        "dead_dns",
        "get_route53",
        "gcp_ips",
        "graphs_data",
        "graphs_docs",
        "graphs_links",
        "groups",
        "iblox_a_records",
        "iblox_aaaa_records",
        "iblox_cname_records",
        "iblox_host_records",
        "iblox_mx_records",
        "iblox_extattr_records",
        "iblox_txt_records",
        "ip_zones",
        "ipv6_zones",
        "jobs",
        "sessions",
        "sonar_rdns",
        "tpd_graphs",
        "tpds",
        "users",
        "virustotal",
        "whois",
        "zgrab_443_data",
        "zgrab_80_data",
        "zgrab_port_data",
        "zones",
    ]

    for collection in collections:
        if m_connection[collection].count_documents({}) > 0:
            print("WARNING: The " + collection + " already exists.")


def create_job_collection(mongo_connector):
    """
    For people who want to run every possible script, this will pre-populate the collection with all of the currently known scripts.
    If you will only be running a subset of scripts, this step can be skipped since the individual scripts will create their own entries.
    """
    jobs_manager = JobsManager.JobsManager(mongo_connector, "")

    script_names = [
        "remote_download",
        "get_virustotal_data",
        "get_riskiq_data",
        "get_iblox_cname",
        "get_iblox_host",
        "get_iblox_alpha_zones",
        "get_aws_data",
        "send_remote_server",
        "remove_expired_entries",
        "get_iblox_a",
        "get_data_by_cidr_dns",
        "get_crt_sh",
        "get_sonar_data_rdns",
        "get_sonar_data_dns-any",
        "get_data_by_cidr_rdns",
        "get_passivetotal_data",
        "create_tpd_graphs",
        "create_netaddr_graphs",
        "get_external_cnames",
        "create_graphs2",
        "extract_mx_records",
        "extract_ssl_domains",
        "common_crawl_graph",
        "dead_dns_cleanup",
        "create_cert_graphs",
        "get_infoblox_zone_extattrs",
        "get_infoblox_cname_extattrs",
        "get_azure_data",
        "get_infoblox_host_extattrs",
        "get_infoblox_a_extattrs",
        "get_iblox_mx",
        "get_iblox_txt",
        "get_iblox_aaaa",
        "marinus_dns",
        "get_sonar_data_dns-a",
        "get_ultradns_zones",
        "get_ultradns_zones_info",
        "mark_expired",
        "whois_lookups",
        "sonar_round_two",
        "get_infoblox_aaaa_extattrs",
        "extract_vt_domains",
        "facebook_certs",
        "fetch_azure_dns",
        "upload_akamai_data",
        "zgrab_domain-80",
        "zgrab_domain-443",
        "zgrab_ip-80",
        "zgrab_ip-443",
        "zgrab_port_ip-22",
        "zgrab_port_ip-25",
        "zgrab_port_ip-443",
        "zgrab_port_ip-465",
    ]

    for job_name in script_names:
        jobs_manager.create_job(job_name)


def create_user(mongo_connector, username):
    """
    The user table is used for Single Sign On deployments of the Marinus UI and contains the API key information.
    By default, an account for "marinus" is established regardless of whether there is an SSO account for marinus.
    This is because the "marinus" user is the default user when Marinus is used in development mode.
    """
    user_collection = mongo_connector.get_users_connection()

    if user_collection.count_documents({}) > 0:
        print("WARNING: The user collection already exists. Skipping initialization.")
        return

    now = datetime.now()

    existing_check = user_collection.count_documents({"userid": username})
    if existing_check != 0:
        print("User already exists!")
        return

    randomValue = "".join(
        [random.choice(string.ascii_letters + string.digits) for n in range(32)]
    )

    user_collection.insert_one(
        {"userid": username, "status": "active", "created": now, "apiKey": randomValue}
    )


def create_first_groups(mongo_connector, username):
    """
    The default Marinus install supports two types of groups: admins and data-admins.
    The group authorization checks exist in both development and production modes.
    This will list the "marinus" user as the creator for those groups and add "marinus" as a member.
    The "marinus" user is the default user when Marinus is in local development mode.
    """
    group_collection = mongo_connector.get_groups_connection()

    if group_collection.count_documents({}) > 0:
        print("WARNING: The group collection already exists. Skipping initialization.")
        return

    now = datetime.now()

    existing_check = group_collection.count_documents({"name": "admin"})
    if existing_check != 0:
        print(
            "The groups have already been created! You should add users to the groups instead."
        )
        return

    members = [username]
    admins = [username]

    group_collection.insert_one(
        {
            "name": "admin",
            "status": "active",
            "creation_date": now,
            "updated": now,
            "creator": username,
            "members": members,
            "admins": admins,
        }
    )
    group_collection.insert_one(
        {
            "name": "data_admin",
            "status": "active",
            "creation_date": now,
            "updated": now,
            "creator": username,
            "members": members,
            "admins": admins,
        }
    )


def add_user_to_group(mongo_connector, username, group):
    """
    This adds a user to the provided group as a non-privileged member of that group.
    This function assumes that the group has already been verified to exist by the argparse restrictions.
    """
    user_collection = mongo_connector.get_users_connection()
    group_collection = mongo_connector.get_groups_connection()
    now = datetime.now()

    user_exists = user_collection.count_documents({"userid": username})
    if user_exists == 0:
        print("User does not yet exist. Please create the user first.")
        return

    update_object = {}
    update_object["$addToSet"] = {}
    update_object["$addToSet"]["members"] = username
    update_object["$set"] = {}
    update_object["$set"]["updated"] = now

    group_collection.update_one({"name": group}, update_object)


def add_admin_to_group(mongo_connector, username, group):
    """
    This will add a new admin to a group. An admin has the authority to add additional members to the group.
    This functionality is intended for a future feature where additional sub-groups beyond admin and data-admin are supported.
    """
    user_collection = mongo_connector.get_users_connection()
    group_collection = mongo_connector.get_groups_connection()
    now = datetime.now()

    user_exists = user_collection.count_documents({"userid": username})
    if user_exists == 0:
        print("User does not yet exist. Please create the user first.")
        return

    group_collection.update_one(
        {"name": group}, {"$addToSet": {"admins": username}, "$set": {"updated": now}}
    )


def create_config_collection(mongo_collection):
    """
    Marinus maintains a configuration which tells it meta information about the organizations that it tracks.
    This includes registration information that would be included in Whois records and TLS certificates.
    This function initializes that table with empty values and is part of the initial set up process.
    """
    new_config = {}
    new_config["DNS_Admins"] = []
    new_config["SSL_Orgs"] = []
    new_config["Whois_Orgs"] = []
    new_config["Whois_Name_Servers"] = []
    now = datetime.now()
    new_config["updated"] = now

    config_collection = mongo_collection.get_config_connection()
    if config_collection.count_documents({}) > 0:
        print("WARNING: The config collection already exists. Skipping initialiation.")
        return

    config_collection.insert_one(new_config)


def add_tls_org(mongo_connector, org):
    """
    For some scripts, Marinus searches the Distinguished Name values of certificates.
    This specifies the Organization values that Marinus will use when searching the Distinguished Name fields.
    """
    config_collection = mongo_connector.get_config_connection()
    now = datetime.now()

    print("Adding TLS Org: " + org)
    config_collection.update_many(
        {}, {"$addToSet": {"SSL_Orgs": org}, "$set": {"updated": now}}
    )


def add_dns_admin(mongo_connector, dns_admin):
    """
    Whois registrations can be searched based on the contacts associated with the domain.
    This will add an email address of the DNS Admin to list for contact based searches.
    This is saved in the config collection.
    """
    config_collection = mongo_connector.get_config_connection()
    now = datetime.now()

    print("Adding DNS Admin: " + dns_admin)
    config_collection.update_many(
        {}, {"$addToSet": {"DNS_Admins": dns_admin}, "$set": {"updated": now}}
    )


def add_whois_org(mongo_connector, org):
    """
    Whois registrations can be searched based on the name of the registering organization.
    This will add a company name to the list of organizations that will be searched.
    This is saved in the config collection.
    """
    config_collection = mongo_connector.get_config_connection()
    now = datetime.now()

    print("Adding Whois Org: " + org)
    config_collection.update_many(
        {}, {"$addToSet": {"Whois_Orgs": org}, "$set": {"updated": now}}
    )


def add_whois_name_server(mongo_connector, name_server):
    """
    International Whois Servers no longer show the names of the registering organization.
    This provides the opportunity to match based on the name server instead.
    This is saved in the config collection.
    """
    config_collection = mongo_connector.get_config_connection()
    now = datetime.now()

    print("Adding Whois Name Server: " + name_server.lower())
    config_collection.update_many(
        {},
        {
            "$addToSet": {"Whois_Name_Servers": name_server.lower()},
            "$set": {"updated": now},
        },
    )


def create_zone(zone):
    """
    A zone refers to a root domain such as "example.org" or "example.net").
    It does not refer to fully qualified domain names (FQDNs) such as "www.example.org" or "images.example.net".
    Marins correlates records from different sources based on their zone.
    This will add a new zone for Marinus to track in the zones collection.
    """
    ZI = ZoneIngestor.ZoneIngestor()

    print("Adding zone: " + zone)
    ZI.add_zone(zone)


def create_IPv4_zone(mongo_collection, cidr):
    """
    When examinging reverse DNS records, Marinus can match based on the IP address range owned by the organization.
    This will an IPv4 CIDR to the list of the organizations known ranges.
    This information is stored in the ip_zones collection.
    """
    ipv4_zone_collection = mongo_collection.get_ipzone_connection()
    now = datetime.now()

    double_check = ipv4_zone_collection.count_documents({"zone": cidr})
    if double_check != 0:
        print("CIDR value: " + cidr + " already exists!")
        return

    try:
        foo = ipaddress.ip_network(cidr)
    except:
        print("Error: Not a valid CIDR value")
        return

    if type(foo) is not ipaddress.IPv4Network:
        print("Not an IPv4 Address")
        return

    new_entry = {}
    new_entry["status"] = "unconfirmed"
    new_entry["source"] = "manual"
    new_entry["updated"] = now
    new_entry["created"] = now
    new_entry["notes"] = []
    new_entry["zone"] = cidr

    print("Inserting IPv4 zone: " + cidr)
    ipv4_zone_collection.insert_one(new_entry)


def create_IPv6_zone(mongo_collection, cidr):
    """
    When examinging reverse DNS records, Marinus can match based on the IP address range owned by the organization.
    This will an IPv6 CIDR to the list of the organizations known ranges.
    This information is stored in the ipv6_zones collection.
    """
    ipv6_zone_collection = mongo_collection.get_ipv6_zone_connection()
    now = datetime.now()

    double_check = ipv6_zone_collection.count_documents({"zone": cidr})
    if double_check != 0:
        print("CIDR value: " + cidr + " already exists!")
        return

    try:
        foo = ipaddress.ip_network(cidr)
    except:
        print("Error: Not a valid IPv6 CIDR value")
        return

    if type(foo) is not ipaddress.IPv6Network:
        print("Not an IPv6 Address")
        return

    new_entry = {}
    new_entry["status"] = "unconfirmed"
    new_entry["source"] = "manual"
    new_entry["updated"] = now
    new_entry["created"] = now
    new_entry["notes"] = []
    new_entry["zone"] = cidr

    print("Inserting IPv6 zone: " + cidr)
    ipv6_zone_collection.insert_one(new_entry)


def add_new_job(mongo_connector, job_name):
    """
    Add a new job to the jobs table.
    """
    jobs_manager = JobsManager.JobsManager(mongo_connector, "")
    jobs_manager.create_job(job_name)


def main():
    """
    Begin the main function.
    """
    parser = argparse.ArgumentParser(
        description="Setup utility for the Marinus MongoDB instance."
    )
    parser.add_argument(
        "--create_collections",
        help="Initialize the collections in the database.",
        action="store_true",
    )
    parser.add_argument(
        "--add_zone",
        metavar="ROOT_DOMAIN",
        help="Add a new domain zone to Marinus",
        action="store",
        type=str,
    )
    parser.add_argument(
        "--add_IPv4_network",
        metavar="IPv4_CIDR",
        help="Add an IPv4 CIDR zone to Marinus",
        action="store",
        type=str,
    )
    parser.add_argument(
        "--add_IPv6_network",
        metavar="IPv6_CIDR",
        help="Add an IPv6 CIDR zone to Marinus",
        action="store",
        type=str,
    )
    parser.add_argument(
        "--add_tls_org",
        metavar="TLS_ORGANIZATION_VALUE",
        help="Add a TLS organization to the Marinus config",
        action="store",
        type=str,
    )
    parser.add_argument(
        "--add_whois_org",
        metavar="WHOIS_ORGANIZATION_VALUE",
        help="Add a Whois organization to the Marinus config",
        action="store",
        type=str,
    )
    parser.add_argument(
        "--add_whois_name_server",
        metavar="WHOIS_NAME_SERVER_VALUE",
        help="Add a Whois name server to the Marinus config",
        action="store",
        type=str,
    )
    parser.add_argument(
        "--add_dns_admin",
        metavar="DNS_ADMIN_EMAIL",
        help="Add a DNS administrator to the Marinus config",
        action="store",
        type=str,
    )
    parser.add_argument(
        "--add_user", help="Add a SSO userid to Marinus", action="store_true"
    )
    parser.add_argument(
        "--add_user_to_group", help="Assign a user to a group", action="store_true"
    )
    parser.add_argument(
        "--add_group_admin", help="Assign another admin to a group", action="store_true"
    )
    parser.add_argument(
        "--username",
        metavar="USERNAME",
        help="The username for add_user or add_user_to_group",
        action="store",
        type=str,
    )
    parser.add_argument(
        "--group",
        metavar="GROUP",
        choices=["admin", "data_admin"],
        help="The group_value for add_user_to_group",
        action="store",
        type=str,
    )
    parser.add_argument(
        "--add_new_job",
        metavar="PYTHON_SCRIPT_NAME",
        help="Add a new tracked script to the jobs table",
        action="store",
        type=str,
    )

    args = parser.parse_args()

    mongo_connector = MongoConnector.MongoConnector()

    if args.create_collections:
        create_collections(mongo_connector.m_connection)
        create_job_collection(mongo_connector)
        create_config_collection(mongo_connector)
        create_user(mongo_connector, "marinus")
        create_first_groups(mongo_connector, "marinus")
    elif args.add_user_to_group:
        if args.username == None or args.group == None:
            print("A username and group value must be provided")
            exit(1)
        add_user_to_group(mongo_connector, args.username, args.group)
    elif args.add_group_admin:
        if args.username == None or args.group == None:
            print("A username and group value must be provided")
            exit(1)
        add_admin_to_group(mongo_connector, args.username, args.group)
    elif args.add_user:
        if args.username == None:
            print("A username must be provided!")
            exit(1)
        create_user(mongo_connector, args.username)
    elif args.add_zone:
        create_zone(args.add_zone)
    elif args.add_IPv4_network:
        create_IPv4_zone(mongo_connector, args.add_IPv4_network)
    elif args.add_IPv6_network:
        create_IPv6_zone(mongo_connector, args.add_IPv6_network)
    elif args.add_tls_org is not None:
        add_tls_org(mongo_connector, args.add_tls_org)
    elif args.add_whois_org is not None:
        add_whois_org(mongo_connector, args.add_whois_org)
    elif args.add_whois_name_server is not None:
        add_whois_name_server(mongo_connector, args.add_whois_name_server)
    elif args.add_dns_admin is not None:
        add_dns_admin(mongo_connector, args.add_dns_admin)
    elif args.add_new_job is not None:
        add_new_job(mongo_connector, args.add_new_job)
    else:
        print("ERROR: Unrecognized action")


if __name__ == "__main__":
    main()
