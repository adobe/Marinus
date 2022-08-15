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
This script is for Azure customers who use Azure DNS and have credentials to the service.

The script will iterate through all zones for the configured subscription ID / tenant ID.
It will insert the identified public records uses the source of "azure-" + resourceGroups.

This script is based on the Azure Python SDK:
https://docs.microsoft.com/en-us/python/api/azure-mgmt-dns/azure.mgmt.dns?view=azure-python
"""

import logging
from datetime import datetime

from azure.mgmt.dns.models import ZoneType
from libs3 import AzureConnector, DNSManager, JobsManager, MongoConnector, ZoneIngestor
from libs3.LoggingUtil import LoggingUtil
from libs3.ZoneManager import ZoneManager


def split_id(url_id):
    """
    Data for the response is encoded in the ID URL
    """
    parts = url_id.split("/")
    data = {}
    for i in range(1, len(parts) - 1, 2):
        data[parts[i]] = parts[i + 1]
    return data


def process_soa_record(logger, entry):
    """
    Convert the Azure SOA record object into Marinus information
    """
    soa = entry.soa_record
    value = soa.host[:-1]
    value += " " + soa.email
    value += " " + str(soa.serial_number)
    value += " " + str(soa.refresh_time)
    value += " " + str(soa.retry_time)
    value += " " + str(soa.expire_time)
    value += " " + str(soa.minimum_ttl)
    logger.debug("SOA: " + value)

    results = []
    results.append({"fqdn": entry.fqdn[:-1], "type": "soa", "value": value})

    return results


def process_arecords(logger, entry):
    """
    Convert the Azure A record object into Marinus information
    """
    results = []
    for arecord in entry.arecords:
        logger.debug("A: " + entry.fqdn[:-1] + " : " + arecord.ipv4_address)
        results.append(
            {"fqdn": entry.fqdn[:-1], "type": "a", "value": arecord.ipv4_address}
        )

    return results


def process_ns_records(logger, entry):
    """
    Convert the Azure NS record object into Marinus information
    """
    results = []
    for ns_record in entry.ns_records:
        logger.debug("NS: " + entry.fqdn[:-1] + " : " + ns_record.nsdname)
        results.append(
            {"fqdn": entry.fqdn[:-1], "type": "ns", "value": ns_record.nsdname[:-1]}
        )

    return results


def process_mx_records(logger, entry):
    """
    Convert the Azure MX record object into Marinus information
    """
    results = []
    for mx_record in entry.mx_records:
        value = str(mx_record.preference) + " " + mx_record.exchange
        logger.debug("MX: " + entry.fqdn[:-1] + " : " + value)
        results.append({"fqdn": entry.fqdn[:-1], "type": "mx", "value": value})

    return results


def process_cname_record(logger, entry):
    """
    Convert the Azure CNAME record object into Marinus information
    """
    logger.debug("CNAME: " + entry.fqdn[:-1] + " : " + entry.cname_record.cname)
    results = []
    results.append(
        {"fqdn": entry.fqdn[:-1], "type": "cname", "value": entry.cname_record.cname}
    )
    return results


def process_aaaa_records(logger, entry):
    """
    Convert the Azure AAAA record object into Marinus information
    """
    results = []
    for aaaa_record in entry.aaaa_records:
        logger.debug("AAAA: " + entry.fqdn[:-1] + " : " + aaaa_record.ipv6_address)
        results.append(
            {"fqdn": entry.fqdn[:-1], "type": "aaaa", "value": aaaa_record.ipv6_address}
        )

    return results


def process_txt_records(logger, entry):
    """
    Convert the Azure TXT record object into Marinus information
    """
    results = []
    for txt_record in entry.txt_records:
        text_value = ""
        for txt in txt_record.value:
            text_value += txt
        logger.debug("TXT: " + entry.fqdn[:-1] + " : " + text_value)
        results.append({"fqdn": entry.fqdn[:-1], "type": "txt", "value": text_value})

    return results


def process_ptr_records(logger, entry):
    """
    Convert the Azure PTR record object into Marinus information
    """
    results = []
    for ptr_record in entry.ptr_records:
        logger.debug("PTR: " + entry.fqdn + " : " + ptr_record.ptrdname)
        results.append(
            {"fqdn": entry.fqdn[:-1], "type": "ptr", "value": ptr_record.ptrdname}
        )

    return results


def process_srv_records(logger, entry):
    """
    Convert the Azure SRV record object into Marinus information
    """
    results = []
    for srv_record in entry.srv_records:
        value = (
            str(srv_record.priority)
            + " "
            + str(srv_record.weight)
            + " "
            + str(srv_record.port)
            + " "
            + srv_record.target
        )
        logger.debug("SRV: " + value)
        results.append({"fqdn": entry.fqdn[:-1], "type": "srv", "value": value})

    return results


def extract_record_set_value(logger, field, entry):
    """
    Call the approprite function for the given field type.
    """
    if field == "A":
        # The missing underscore is intentional. MS was inconsistent.
        return process_arecords(logger, entry)
    elif field == "AAAA":
        return process_aaaa_records(logger, entry)
    elif field == "MX":
        return process_mx_records(logger, entry)
    elif field == "NS":
        return process_ns_records(logger, entry)
    elif field == "PTR":
        return process_ptr_records(logger, entry)
    elif field == "SRV":
        return process_srv_records(logger, entry)
    elif field == "TXT":
        return process_txt_records(logger, entry)
    elif field == "CNAME":
        return process_cname_record(logger, entry)
    elif field == "SOA":
        return process_soa_record(logger, entry)
    else:
        logger.warning("Unknown Record Set Type")


def main(logger=None):
    """
    Begin Main...
    """
    if logger is None:
        logger = LoggingUtil.create_log(__name__)

    now = datetime.now()
    print("Starting: " + str(now))
    logger.info("Starting...")

    azure_connector = AzureConnector.AzureConnector()
    mongo_connector = MongoConnector.MongoConnector()
    dns_manager = DNSManager.DNSManager(mongo_connector)
    zone_ingestor = ZoneIngestor.ZoneIngestor()
    jobs_manager = JobsManager.JobsManager(mongo_connector, "fetch_azure_dns")
    jobs_manager.record_job_start()

    current_zones = ZoneManager.get_distinct_zones(mongo_connector)

    resource_client = azure_connector.get_resources_client()
    resources = []

    # The resource list is not currently used.
    for item in resource_client.resource_groups.list():
        resources.append(item.name)

    dns_client = azure_connector.get_dns_client()

    zones = dns_client.zones.list()

    # The type of records the Azure DNS will let you configure
    record_types = {
        "A": "arecords",
        "AAAA": "aaaa_records",
        "MX": "mx_records",
        "NS": "ns_records",
        "PTR": "ptr_records",
        "SRV": "srv_records",
        "TXT": "txt_records",
        "CNAME": "cname_record",
        "SOA": "soa_record",
    }

    for zone in zones:
        logger.info("Zone: " + zone.name)
        data = split_id(zone.id)

        if zone.zone_type == ZoneType.public:
            logger.info(zone.name + " is public:")

            if zone.name not in current_zones:
                logger.debug("Creating zone: " + zone.name)
                zone_ingestor.add_zone(zone.name, "azure:" + data["resourceGroups"])

            try:
                logger.info("ResourceGroup: " + data["resourceGroups"])
                records = dns_client.record_sets.list_all_by_dns_zone(
                    data["resourceGroups"], zone.name
                )
                for entry in records:
                    # The record_data id value ends in rtype/rvalue so you must guess the rtype
                    record_data = split_id(entry.id)
                    for rtype in record_types:
                        if rtype in record_data:
                            results = extract_record_set_value(logger, rtype, entry)
                            for result in results:
                                result["zone"] = zone.name
                                result["created"] = datetime.now()
                                result["status"] = "confirmed"
                                dns_manager.insert_record(
                                    result, "azure:" + data["resourceGroups"]
                                )
            except:
                logger.warning("No records found")

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
