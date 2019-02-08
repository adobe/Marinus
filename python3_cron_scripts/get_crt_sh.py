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
This script is designed to query the crt.sh service. Users should note that there are query limits
on crt.sh which could cause issues when querying a large number of zones in the first run.
Marinus will keep track of which IDs have been previously retrieved in order to limit the requests
to the crt.sh service in subsequent runs. There are also periodic sleep commands in order to pace
out the requests against their service.

Whether the certificates are saved to disk is optional. This script will create the directory for
saving certificates. The default is "/mnt/workspace/crt_sh" but this can be overridden.
"""

import argparse
import json
import os
import requests
import time
from datetime import datetime
from pprint import pprint
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

from libs3 import MongoConnector, DNSManager, GoogleDNS, X509Parser, JobsManager
from libs3.ZoneManager import ZoneManager

def requests_retry_session(
    retries=5,
    backoff_factor=7,
    status_forcelist=[408, 500, 502, 503, 504],
    session=None,
):
    session = session or requests.Session()
    retry = Retry(
        total=retries,
        read=retries,
        connect=retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('https://', adapter)
    return session


def make_https_request(url, download=False):
    """
    Utility function for making HTTPS requests.
    """
    try:
        req = requests_retry_session().get(url)
    except Exception as ex:
        print("Connection died after 5 tries")
        print(str(ex))
        exit(1)

    if req.status_code != 200:
        return None

    if download:
        return req.content

    return req.text


def get_tracked_zone(name, zones):
    """
    What is the tracked zone for the provided hostname?
    """
    for zone in zones:
        if name.endswith("." + zone) or name == zone:
            return zone

    return None


def add_new_domain_names(hostnames, zones, mongo_connector):
    """
    Perform a GoogleDNS lookup on all identified domain names
    and add them to the DNS tracker.
    """
    google_dns = GoogleDNS.GoogleDNS()
    dns_manager = DNSManager.DNSManager(mongo_connector)

    for hostname in hostnames:
        results = google_dns.fetch_DNS_records(hostname)

        if results != []:
            for result in results:
                temp_zone = get_tracked_zone(result['fqdn'], zones)
                if temp_zone is not None:
                    new_record = {"fqdn": result['fqdn']}
                    new_record['zone'] = temp_zone
                    new_record['created'] = datetime.now()
                    new_record['type'] = result['type']
                    new_record['value'] = result['value']
                    new_record['status'] = 'unknown'
                    dns_manager.insert_record(new_record, "ssl")


def get_list_of_existing_certificates(ct_collection):
    """
    We don't want to re-download data that we already have.
    Therefore, we get the list of known crt_sh_ids from the database.
    """
    existing_ids = []
    results = ct_collection.find({'crt_sh_min_id': {"$exists": True}}, {'crt_sh_min_id': 1})

    for result in results:
        if result['crt_sh_min_id'] not in existing_ids:
            existing_ids.append(result['crt_sh_min_id'])

    return existing_ids


def get_cert_zones(cert, zones):
    """
    Find the relevant certificate zones
    """
    cert_zones = []

    if 'subject_common_names' in cert:
        for cn in cert['subject_common_names']:
            for zone in zones:
                if cn == zone or cn.endswith("." + zone):
                    if zone not in cert_zones:
                        cert_zones.append(zone)

    if 'subject_dns_names' in cert:
        for cn in cert['subject_dns_names']:
            for zone in zones:
                if cn == zone or cn.endswith("." + zone):
                    if zone not in cert_zones:
                        cert_zones.append(zone)

    return cert_zones


def add_new_certificate_values(new_ids, ct_collection, zones, save_location=None):
    """
    Add new certificate values to the database.
    """
    x509_parser = X509Parser.X509Parser()

    existing_ids = get_list_of_existing_certificates(ct_collection)

    for min_cert_id in new_ids:
        if min_cert_id not in existing_ids:
            # Pace out certificate requests against their service
            time.sleep(2)

            c_file = make_https_request("https://crt.sh/?d=" + str(min_cert_id), True)

            if c_file is None:
                print("ERROR: Failed communicating with crt.sh. Skipping cert_id: " + str(min_cert_id))
                continue

            if save_location is not None:
                open(save_location + str(min_cert_id) + ".crt", "wb").write(c_file)

            cert = x509_parser.parse_data(c_file, "crt_sh")
            if cert is None:
                print("ERROR: Could not parse certificate for: " + str(min_cert_id) + ". Skipping for now.")
                continue

            cert_zones = get_cert_zones(cert, zones)
            print("Adding crt.sh id: " + str(min_cert_id) + " SHA256: " + cert['fingerprint_sha256'])

            if ct_collection.find({"fingerprint_sha256": cert['fingerprint_sha256']}).count() != 0:
                # The certificate exists in the database but does not have crt_sh id and/or zones
                ct_collection.update_one({"fingerprint_sha256": cert['fingerprint_sha256']}, {"$set": {"crt_sh_min_id": min_cert_id, "zones": cert_zones}, "$addToSet": {'sources': 'crt_sh'}})
            else:
                # Add the new certificate
                cert['crt_sh_min_id'] = min_cert_id
                cert['zones'] = cert_zones
                ct_collection.insert_one(cert)


def check_save_location(save_location):
    """
    Check to see if the directory exists.
    If the directory does not exist, it will automatically create it.
    """
    if not os.path.exists(save_location):
        os.makedirs(save_location)


def main():
    now = datetime.now()
    print("Starting: " + str(now))

    # Set up the common objects
    mongo_connector = MongoConnector.MongoConnector()
    ct_collection = mongo_connector.get_certificate_transparency_connection()
    zones = ZoneManager.get_distinct_zones(mongo_connector)
    jobs_manager = JobsManager.JobsManager(mongo_connector, "get_crt_sh")
    jobs_manager.record_job_start()

    save_location = "/mnt/workspace/crt_sh"

    parser = argparse.ArgumentParser(description='Download DNS and/or certificate information from crt.sh.')
    parser.add_argument('--fetch_dns_records', action='store_true', help='Indicates whether to add DNS entries to the database')
    parser.add_argument('--download_methods', choices=['dbAndSave', 'dbOnly'], help='Indicates whether to download the raw files or just record in the database.')
    parser.add_argument('--cert_save_location', required=False, default=save_location, help='Indicates where to save the certificates on disk when choosing dbAndSave')
    args = parser.parse_args()

    if args.cert_save_location:
        save_location = args.cert_save_location
        if not save_location.endswith("/"):
            save_location = save_location + "/"

    if args.download_methods == 'dbAndSave':
        check_save_location(save_location)

    for zone in zones:
        # Pace out requests so as not to DoS crt.sh and Google DNS
        time.sleep(5)

        # This could be done with backoff but we don't want to be overly aggressive.
        json_result = make_https_request("https://crt.sh/?q=%25." + zone + "&output=json")
        if json_result is None:
            print("Can't find result for: " + zone)
            json_result = "{}"

        json_data = json.loads(json_result)

        new_names = []
        new_ids = []
        for entry in json_data:
            if entry['min_cert_id'] not in new_ids:
                new_ids.append(entry['min_cert_id'])

            if "*" not in entry["name_value"] and entry["name_value"] not in new_names:
                new_names.append(entry["name_value"])

    if args.fetch_dns_records:
        add_new_domain_names(new_names, zones, mongo_connector)

    if args.download_methods == "dbAndSave":
        add_new_certificate_values(new_ids, ct_collection, zones, save_location)
    elif args.download_methods == "dbOnly":
        add_new_certificate_values(new_ids, ct_collection, zones, None)

    # Set isExpired for any entries that have recently expired.
    ct_collection.update({"not_after": {"$lt": datetime.utcnow()}, "isExpired": False},
                        {"$set": {"isExpired": True}}, multi=True)

    jobs_manager.record_job_complete()

    now = datetime.now()
    print("Ending: " + str(now))


if __name__ == "__main__":
    main()

