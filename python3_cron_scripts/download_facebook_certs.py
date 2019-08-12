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
This script pulls certificate information from the Facebook Graph API assuming that you
have a Facebook Graph account.

Unless otherwise specified, data is written to: /mnt/workspace/ct_facebook/
The hash_based_upload script is no longer necessary for this script.

https://developers.facebook.com/docs/certificate-transparency-api
"""

import argparse
import json
import os
import time
from datetime import datetime

import requests

from libs3 import FacebookConnector, MongoConnector, X509Parser, JobsManager
from libs3.ZoneManager import ZoneManager


def make_https_request(fb_url):
    """
    Utility function so that the script can loop over paged results.
    """
    try:
        req = requests.get(fb_url)
        req.raise_for_status()
    except requests.exceptions.ConnectionError:
        print("Connection Error while fetching the cert list")
        exit(0)
    except requests.exceptions.HTTPError:
        # This occasionally triggers on false domain names
        # For instance, we are holding .web but it isn't officially recognized yet.
        # Therefore, Facebook will error on it but it is safe to continue processing.
        print("HTTP Error while fetching the cert list")
        return None
    except requests.exceptions.RequestException as err:
        print("Request exception while fetching the cert list")
        print(str(err))
        exit(0)

    if req.status_code != 200:
        return None

    return json.loads(req.text)


def fetch_domain(fbc, access_token, zone):
    """
    Fetch the results for the specified zone.
    """
    fb_url = (fbc.BASE_URL + fbc.VERSION + \
             "/certificates?query=") + zone + \
             ("&access_token=" + access_token + \
             "&limit=500" + \
             "")
             # "&fields=cert_hash_sha256,domains,issuer_name,certificate_pem"

    cert_results = []

    while fb_url is not None:
        result = make_https_request(fb_url)

        if result is None:
            print("Error querying: " + zone)
            return None

        cert_results = cert_results + result['data']

        try:
            paging = result['paging']
            fb_url = paging['next']
        except:
            fb_url = None

    return cert_results


def check_save_location(location):
    """
    Check to see if the directory exists.
    If the directory does not exist, it will automatically create it.
    """
    if not os.path.exists(location):
        os.makedirs(location)


def main():
    """
    Begin Main...
    """
    now = datetime.now()
    print("Starting: " + str(now))

    # Make database connections
    mongo_connector = MongoConnector.MongoConnector()
    ct_collection = mongo_connector.get_certificate_transparency_connection()
    jobs_manager = JobsManager.JobsManager(mongo_connector, "facebook_certs")

    jobs_manager.record_job_start()

    file_path = "/mnt/workspace/ct_facebook/"

    fb_connector = FacebookConnector.FacebookConnector()
    access_token = fb_connector.get_facebook_access_token()

    zones = ZoneManager.get_distinct_zones(mongo_connector)
    x509_parser = X509Parser.X509Parser()

    parser = argparse.ArgumentParser(description='Download DNS and/or certificate information from crt.sh.')
    parser.add_argument('--fetch_cert_records', choices=['dbAndSave', 'dbOnly'], default="dbAndSave", help='Indicates whether to download the raw files or just record in the database')
    parser.add_argument('--cert_save_location', required=False, default=file_path, help='Indicates where to save the certificates on disk when choosing dbAndSave')
    args = parser.parse_args()

    check_save_location(args.cert_save_location)

    save_location = args.cert_save_location
    if not save_location.endswith("/"):
        save_location = save_location + "/"

    for zone in zones:
        time.sleep(15)
        results = fetch_domain(fb_connector, access_token, zone)

        if results is None:
            print("ERROR looking up: " + zone)
            continue

        print(zone + ": " + str(len(results)))

        for result in results:
            if args.fetch_cert_records == "dbAndSave":
                cert_f = open(save_location + zone + "_" + result['id'] + ".pem", "w")
                cert_f.write(result['certificate_pem'])
                cert_f.close()

            cert = x509_parser.parse_data(result['certificate_pem'], "facebook")
            cert['facebook_id'] = result['id']

            if ct_collection.find({'fingerprint_sha256': cert['fingerprint_sha256']}).count() == 0:
                ct_collection.insert(cert)
            else:
                if ct_collection.find({'fingerprint_sha256': cert['fingerprint_sha256'], 'facebook_id': result['id'], 'zones': zone}).count() == 0:
                    ct_collection.update({'fingerprint_sha256': cert['fingerprint_sha256']}, {"$set": {'marinus_updated': datetime.now(), 'facebook_id': result['id']}, "$addToSet": {'zones': zone}})

    jobs_manager.record_job_complete()

    now = datetime.now()
    print("Complete: " + str(now))


if __name__ == "__main__":
    main()

