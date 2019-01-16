#!/usr/bin/python3

# Copyright 2018 Adobe. All rights reserved.
# This file is licensed to you under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License. You may obtain a copy
# of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR REPRESENTATIONS
# OF ANY KIND, either express or implied. See the License for the specific language
# governing permissions and limitations under the License.

"""
This script will do searches against the PassiveTotal whois database
based on known email addresses. It replaces the RiskIQ script that did
the same thing. This is one way to find out about new root domains.

PassiveTotal includes historical data for domains that have expired.
Unfortunately, the "expiresAt" property is often not accurate and
cannot be used to reliably identify whether a domain is currently
registered. Identification of expired records happens in a later script.

This script requires a PassiveTotal subscription.
"""

import json
import re
from datetime import datetime

from libs3 import MongoConnector, PassiveTotal, ZoneIngestor


def search_pt_email(email, pt, zi, jobs_collection):
    """
    Search PassiveTotal for records associated with the provided email address.
    """
    print("Searching: " + email)
    results = pt.get_whois(email)

    if results is None:
        print("Error querying email: " + email)
        jobs_collection.update_one({'job_name': 'get_passivetotal_data'},
                                   {'$currentDate': {"updated": True},
                                    "$set": {'status': 'ERROR'}})
        exit(0)

    print("Results for " + email + ": " + str(len(results['results'])))

    for j in range(0, len(results['results'])):
        domain = results['results'][j]['domain'].encode('utf-8').decode('utf8')
        print("Checking domain: " + domain)

        if re.match(r"^([0-9]{1,3}\.){3}[0-9]{1,3}\/\d\d$", domain):
            print("Matched IP address. Skipping...")
            continue

        zi.add_zone(domain, 'PassiveTotal')


def search_pt_org(org, pt, zi, jobs_collection):
    """
    Search PassiveTotal for records associated with the provided organization.
    """
    print("Searching: " + org)
    results = pt.get_organization(org)

    if results is None:
        print("Error querying org: " + org)
        jobs_collection.update_one({'job_name': 'get_passivetotal_data'},
                                   {'$currentDate': {"updated": True},
                                    "$set": {'status': 'ERROR'}})
        exit(0)

    print("Results for " + org + ": " + str(len(results['results'])))

    for j in range(0, len(results['results'])):
        domain = results['results'][j]['domain'].encode('utf-8').decode('utf8')
        print("Checking domain: " + domain)

        if re.match(r"^([0-9]{1,3}\.){3}[0-9]{1,3}\/\d\d$", domain) or re.match(r"^([0-9]{1,3}\.){3}[0-9]{1,3}$", domain):
            print("Matched IP address. Skipping...")
            continue

        zi.add_zone(domain, 'PassiveTotal')


def main():
    """
    Begin Main...
    """
    now = datetime.now()
    print("Starting: " + str(now))

    # Obtain the list of known email addresses from the config collection
    MC = MongoConnector.MongoConnector()
    PT = PassiveTotal.PassiveTotal()
    zi = ZoneIngestor.ZoneIngestor()
    config_collection = MC.get_config_connection()
    res = config_collection.find({})

    jobs_collection = MC.get_jobs_connection()

    # Perform a search for each email address
    for i in range(0, len(res[0]['DNS_Admins'])):
        search_pt_email(res[0]['DNS_Admins'][i], PT, zi, jobs_collection)

    for i in range(0, len(res[0]['Whois_Orgs'])):
        search_pt_org(res[0]['Whois_Orgs'][i], PT, zi, jobs_collection)

    # Record status
    jobs_collection.update_one({'job_name': 'get_passivetotal_data'},
                               {'$currentDate': {"updated": True},
                                "$set": {'status': 'COMPLETE'}})

    now = datetime.now()
    print("Complete: " + str(now))


if __name__ == "__main__":
    main()

exit(0)
