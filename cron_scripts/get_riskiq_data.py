#!/usr/bin/python

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
This script has been replaced by the PassiveTotal script.
It is only kept here for historical purposes and it is not maintained.

This script attempts to obtain the list domains based on the email address of the owner.
This script assumes that you have a RiskIQ subscription.
"""

import json
import string
from datetime import datetime

from libs2 import MongoConnector, RiskIQ

# Get an instance of the RiskIQ class
RIQ = RiskIQ.RiskIQ()

def search_riq(email, zone_collection, jobs_collection):
    """
    Search RiskIQ for records associated with the provided admin email address
    """

    print "Searching: " + email
    # Perform the search based on what character the domain ends with.
    # This is based on the assumption that country codes are written in ascii characters.
    # This approach is due to the fact that RiskIQ limits the number of matches per request.

    # Risk IQ has an upper limit on the number of results that can be returned.
    # Therefore, we have to split up the responses based on the alpahbet
    ALPHABET = list(string.ascii_lowercase)

    for i in range(0, len(ALPHABET)):
        results = RIQ.get_whois(email, "*" + ALPHABET[i])

        if results is None:
            print "Error querying letter " + ALPHABET[i]
            jobs_collection.update_one({'job_name': 'get_riskiq_data'},
                                       {'$currentDate': {"updated": True},
                                        "$set": {'status': 'ERROR'}})
            exit(0)

        for j in range(0, results['results']):
            domain = results['domains'][j]['domain'].encode('UTF-8')
            print "Checking domain " + domain

            zone = zone_collection.find_one({'zone': domain})

            if zone is None:
                print "Inserting " + domain
                insert_json = {'zone': domain}
                insert_json['status'] = 'unconfirmed'
                insert_json['sub_zones'] = []
                insert_json['created'] = datetime.now()
                insert_json['updated'] = datetime.now()
                insert_json['reporting_sources'] = ["RiskIQ"]
                insert_json['notes'] = []
                zone_collection.insert_one(insert_json)
            else:
                zone_collection.update_one({'zone': domain},
                                           {'$currentDate': {"updated": True}})


def main():
    """
    Begin Main...
    """
    now = datetime.now()
    print "Starting: " + str(now)

    # Get handles to the database collections
    MC = MongoConnector.MongoConnector()

    # Retrieve the list of Adobe email addresses from the config collection
    config_collection = MC.get_config_connection()
    res = config_collection.find({})

    zone_collection = MC.get_zone_connection()
    jobs_collection = MC.get_jobs_connection()

    # Retrieve the results for each email address
    for i in range(0, len(res[0]['DNS_Admins'])):
        search_riq(res[0]['DNS_Admins'][i], zone_collection, jobs_collection)

    # Record status
    jobs_collection.update_one({'job_name': 'get_riskiq_data'},
                               {'$currentDate': {"updated": True},
                                "$set": {'status': 'COMPLETE'}})

    now = datetime.now()
    print "Complete: " + str(now)

if __name__ == "__main__":
    main()

exit(0)
