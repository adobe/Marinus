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
This script is a template for users who want to pull data from their Splunk logs.
It is not an implementation for any specific type of log. It is just an example template
to show people how to use the SplunkQueryManager to read from Splunk.
It is up to the user to know their Splunk formats and how their information might be
useful in Marinus.
"""

import json

from datetime import datetime

from libs3 import MongoConnector, SplunkQueryManager, JobsManager, DNSManager


def parse_splunk_results(results, dns_manager, splunk_collection):
    """
    Put your logic for parsing splunk results here...
    Depending on the data, you might store it in the master DNS table using the dns_manager.
    Alternatively, you might store it in its Splunk collection. Using the splunk_collection is not required.
    """
    for result in results:
        if isinstance(result, dict):
            my_data = result['my_field']
            print(str(my_data))
            # Do what is appropriate for your data here.


def main():
    now = datetime.now()
    print("Starting: " + str(now))

    mongo_connector = MongoConnector.MongoConnector()
    splunk_query_manager = SplunkQueryManager.SplunkQueryManager()
    splunk_collection = mongo_connector.get_splunk_connection()
    dns_manager = DNSManager.DNSManager(mongo_connector)

    jobs_manager = JobsManager.JobsManager(mongo_connector, "get_splunk_data")
    jobs_manager.record_job_start()

    print ("Starting Splunk Query")

    results_per_page = 100

    # Put your custom Splunk search query here.
    results = splunk_query_manager.do_search('search index=...', results_per_page)

    print("Processing " + str(splunk_query_manager.RESULTCOUNT) + " results")

    parse_splunk_results(results, dns_manager, splunk_collection)

    while True:
        results = splunk_query_manager.get_next_page()
        if results is None:
            break
        parse_splunk_results(results, dns_manager, splunk_collection)


    jobs_manager.record_job_complete()

    now = datetime.now()
    print("Complete: " + str(now))


if __name__ == "__main__":
    main()
