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
This script runs daily to pull down the list of AWS CIDRs and uploads them to the Marinus database.
It has no dependencies on other scripts.
"""

import json
from datetime import datetime
import requests
from libs3 import MongoConnector

# Make database connections
mongo_connector = MongoConnector.MongoConnector()

JSON_LOCATION = "https://ip-ranges.amazonaws.com/ip-ranges.json"

def main():
    """
    Begin main...
    """
    now = datetime.now()
    print ("Starting: " + str(now))

    jobs_collection = mongo_connector.get_jobs_connection()

    # Download the JSON file
    req = requests.get(JSON_LOCATION)

    if req.status_code != 200:
        print("Bad Request")
        jobs_collection.update_one({'job_name': 'get_aws_data'},
                                   {'$currentDate': {"updated" :True},
                                    "$set": {'status': 'ERROR'}})
        exit(0)


    # Convert the response to JSON
    json_data = json.loads(req.text)

    # Replace the old entries with the new entries
    aws_collection = mongo_connector.get_aws_ips_connection()
    aws_collection.remove({})
    aws_collection.insert(json_data)

    # Record status
    jobs_collection.update_one({'job_name': 'get_aws_data'},
                               {'$currentDate': {"updated" :True},
                                "$set": {'status': 'COMPLETE'}})

    now = datetime.now()
    print ("Complete: " + str(now))

if __name__ == "__main__":
    main()
