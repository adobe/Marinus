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
This script is not designed to run weekly.
It is being checked in as a record of the Akamai IP ranges that were known at the time of set up.
If the table ever gets deleted accidently, this script can be re-run to populate the data again.
At that time, it would be good to confirm that the Akamai IP ranges have not changed.
"""

from datetime import datetime
from libs3 import MongoConnector, JobsManager

mongo_connector = MongoConnector.MongoConnector()
AKAMAI_COLLECTION = mongo_connector.get_akamai_ips_connection()
jobs_manager = JobsManager.JobsManager(mongo_connector, "upload_akamai_data")
jobs_manager.record_job_start()

# Clear previous data
AKAMAI_COLLECTION.remove({})

AKAMAI_DATA = {}

# Record the date that the data was updated.
AKAMAI_DATA['created'] = datetime.now()

# Leave a note for those who query the database directly.
AKAMAI_DATA['note'] = ("This does not cover all Akamai ranges. " +
                       "It just covers the ones that the tracked organization appears to use as of the created date.")

# Create the list of known ranges.
AKAMAI_DATA['ranges'] = []
AKAMAI_DATA['ranges'].append({'cidr': '2.23.144.0/20',
                              'ip_range': '2.23.144.0 - 2.23.159.255'})
AKAMAI_DATA['ranges'].append({'cidr': '104.64.0.0/10',
                              'ip_range': '104.64.0.0 - 104.127.255.255'})
AKAMAI_DATA['ranges'].append({'cidr': '172.224.0.0/12',
                              'ip_range': '172.224.0.0 - 172.239.255.255'})
AKAMAI_DATA['ranges'].append({'cidr': '173.222.0.0/15',
                              'ip_range': '173.222.0.0 - 173.223.255.255'})
AKAMAI_DATA['ranges'].append({'cidr': '184.24.0.0/13',
                              'ip_range': '184.24.0.0 - 184.31.255.255'})
AKAMAI_DATA['ranges'].append({'cidr': '184.50.0.0/15',
                              'ip_range': '184.50.0.0 - 184.51.255.255'})
AKAMAI_DATA['ranges'].append({'cidr': '184.84.0.0/14',
                              'ip_range': '184.84.0.0 - 184.87.255.255'})
AKAMAI_DATA['ranges'].append({'cidr': '23.0.0.0/12',
                              'ip_range': '23.0.0.0 - 23.15.255.255'})
AKAMAI_DATA['ranges'].append({'cidr': '23.32.0.0/11',
                              'ip_range': '23.32.0.0 - 23.63.255.255'})
AKAMAI_DATA['ranges'].append({'cidr': '23.64.0.0/14',
                              'ip_range': '23.64.0.0 - 23.67.255.255'})
AKAMAI_DATA['ranges'].append({'cidr': '23.72.0.0/13',
                              'ip_range': '23.72.0.0 - 23.79.255.255'})
AKAMAI_DATA['ranges'].append({'cidr': '23.192.0.0/11',
                              'ip_range': '23.192.0.0 - 23.223.255.255'})

AKAMAI_DATA['ipv6_ranges'] = []
AKAMAI_DATA['ipv6_ranges'].append({'cidr': '2600:1400::/24',
                                   'ipv6_range': '2600:1400:: - 2600:14FF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF'})

# Insert the data
AKAMAI_COLLECTION.insert(AKAMAI_DATA)

jobs_manager.record_job_complete()

exit(0)
