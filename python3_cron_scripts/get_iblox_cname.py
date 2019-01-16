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
This script queries Infoblox for the 'cname' information of the zones in the zone collection.

This script is only useful to Infoblox customers.
"""

from datetime import datetime

from libs3 import InfobloxDNSManager, MongoConnector


def main():
    """
    Begin Main...
    """

    print("Starting: " + str(datetime.now()))

    # Make database connections
    mc = MongoConnector.MongoConnector()
    jobs_collection = mc.get_jobs_connection()

    idm = InfobloxDNSManager.InfobloxDNSManager('cname')
    idm.get_infoblox_dns()

    # Record status
    jobs_collection.update_one({'job_name': 'get_iblox_cname'},
                               {'$currentDate': {"updated": True},
                                "$set": {'status': 'COMPLETE'}})

    print("Ending: " + str(datetime.now()))


if __name__ == "__main__":
    main()
