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
This script queries the VirusTotal domain reports for any reports that match a tracked domain.
This script uses the free API because the results are the same as the paid API.
We are also allowed more queries per day on the free API than the paid API.
Therefore, we use the free API in order to save the paid API credits for more critical work.
"""

import time
from datetime import datetime

from libs3 import MongoConnector, VirusTotal, JobsManager
from libs3.ZoneManager import ZoneManager


def main():
    """
    Begin Main...
    """
    now = datetime.now()
    print("Starting: " + str(now))

    # Create an instance of the VirusTotal class
    vt_instance = VirusTotal.VirusTotal()

    # Get collections for the queries
    mongo_connector = MongoConnector.MongoConnector()
    vt_collection = mongo_connector.get_virustotal_connection()

    jobs_manager = JobsManager.JobsManager(mongo_connector, 'get_virustotal_data')
    jobs_manager.record_job_start()

    # Collect the list of tracked TLDs
    zones = ZoneManager.get_distinct_zones(mongo_connector)

    # For each tracked TLD
    for zone in zones:
        print("Checking " + zone)
        results = vt_instance.get_domain_report(zone)

        if results is None:
            print("Error querying zone " + zone)
        elif results['response_code'] == -1:
            print("VT unhappy with " + zone)
        elif results['response_code'] == 0:
            print("VT doesn't have " + zone)
        else:
            print("Matched " + zone)

            results['zone'] = zone
            results['created'] = datetime.now()

            # Mongo doesn't allow key names with periods in them
            # Re-assign to an undotted key name
            if "Dr.Web category" in results:
                results['Dr Web category'] = results.pop("Dr.Web category")

            vt_collection.delete_one({"zone": zone})
            vt_collection.insert(results)

        # This sleep command is so that we don't exceed the daily limit on the free API
        # This setting results in this script taking several days to complete
        time.sleep(25)


    # Record status
    jobs_manager.record_job_complete()

    now = datetime.now()
    print("Complete: " + str(now))

if __name__ == "__main__":
    main()

exit(0)
