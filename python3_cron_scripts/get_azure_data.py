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
This script parses an Azure IP list such as the XML File that can be found at:
https://www.microsoft.com/en-us/download/details.aspx?id=41653

Unfortunately, Microsoft doesn't provide an API to retrieve the list.
Therefore, this script parses the web page looking for the link.
This technique is bound to break over time.
However, it is what is possible until a better solution is provided.

The XML etree module in Python 3.x is vulnerable to DoS attacks.
It was preferable over the alternatives which were vulnerable to XXE attacks.
https://docs.python.org/3/library/xml.html#xml-vulnerabilities
"""

import xml.etree.ElementTree as ET
from datetime import datetime
from html.parser import HTMLParser
import requests
from libs3 import MongoConnector

mongo_connector = MongoConnector.MongoConnector()

XML_LOCATION = "https://www.microsoft.com/en-us/download/confirmation.aspx?id=41653"


class MyHTMLParser(HTMLParser):
    """
    Create a subclass and override the handler methods.
    """
    URL = ""

    def handle_starttag(self, tag, attrs):
        found = False
        if tag == "a":
            for attr in attrs:
                if attr[0] == "class" and attr[1] == "mscom-link failoverLink":
                    found = True

            if found:
                for attr in attrs:
                    if attr[0] == "href":
                        print(attr[1])
                        self.URL = attr[1]


def main():
    """
    Begin main...
    """
    now = datetime.now()
    print ("Starting: " + str(now))

    jobs_collection = mongo_connector.get_jobs_connection()

    # Download the XML file
    req = requests.get(XML_LOCATION)

    if req.status_code != 200:
        print("Bad Request")
        jobs_collection.update_one({'job_name': 'get_azure_data'},
                                   {'$currentDate': {"updated" :True},
                                    "$set": {'status': 'ERROR'}})
        exit(0)

    parser = MyHTMLParser()
    parser.feed(req.text)

    if parser.URL == "":
        print("Unable to identify URL in Microsoft HTML")
        jobs_collection.update_one({'job_name': 'get_azure_data'},
                                   {'$currentDate': {"updated": True},
                                    "$set": {'status': 'ERROR'}})
        exit(0)

    req = requests.get(parser.URL)

    if req.status_code != 200:
        print("Bad Request")
        jobs_collection.update_one({'job_name': 'get_azure_data'},
                                   {'$currentDate': {"updated": True},
                                    "$set": {'status': 'ERROR'}})
        exit(0)

    root = ET.fromstring(req.text)

    insert_json = {}
    insert_json['created'] = datetime.now()
    insert_json['prefixes'] = []

    for region in root.findall('Region'):
        region_name = region.get("Name")
        for iprange in region.findall('IpRange'):
            cidr = iprange.get("Subnet")
            insert_json['prefixes'].append({'region': region_name, 'ip_prefix': cidr})

    azure_ips = mongo_connector.get_azure_ips_connection()
    azure_ips.remove({})
    azure_ips.insert(insert_json)

    # Record status
    jobs_collection.update_one({'job_name': 'get_azure_data'},
                               {'$currentDate': {"updated": True},
                                "$set": {'status': 'COMPLETE'}})

    now = datetime.now()
    print("Complete: " + str(now))


if __name__ == "__main__":
    main()
