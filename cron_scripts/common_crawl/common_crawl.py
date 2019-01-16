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
This script will download the original Common Crawl warc files and
insert them into a table in the remote database. The URL is currently
hard coded to a specific month. To complete this project, the script
would need to be able to walk all the monthly entries.

The number of results this produced was limited so further development
is currently stalled. Instead, the Common Crawl graph became a focus.
This uploaded file is currently saved for historical purposes in case
this approach is revisited.

The WARC files are large so this processing was done in a remote
environment.
"""

import glob
import json
import os
import subprocess
import time
from datetime import datetime
from httplib import HTTPResponse
from StringIO import StringIO
from urlparse import urlparse

import requests

import warc
from libs2 import RemoteMongoConnector

OUT_DIR = "./output_dir/"

class FakeSocket(object):
    """
    A fake socket is necessary for getting HTTP lib to read data
    """
    def __init__(self, response_str):
        self._file = StringIO(response_str)

    def makefile(self, *args, **kwargs):
        """
        Return the StringIO object
        """
        return self._file

def download_file(url_path):
    """
    Download the file from the provided URL.
    Use the filename in the URL as the name of the outputed file.
    """
    local_filename = url_path.split('/')[-3] + "-" + url_path.split('/')[-1]
    local_filename = OUT_DIR + local_filename
    print local_filename
    url = "https://commoncrawl.s3.amazonaws.com/" + url_path
    # NOTE the stream=True parameter
    req = requests.get(url, stream=True)
    with open(local_filename, 'wb') as write_f:
        for chunk in req.iter_content(chunk_size=1024):
            if chunk: # filter out keep-alive new chunks
                write_f.write(chunk)
    write_f.close()
    return local_filename


def get_cc_files(zone):
    """
    Get files from Common Crawl site by searching for zone
    """
    downloaded_files = []
    details_url = "http://index.commoncrawl.org/CC-MAIN-2017-17-index?output=json&url=" + zone
    req = requests.get(details_url)

    if req.status_code != 200:
        print "Error " + str(req.status_code) + ": Error from Common Crawl API\n"
        print req.text

        if req.status_code != 404:
            time.sleep(60)
            req = requests.get(details_url)
            if req.status_code != 200:
                print "Error on retry. Giving up..."
                exit(0)
        else:
            time.sleep(30)
            return None

    response = "[" + req.text.replace("\n", ",")[:-1] + "]"
    json_data = json.loads(response)

    for entry in json_data:
        compressed_path = entry['filename']
        if compressed_path not in downloaded_files:
            downloaded_files.append(compressed_path)
            _ = download_file(compressed_path)
            # Warc library now handles gzip: subprocess.check_call(["gunzip", filename])

    return json_data


def main():
    """
    Begin Main....
    """

    now = datetime.now()
    print "Starting: " + str(now)

    RMC = RemoteMongoConnector.RemoteMongoConnector()

    zones_collection = RMC.get_zone_connection()
    cc_collection = RMC.get_common_crawl_connection()

    zone_results = zones_collection.find({'status': {"$nin": ["false_positive", "expired"]}})

    zones = []
    for rec in zone_results:
        if rec['zone'].find("."):
            zones.append(rec['zone'].encode('UTF-8'))


    for zone in zones:
        print "Zone: " + zone
        result = get_cc_files(zone)

        if result != None:
            for file in os.listdir(OUT_DIR):
                if file.endswith(".gz"):
                    print os.path.join(OUT_DIR, file)
                    warc_f = warc.open(OUT_DIR + file)
                    fsize = os.path.getsize(OUT_DIR + file)

                    while fsize > warc_f.tell():
                        for _, record in enumerate(warc_f):
                            if ('warc-target-uri' in record.header
                                    and record.header['warc-target-uri'].find(zone) > 0):
                                print record.url
                                if record.type == "response":
                                    print record.url
                                    insert_json = {}
                                    insert_json['zone'] = zone
                                    insert_json['url'] = record.url
                                    obj = urlparse(record.url)
                                    insert_json['domain'] = obj.netloc
                                    source = FakeSocket(record.payload.read())
                                    response = HTTPResponse(source)
                                    response.begin()
                                    insert_json['headers'] = response.getheaders()
                                    insert_json['status'] = response.status
                                    insert_json['version'] = response.version
                                    insert_json['reason'] = response.reason
                                    insert_json['created'] = datetime.now()
                                    cc_collection.insert(insert_json)



    files = glob.glob(OUT_DIR + "*")
    for file in files:
        os.remove(file)

    now = datetime.now()
    print "Ending: " + str(now)

if __name__ == "__main__":
    main()
