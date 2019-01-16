#!/usr/bin/env python

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
Based on:
https://github.com/google/certificate-transparency/blob/master/python/ct/client/tools/simple_scan.py

Ths script scans the Google Pilot database for certificates related to Marinus SSL_Orgs.
SSL_Orgs is used instead of zones because of the number of comparisons that need to be done.
That said, if there is a particular zone of interest, then you can change the value of the
primary_domain variable in the __main__ function.

The Google Pilot database is one of the oldest and it is quite a large log to scan. Therefore,
this script will likley take the longest to run.

Data is written to: /mnt/workspace/ct_pilot/

The certificate transparency github project must be installed in /mnt/workspace/certificate-transparency/
The certificate transparency project is located at: https://github.com/google/certificate-transparency/
"""

import os
import re
import sys
import gflags
import subprocess

from datetime import datetime
from libs2 import MongoConnector

sys.path.append("/mnt/workspace/certificate-transparency/python")
from ct.client import scanner

FLAGS = gflags.FLAGS

gflags.DEFINE_integer("multi", 4, "Number of cert parsing processes to use in "
                      "addition to the main process and the network process.")
gflags.DEFINE_string("output", "/mnt/workspace/ct_pilot/",
                     "Output directory to write certificates to.")

global primary_domain
global ssl_orgs


def is_running(process):
    """
    Is the provided process name is currently running?
    """
    proc_list = subprocess.Popen(["pgrep", "-f", process], stdout=subprocess.PIPE)
    for proc in proc_list.stdout:
        if proc.rstrip() != str(os.getpid()) and proc.rstrip() != str(os.getppid()):
            return True
    return False


def match(certificate, entry_type, extra_data, certificate_index):
    """
    Try to match the provided certificate with the embedded criteria.
    This needs to be thread safe.
    """
    try:
        # Fill this in with your match criteria, e.g.
        #
        # return "google" in certificate.subject_name().lower()
        #
        # NB: for precertificates, issuer matching may not work as expected
        # when the precertificate has been issued by the special-purpose
        # precertificate signing certificate.

        cns = certificate.subject_common_names()
        dns = certificate.subject_dns_names()
        names = cns + dns

        for org in ssl_orgs:
            if org.lower() in certificate.print_subject_name().lower():
                return ("cert_%d.der" % certificate_index, certificate.to_der())

        # It is likely that most certificates will be caught by the org match.
        # However, if there is a particular FLD that you want to monitor, this can
        # catch certificates issued to other orgs for the FLD.
        if primary_domain != "":
            for name in names:
                if str(name).endswith(primary_domain):
                    return ("cert_%d.der" % certificate_index, certificate.to_der())

    except:
        return None

    return None


def write_matched_certificate(matcher_output):
    """
    Callback for writing the matched certificate to a file
    """
    output_file, der_data = matcher_output
    with open(os.path.join(FLAGS.output, output_file), "wb") as out_f:
        out_f.write(der_data)


def run():
    """
    Kick off the multi-threaded certificate search
    """
    if not FLAGS.output:
        raise Exception("Certificates output directory must be specified.")

    res = scanner.scan_log(
        match, "https://ct.googleapis.com/pilot", FLAGS.multi,
        write_matched_certificate)
    print "Scanned %d, %d matched and %d failed strict or partial parsing" % (
        res.total, res.matches, res.errors)


if __name__ == "__main__":
    now = datetime.now()
    print "Starting: " + str(now)

    if is_running(os.path.basename(__file__)):
        print "Already running..."
        exit(0)

    mongo_connector = MongoConnector.MongoConnector()
    config_collection = mongo_connector.get_config_connection()
    ssl_m_results = config_collection.find({},{"SSL_Orgs": 1})
    ssl_orgs = []
    for result in ssl_m_results:
        for ssl_org in result['SSL_Orgs']:
            ssl_orgs.append(ssl_org)

    # Change this value in order to search for a specific zone
    primary_domain = ""

    del config_collection
    del mongo_connector

    sys.argv = FLAGS(sys.argv)
    run()

    now = datetime.now()
    print "Complete: " + str(now)
