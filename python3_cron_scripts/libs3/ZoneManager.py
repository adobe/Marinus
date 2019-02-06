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
This class mostly exists because almost every script needs to do a get_distinct_zones
Having it centralized, means that the included and excluded status' can be managed in one place.
"""

from pymongo import MongoClient
from datetime import datetime


class ZoneManager(object):

    # A status of confirmed typically means it was entered by a human
    CONFIRMED = "confirmed"

    # A status of unconfirmed means that it was added via automation
    # It has not been revied by a human
    UNCONFIRMED = "unconfirmed"

    # A status of false positive means that a human identified that automation made a mistake
    FALSE_POSITIVE = "false_positive"

    # A status of expired means that the automation believes that the domain is no longer registered
    EXPIRED = "expired"

    # The MongoConnector
    mongo_connector = None

    # The zone collection
    zone_collection = None


    def __init__(self, mongo_connector):
        """
        Initialize the MongoDB Connector
        """
        self.mongo_connector = mongo_connector
        self.zone_collection = mongo_connector.get_zone_connection()


    def _check_valid_status(self, status):
        if status != ZoneManager.EXPIRED and status != ZoneManager.FALSE_POSITIVE and \
           status != ZoneManager.CONFIRMED and status!= ZoneManager.UNCONFIRMED:
           print("ERROR: Bad status value")
           return False

        return True


    @staticmethod
    def get_distinct_zones(mongo_connector, includeAll = False):
        """
        This is the most common usage of get zones where the caller wants just the list of
        active zones.

        This returns the list of zones as an array of strings rather than the complete JSON objects
        """
        zones_collection = mongo_connector.get_zone_connection()

        if includeAll:
            zone_results = mongo_connector.perform_distinct(zones_collection, 'zone')
        else:
            zone_results = mongo_connector.perform_distinct(zones_collection, 'zone', {'status': {"$nin": [ZoneManager.FALSE_POSITIVE, ZoneManager.EXPIRED]}})

        zones = []
        for zone in zone_results:
            if zone.find(".") >= 0:
                zones.append(zone)

        return zones


    @staticmethod
    def get_reversed_zones(mongo_connector):
        """
        Retrieve the list of active zones and then reverse them to match the Common Crawl format
        """
        zones_collection = mongo_connector.get_zone_connection()
        zone_results = mongo_connector.perform_distinct(zones_collection, 'zone', {'status': {"$nin": [ZoneManager.FALSE_POSITIVE, ZoneManager.EXPIRED]}})

        zones = []
        for zone in zone_results:
            if zone.find("."):
                zone_parts = zone.split(".")

                # The vertices.txt entries from common_crawl are in reverse order (e.g. org.example.www)
                # To string match faster, the zones are stored in a reverse format prior to matching.
                # This avoids having to reverse each entry in the file which is less efficient.
                rev_zone = ""
                for part in zone_parts:
                    rev_zone = part + "." + rev_zone
                rev_zone = rev_zone[:-1]
                zones.append(rev_zone)

        return zones


    @staticmethod
    def get_zones_by_source(mongo_connector, source, includeAll=False):
        """
        Returns a list of zones based on the provided reporting source
        """
        zone_collection = mongo_connector.get_zone_connection()

        if includeAll:
            zones = mongo_connector.perform_distinct(zone_collection, 'zone', {
                'reporting_sources.source': source})
        else:
            zones = mongo_connector.perform_distinct(zone_collection, 'zone', {
                'reporting_sources.source': source,
                'status': {'$nin': [ZoneManager.FALSE_POSITIVE, ZoneManager.EXPIRED]}})

        return zones


    @staticmethod
    def get_zones(mongo_connector, includeAll=False):
        """
        This is will return the full zones object for all active zones.

        This returns the complete json objects for the matching descriptions
        """
        zones_collection = mongo_connector.get_zone_connection()

        if includeAll:
            zone_results = mongo_connector.perform_find(zones_collection, {})
        else:
            zone_results = mongo_connector.perform_find(zones_collection, {'status': {"$nin": [ZoneManager.FALSE_POSITIVE, ZoneManager.EXPIRED]}})

        zones = []
        for zone in zone_results:
            if zone['zone'].find(".") >= 0:
                zones.append(zone)

        return zones


    def get_zone(self, zone):
        """
        Fetch the full individual zone record.
        This is not a staticmethod since it would probably be called repeatedly.
        """

        return self.mongo_connector.perform_find(self.zone_collection, {'zone': zone})


    def get_zones_by_status(self, status):
        """
        This returns the list of zones associated with the provided status.

        This returns the list of zones as an array of strings rather than the complete JSON objects
        """

        if not self._check_valid_status(status):
            return

        zone_results = self.mongo_connector.perform_distinct(self.zone_collection, 'zone', {'status': status})

        zones = []
        for zone in zone_results:
            if zone.find(".") >= 0:
                zones.append(zone)

        return zones


    def set_status(self, zone, status, caller):
        """
        Set a zone to expired.
        """
        if self.zone_collection.find({'zone': zone}).count() == 0:
            print("ERROR: Invalid zone!")
            return

        if status != ZoneManager.EXPIRED and status != ZoneManager.FALSE_POSITIVE and \
           status != ZoneManager.CONFIRMED and status!= ZoneManager.UNCONFIRMED:
           print("ERROR: Bad status value!")
           return

        if caller is None or caller == "":
            print("ERROR: Please provide a caller value!")
            return

        now = datetime.now()
        note = caller + " set to " + status + " on " + str(now)
        self.zone_collection.update({"zone": zone}, {"$set": {"status": status, "updated": now}, "$addToSet": {"notes": note}})


    def add_note(self, zone, note):
        """
        In the future, there should probably be restrictions on note length.
        For now, it is not set until more information on usage is available.
        """

        self.zone_collection.update({"zone": zone}, {"$addToSet": {"notes": note}})

