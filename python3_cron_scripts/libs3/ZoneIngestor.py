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
This script inserts zone into 'zones' collection.
It expects 3 inputs:
-- zone: Required value.
-- source: Default value set to 'Manual'
-- parent: Default value set to None
-- custom_fields: Default value set None. This a Python dictionary of additional fields to add to the source record.
"""

import logging
from datetime import datetime

from bson.objectid import ObjectId

from libs3 import MongoConnector, ZoneManager


class ZoneIngestor(object):
    # Connect to the database
    MC = MongoConnector.MongoConnector()
    zone_collection = MC.get_zone_connection()
    zone_manager = ZoneManager.ZoneManager(MC)

    _logger = logging.getLogger(__name__)

    def __check_parent_zone(self, zone):
        """
        For the provided zone, find the existing parent zone record.
        :param zone: Zone for which parent record needs to be found.
        :return: Parent zone record found or None
        """
        zones_present = list(self.zone_collection.find({}, {"zone": 1}))
        zone_segments = zone.split(".")
        segment_length = len(zone_segments)
        parent_zone = zone_segments[segment_length - 1]

        for segment in zone_segments[segment_length - 2 : 0 : -1]:
            parent_zone = segment + "." + parent_zone
            for zone_present in zones_present:
                if zone_present["zone"] == parent_zone:
                    return zone_present
        return None

    def __check_sub_zone(self, zone):
        """
        Return sub-zones as a list of the zone provided
        :param zone: Zone for which sub-zones need to be found.
        :return: List of the sub-zones found.
        """
        zones_present = list(self.zone_collection.find({}, {"_id": 0}))
        zone = "." + zone
        sub_zones_matched = []
        for zone_present in zones_present:
            if zone_present["zone"].rfind(zone) > 0:
                sub_zones_matched.append(zone_present)
        return sub_zones_matched

    @staticmethod
    def __create_sub_zone_entries(sub_zone):
        """
        Iterate recursively through the sub_zone list to create the sub-zones list.
        :param sub_zone: Sub-zone record to be iterated to create the sub-zone list
        :return: List of sub-zones prepared.
        """
        temp_sub_zone_list = []
        temp_sub_zone = dict()
        temp_sub_zone["sub_zone"] = sub_zone["zone"]
        temp_sub_zone["source"] = sub_zone["reporting_sources"][0]["source"]
        temp_sub_zone["created"] = sub_zone["created"]
        temp_sub_zone["updated"] = datetime.now()
        temp_sub_zone["status"] = sub_zone["reporting_sources"][0]["status"]
        temp_sub_zone_list.append(temp_sub_zone)
        for sz in sub_zone["sub_zones"]:
            temp_sub_zone = dict()
            temp_sub_zone["sub_zone"] = sz["sub_zone"]
            temp_sub_zone["source"] = sz["source"]
            temp_sub_zone["created"] = sz["created"]
            temp_sub_zone["updated"] = datetime.now()
            temp_sub_zone["status"] = sz["status"]
            temp_sub_zone_list.append(temp_sub_zone)
        return temp_sub_zone_list

    def __update_parent_sub_zones(self, sub_zone_records, source, parent):
        """
        Add a new document for the parent record with the source provided. Add the
        sub_zone_records found as sub_zones to the parent zone.
        :param sub_zone_records: Sub-zone records found.
        :param source: Source of the parent
        :param parent: Parent value to be added
        """
        sub_zones = []
        for sub_zone in sub_zone_records:
            sub_zones.extend(self.__create_sub_zone_entries(sub_zone))

        insert_zone = dict()
        insert_zone["zone"] = parent.lower()
        insert_zone["reporting_sources"] = list()
        insert_zone["reporting_sources"].append(
            {
                "created": datetime.now(),
                "updated": datetime.now(),
                "status": "unconfirmed",
                "source": source,
            }
        )
        insert_zone["created"] = datetime.now()
        insert_zone["updated"] = datetime.now()
        insert_zone["status"] = "unconfirmed"
        insert_zone["sub_zones"] = sub_zones
        self.zone_collection.insert_one(insert_zone)

    def __add_sub_zone(self, zone, source, parent_record):
        """
        Add the zone as sub-zone for the parent_record provided with the provided source.
        The updated time of the parent_record will be updated also.

        :param zone: Sub-zone value to be added.
        :param source: Source value of the sub-zone.
        :param parent_record: Parent document to which the sub-zone needs to be added.
        """
        sub_zone = dict()
        sub_zone["sub_zone"] = zone
        sub_zone["source"] = source
        sub_zone["created"] = datetime.now()
        sub_zone["updated"] = datetime.now()
        sub_zone["status"] = "unconfirmed"

        self.zone_collection.update_one(
            {"_id": ObjectId(parent_record["_id"])},
            {"$push": {"sub_zones": sub_zone}, "$set": {"updated": datetime.now()}},
        )

    def __add_new_zone(self, zone, source, parent, custom_fields):
        """
        Add a new record with the parent zone and the sub-zone.
        The source value is as provided in the initial function call.
        The zone value can be None indicating we are adding only TLD.
        :param zone: Sub-zone value to be added.
        :param source: Source of the parent and the zone.
        :param parent: Parent zone value to be added.
        """
        sub_zones = list()
        # zone value can be None
        if zone:
            sub_zones.append({})
            sub_zones[0]["sub_zone"] = zone
            sub_zones[0]["source"] = source
            sub_zones[0]["created"] = datetime.now()
            sub_zones[0]["updated"] = datetime.now()
            sub_zones[0]["status"] = "unconfirmed"

        insert_zone = dict()
        insert_zone["zone"] = parent
        insert_zone["reporting_sources"] = list()
        sources_data = {
            "created": datetime.now(),
            "updated": datetime.now(),
            "status": "unconfirmed",
            "source": source,
        }

        if custom_fields is not None:
            for key_value in custom_fields.keys():
                sources_data[key_value] = custom_fields[key_value]

        insert_zone["reporting_sources"].append(sources_data)
        insert_zone["created"] = datetime.now()
        insert_zone["updated"] = datetime.now()
        insert_zone["status"] = "unconfirmed"
        insert_zone["sub_zones"] = sub_zones
        self.zone_collection.insert_one(insert_zone)

    def __update_source_time(self, record, source, custom_fields):
        """
        Append the source to the list of sources of parent zone if not previously present.
        Update the updated time of the parent zone entry.
        :param record: Document which needs to be updated.
        :param source: Source value which needs to be added.
        """
        source_contained = False
        for reporting_source in record["reporting_sources"]:
            if reporting_source["source"] == source:
                source_contained = True

        if not source_contained:
            # the source does not exist in the zone so push one.
            source_data = dict()
            source_data["created"] = datetime.now()
            source_data["updated"] = datetime.now()
            source_data["status"] = "unconfirmed"
            source_data["source"] = source

            if custom_fields is not None:
                for key_value in custom_fields.keys():
                    source_data[key_value] = custom_fields[key_value]

            self.zone_collection.update_one(
                {"_id": ObjectId(record["_id"])},
                {
                    "$push": {"reporting_sources": source_data},
                    "$set": {"updated": datetime.now()},
                },
            )

        else:
            self.zone_collection.update_one(
                {"_id": ObjectId(record["_id"]), "reporting_sources.source": source},
                {
                    "$set": {
                        "reporting_sources.$.updated": datetime.now(),
                        "updated": datetime.now(),
                    }
                },
            )
            if custom_fields is not None:
                for key_value in custom_fields.keys():
                    self.zone_collection.update_one(
                        {
                            "_id": ObjectId(record["_id"]),
                            "reporting_sources.source": source,
                        },
                        {
                            "$set": {
                                "reporting_sources.$."
                                + key_value: custom_fields[key_value],
                                "updated": datetime.now(),
                            }
                        },
                    )

    def __update_time(self, record, zone, custom_fields=None):
        """
        Update the time of the zone record and that of the sub-zone.

        :param record: Document which needs to be updated.
        :param zone: Sub-zone value of document whose time needs to be updated.
        """
        self.zone_collection.update_one(
            {"_id": ObjectId(record["_id"]), "sub_zones.sub_zone": zone},
            {
                "$set": {
                    "sub_zones.$.updated": datetime.now(),
                    "updated": datetime.now(),
                }
            },
        )

        if custom_fields is not None:
            for key_value in custom_fields.keys():
                self.zone_collection.update_one(
                    {"_id": ObjectId(record["_id"]), "sub_zones.sub_zone": zone},
                    {
                        "$set": {
                            "sub_zones.$." + key_value: custom_fields[key_value],
                            "updated": datetime.now(),
                        }
                    },
                )

    def __delete_zone(self, zone):
        """
        Delete the zone record.
        :param zone: Zone value to be deleted.
        """
        self.zone_collection.delete_many({"zone": zone})

    def __zone_previously_not_present(self, zone, source, parent, custom_fields):
        """
        Handling of the zone while it does not already exists.
        1. Check if the parent value has been provided in the parameters.
        2. If yes:
                    -- if parent is present as a zone: Return if more than one document is found.
                                                       Else add zone to the parent document as a sub-zone with the
                                                       source value provided.
                    -- if parent is not present as a zone: create a new zone and parent entry with source.
        3. If no:
                    -- if any parent zone is already present: Add the zone as sub-zone of parent zone record.
                    -- if no parent zone is already present: Add zone as parent zone with any existing sub-zones added
                                                             as sub-zones. Delete existing sub-zones.
                                                             Else add zone as parent zone with no sub-zones.
        :param zone: Zone to be added which is not previously present.
        :param source: Source of the zone provided.
        :param parent: Parent value of the zone.
        """
        if parent:
            # check if the parent is present as zone.
            # If yes, add zone as sub-zone
            # If no, add zone and parent as new entry.
            parent_record = self.MC.perform_find(self.zone_collection, {"zone": parent})
            if parent_record:
                count = self.MC.perform_count(self.zone_collection, {"zone": parent})
                if count > 1:
                    self._logger.error(
                        "Error: Too many records for the parent zone:{parent}.".format(
                            parent=parent
                        )
                    )
                    return False
                self.__add_sub_zone(zone, source, parent_record[0])
            else:
                self.__add_new_zone(zone, source, parent, custom_fields)

        else:
            # check for a previously present parent.
            # If yes, add zone as sub-zone
            # If no, add zone as new entry.
            parent_zone_record = self.__check_parent_zone(zone)

            if parent_zone_record:
                self.__add_sub_zone(zone, source, parent_zone_record)
            else:
                # check for sub-zone existing for this zone.
                # This could be the case when the sub-zone was ingested before parent zone
                sub_zone_records = self.__check_sub_zone(zone)
                if sub_zone_records:
                    # zone as parent zone and source provided. Previous sub_zone record to be taken.
                    # call delete sub-zone also.
                    self.__update_parent_sub_zones(sub_zone_records, source, zone)
                    for sub_zone in sub_zone_records:
                        self.__delete_zone(sub_zone["zone"])
                else:
                    self.__add_new_zone(None, source, zone, custom_fields)

    def __zone_previously_present(self, zone, source, parent, query, custom_fields):
        """
        Handling of the zone while it already exists in the collection as zone/sub-zone. The function returns
        in case multiple documents of the zone are discovered.
        1. Return if more than one existing record of zone is discovered.
        2. Check if zone exists as parent zone.
        3. If yes:
                    -- if parent value is not provided: update date and source of the zone
                    -- if parent is provided: Return if current zone entry has more than 1 reporting sources or current
                                              source is not equal to provided source since one sub-zone can have only
                                              one source.
                                              Else create a new zone and parent entry with source and delete older entry
        4. If no (i.e zone exists as sub-zone):
                    -- Return if the parent provided is not the same as the parent zone value.
                    -- Return if the source provided is not the same as the source of the sub-zone
                    -- Else update date and time of sub-zone and zone.
        :param zone: Zone value to be added
        :param source: Source value of the zone
        :param parent: Parent of the zone to be added
        :param cursor: Existing record of zone provided.
        """

        count = self.MC.perform_count(self.zone_collection, query)

        if count > 1:
            self._logger.error(
                "Error: The zone:{zone} is present in multiple records. Rectify.".format(
                    zone=zone
                )
            )
            return

        cursor = self.MC.perform_find(self.zone_collection, query)

        record = cursor[0]
        # if record['status'] == 'false_positive':
        #     self._logger.error('False positive encountered in collection for zone:{zone}. No action required.'.format(zone=zone))
        #     return

        if record["zone"] == zone:
            if not parent:
                self.__update_source_time(record, source, custom_fields)

                if record["status"] == self.zone_manager.EXPIRED:
                    self.zone_manager.set_status(
                        zone, self.zone_manager.UNCONFIRMED, source
                    )
            else:
                # Return in case the zone is present with another source since sub-zones cannot have two sources.
                if len(record["reporting_sources"]) > 1 or not (
                    record["reporting_sources"][0]["source"] == source
                ):
                    self._logger.error(
                        "Error: The zone:{zone} has multiple sources".format(zone=zone)
                    )
                    return

                self.__add_new_zone(zone, source, parent, custom_fields)
                self.__delete_zone(zone)
        else:
            record_zone = None
            for sub_zone in record["sub_zones"]:
                if sub_zone["sub_zone"] == zone:
                    record_zone = sub_zone
            # if record_zone['status'] == 'false_positive':
            #     self._logger.error('False positive encountered in collection for zone:{zone}. No action required.'.format(zone=zone))
            #     return
            if parent and (not record["zone"] == parent):
                self._logger.error(
                    "Error: The zone:{zone} pre-exists as a sub-zone of another parent zone apart from parent:{parent}.".format(
                        zone=zone, parent=parent
                    )
                )
                return
            if not record_zone["source"] == source:
                self._logger.error(
                    "Error: The zone:{zone} pre-exists as a sub-zone from another source:{source}.".format(
                        zone=zone, source=source
                    )
                )
                return

            self.__update_time(record, zone, custom_fields)

            if record["status"] == self.zone_manager.EXPIRED:
                self.zone_manager.set_status(
                    zone, self.zone_manager.UNCONFIRMED, source
                )

    def add_zone(self, zone, source="Manual", parent=None, custom_fields=None):
        """
        Publicly exposed function responsible to ingest the zone into zone collection
        :param zone: Zone value.
        :param source: Source of the zone being ingested. Default value is Manual.
        :param parent: Parent zone of the zone being ingested if any. Default value is None
        :param custom_fields: An optional dictionary of custom fields to add to the source record.
        """
        if not zone:
            self._logger.error("Error: Provide zone value.")
            return

        # Reject any zone which does not contain a TLD.
        if "." not in zone:
            self._logger.error("Error: Invalid zone entry : " + zone)
            return

        query = {"$or": [{"sub_zones.sub_zone": zone}, {"zone": zone}]}

        count = self.MC.perform_count(self.zone_collection, query)

        if count == 0:
            self.__zone_previously_not_present(zone, source, parent, custom_fields)
        else:
            self.__zone_previously_present(zone, source, parent, query, custom_fields)
