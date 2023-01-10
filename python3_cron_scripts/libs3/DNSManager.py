#!/usr/bin/python3

# Copyright 2022 Adobe. All rights reserved.
# This file is licensed to you under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License. You may obtain a copy
# of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR REPRESENTATIONS
# OF ANY KIND, either express or implied. See the License for the specific language
# governing permissions and limitations under the License.

"""
This module manages consolidating DNS records from various sources.
"""

import logging
from datetime import datetime

from bson.objectid import ObjectId
from libs3 import IPManager


class DNSManager(object):
    """
    Marinus collects DNS information from multiple sources.
    In the original version of Marinus, there was a separate table for each source.
    Maintaining separate tables makes it difficult to search.
    Therefore, the tables have been merged into "all_dns".
    This class acts as the interface for translating a DNS record into the all_dns format.
    When submitting a DNS record, a "source" must be provided.
    The approved sources are "virustotal", "common_crawl", "sonar_dns", and "ssl".
    These will eventually be saved as constants.
    """

    all_dns_collection = None
    mongo_connector = None
    _logger = None

    def _log(self):
        """
        Get the log
        """
        return logging.getLogger(__name__)

    def __init__(self, mongo_connector, alternative_collection=None):
        """
        Initialize the object with the necessary database configurations
        """
        self._logger = self._log()
        self.mongo_connector = mongo_connector
        if alternative_collection is not None:
            try:
                self.all_dns_collection = getattr(
                    mongo_connector, alternative_collection
                )()
            except:
                self._logger.error(
                    "FATAL: Could not fetch dynamic collection in DNS Manager"
                )
                exit(1)
        else:
            self.all_dns_collection = mongo_connector.get_all_dns_connection()

    @staticmethod
    def monthdelta(date, delta):
        """
        Return the date from the given delta

        :param date: The original date
        :param delta: The change from the original date that is to be calculated.
        """
        m, y = (date.month + delta) % 12, date.year + ((date.month) + delta - 1) // 12
        if not m:
            m = 12
        d = min(
            date.day,
            [
                31,
                29 if y % 4 == 0 and not y % 400 == 0 else 28,
                31,
                30,
                31,
                30,
                31,
                31,
                30,
                31,
                30,
                31,
            ][m - 1],
        )
        return date.replace(day=d, month=m, year=y)

    def insert_record(self, result, source_name, source_metadata=None):
        """
        Insert the provided source as a record from the provided source name.
        :param result: The result of a DNS lookup as a JSON object including
                       the fqdn, type, value, zone, and created values.
        :param source_name: The DNS record source ("ssl","virustotal","sonar_dns","common_crawl")
        :param source_metadata: An optional record for additional source metadata
                        [{"key": "foo1", "value", "bar1"}, {"key": "foo2", "value", "bar2"}]
        """
        # Ensure all inserted records are lowercase
        result["fqdn"] = result["fqdn"].lower()

        query = {
            "fqdn": result["fqdn"],
            "type": result["type"],
            "value": result["value"],
        }
        check = self.mongo_connector.perform_find_one(self.all_dns_collection, query)

        if check is None:
            result["sources"] = []
            result["sources"].append({})
            result["sources"][0]["source"] = source_name
            result["sources"][0]["updated"] = datetime.now()
            if source_metadata is not None and len(source_metadata) > 0:
                for entry in source_metadata:
                    result["sources"][0][entry["key"]] = entry["value"]
            result["updated"] = datetime.now()
            self.mongo_connector.perform_insert(self.all_dns_collection, result)
        else:
            source_index = -1
            for i in range(0, len(check["sources"])):
                if check["sources"][i]["source"] == source_name:
                    source_index = i
            if source_index != -1:
                name = "sources." + str(source_index) + ".updated"
                entry = {}
                entry[name] = datetime.now()
                self.all_dns_collection.update_one(
                    {"_id": ObjectId(check["_id"])}, {"$set": entry}
                )
                self.all_dns_collection.update_one(
                    {"_id": ObjectId(check["_id"])},
                    {"$set": {"updated": datetime.now()}},
                )
                if source_metadata is not None and len(source_metadata) > 0:
                    for metadata in source_metadata:
                        self.all_dns_collection.update_one(
                            {
                                "_id": ObjectId(check["_id"]),
                                "sources.source": source_name,
                            },
                            {
                                "$set": {
                                    "sources.$." + metadata["key"]: metadata["value"],
                                }
                            },
                        )
            else:
                entry = {}
                entry["source"] = source_name
                entry["updated"] = datetime.now()
                if source_metadata is not None and len(source_metadata) > 0:
                    for metadata in source_metadata:
                        entry[metadata["key"]] = metadata["value"]

                self.all_dns_collection.update_one(
                    {"_id": ObjectId(check["_id"])}, {"$push": {"sources": entry}}
                )
                self.all_dns_collection.update_one(
                    {"_id": ObjectId(check["_id"])},
                    {"$set": {"updated": datetime.now()}},
                )

        if result["type"] == "a" or result["type"] == "aaaa":
            ip_manager = IPManager.IPManager(self.mongo_connector)
            ip_manager.insert_record(result["value"], source_name)

    def find_multiple(self, criteria, source):
        """
        Find multiple records for the specified criteria.

        :param criteria: A JSON object representing the find query. No limit support.
        :param source: (Optional) The DNS record source ("ssl","virustotal","sonar_rdns",etc.)
        :return: The cursor from the find operation
        """
        if source != None:
            criteria["sources.source"] = source

        check = self.mongo_connector.perform_find(
            self.all_dns_collection, criteria, batch_size=25
        )
        return check

    def find_one(self, criteria, source):
        """
        Find a single record for the specified criteria

        :param criteria: A JSON object representing the find query. No limit support.
        :param source: (Optional) The DNS record source ("ssl","virustotal","sonar_dns",etc.)
        :return: The cursor from the find operation
        """
        if source != None:
            criteria["sources.source"] = source

        check = self.mongo_connector.perform_find_one(self.all_dns_collection, criteria)
        return check

    def find_count(self, criteria, source):
        """
        Return the count of records for the specified criteria.

        :param criteria: A JSON object representing the find query. No limit support.
        :param source: (Optional) The DNS record source ("ssl","virustotal","sonar_dns",etc.)
        :return: The cursor from the find operation
        """
        if source != None:
            criteria["sources.source"] = source

        check = self.mongo_connector.perform_count(self.all_dns_collection, criteria)
        return check

    def remove_by_domain_and_source(self, domain, dns_type, dns_value, source):
        """
        Remove a specific all_dns entry by providing the domain, type, value and
        source of the record to be removed.

        :param domain: The domain that is to be altered
        :param dns_type: The type of record that is to be removed
        :param dns_value: The corresponding value that is to be removed
        :param source: The source of the record that is to be removed.
        :return: A boolean indicating success or failure
        """
        result = self.all_dns_collection.find_one(
            {"fqdn": domain, "type": dns_type, "value": dns_value}
        )

        if result is None:
            return False

        if len(result["sources"]) == 1:
            self.all_dns_collection.delete_one({"fqdn": domain})
            return True

        self.all_dns_collection.update_one(
            {"_id": ObjectId(result["_id"])}, {"$pull": {"sources": {"source": source}}}
        )
        return True

    def remove_by_object_id_and_source(self, object_id, source):
        """
        Remove a specific all_dns entry by providing the object_id and source to be removed.
        If an entry is associated with multiple sources,
        then only the association with the specified source will be removed.

        :param objectid: The object ID of the record.
        :param source: The source reference that is to be removed from the object_id.
        :return: A boolean indicating success or failure
        """
        result = self.all_dns_collection.find_one({"_id": ObjectId(object_id)})

        if result is None:
            return False

        if len(result["sources"]) == 1:
            self.all_dns_collection.delete_one({"_id": ObjectId(object_id)})
            return True

        self.all_dns_collection.update_one(
            {"_id": ObjectId(result["_id"])}, {"$pull": {"sources": {"source": source}}}
        )
        return True

    def remove_all_by_source_and_date(self, source, month_delta=-2):
        """
        Remove a specific all_dns entry by providing the object_id and source to be removed.
        If an entry is associated with multiple sources,
        then only the association with the specified source will be removed.

        :param source: The source of the records that are to be aged out.
        :param month_delta: How many months to keep (e.g. Keep the last two months)
        :return: A boolean indicating success or failure
        """
        d_minus_2m = self.monthdelta(datetime.now(), month_delta)
        results = self.all_dns_collection.find(
            {
                "sources": {
                    "$elemMatch": {"source": source, "updated": {"$lt": d_minus_2m}}
                }
            }
        ).batch_size(30)

        for result in results:
            if len(result["sources"]) > 1:
                self.all_dns_collection.update_one(
                    {"_id": ObjectId(result["_id"])},
                    {"$pull": {"sources": {"source": source}}},
                )
            else:
                self.all_dns_collection.delete_one({"_id": ObjectId(result["_id"])})

        return True

    def remove_by_source(self, source):
        """
        Remove all entries associated with a specific source.
        If an entry is associated with multiple sources,
        then only the association with the specified source will be removed.

        :param source: The source references that are to be removed.
        :return: A boolean indicating success or failure
        """
        results = self.all_dns_collection.find({"sources.source": source})

        if results is None:
            return False

        for result in results:
            if len(result["sources"]) == 1:
                self.all_dns_collection.delete_one({"_id": ObjectId(result["_id"])})
            else:
                self.all_dns_collection.update_one(
                    {"_id": ObjectId(result["_id"])},
                    {"$pull": {"sources": {"source": source}}},
                )
        return True
