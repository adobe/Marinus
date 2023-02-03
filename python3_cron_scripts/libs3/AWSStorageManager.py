#!/usr/bin/python3

# Copyright 2022 Adobe Inc. All rights reserved.
# This file is licensed to you under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License. You may obtain a copy
# of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR REPRESENTATIONS
# OF ANY KIND, either express or implied. See the License for the specific language
# governing permissions and limitations under the License.

"""
This is a simple interface for AWS S3 interactions.
DO NOT rename the methods since they are meant to be inherited by the storage manager class.
This currently assumes that credentials exist in the ~/.aws/config file as defined by Amazon.
"""

import configparser
import logging
from ast import Bytes

import boto3
from boto3.s3.transfer import TransferConfig
from libs3.ConnectorUtil import ConnectorUtil


class AWSStorageManager(object):
    _storage_config_file = "connector.config"
    _logger = None

    _aws_session = None
    _aws_region = "us-west-2"

    def _log(self):
        """
        Get the log
        """
        return logging.getLogger(__name__)

    def _auth_to_amazon(self, config):
        """
        Authenticate to Amazon
        """
        access_key_id = ConnectorUtil.get_config_setting(
            self._logger, config, "AWS", "aws.access_key_id"
        )
        secret = ConnectorUtil.get_config_setting(
            self._logger, config, "AWS", "aws.secret_access_key"
        )

        self._aws_region = ConnectorUtil.get_config_setting(
            self._logger, config, "AWS", "aws.region", "str", self._aws_region
        )

        try:
            # If the access_key and secret were not found,
            # then this defaults to the local config in ~/.aws
            self._aws_session = boto3.Session(
                aws_access_key_id=access_key_id,
                aws_secret_access_key=secret,
                region_name=self._aws_region,
            )
        except Exception as err:
            self._logger.error("Unable to authenticate to Amazon")
            self._logger.error(str(err))
            exit(1)

        self._s3_resource = self._aws_session.resource("s3")

    def __init__(self, config_file="", log_level=None) -> None:
        """
        Initialize the instance
        """

        self._logger = self._log()
        if log_level is not None:
            self._logger.setLevel(log_level)

        if config_file != "":
            self._storage_config_file = config_file

        config = configparser.ConfigParser()
        list = config.read(self._storage_config_file)
        if len(list) == 0:
            self._logger.error("Error: Could not find the config file")
            exit(1)

        self._auth_to_amazon(config)

    def write_file(self, folder: str, filename: str, data: bytes) -> bool:
        """
        Write a file to AWS
        """
        try:
            s3_object = self._s3_resource.Object(folder, filename)
            result = s3_object.put(Body=data)
            res = result.get("ResponseMetadata")
            return_status = res.get("HTTPStatusCode")
            if return_status != 200:
                self._logger.error("Unsuccessful upload to S3")
                self._logger.error("HTTP Status Code: " + str(return_status))
                return False
        except Exception as err:
            self._logger.error("Unable to upload file: " + filename + " to S3")
            self._logger.error(str(err))
            return False

        return True

    def write_large_file(
        self, folder: str, remote_file_name: str, local_file_path: str
    ) -> bool:
        """
        Upload a large file to an S3 bucket

        :param folder: The remote folder
        :param remote_file_name: Name for the new remote file
        :param local_file_path: The path to the local file
        :return: True if file was uploaded, else False
        """

        GB = 1024**3
        config = TransferConfig(multipart_threshold=4 * GB)

        try:
            bucket = self._s3_resource.Bucket(folder)

            with open(local_file_path, "rb") as data:
                bucket.upload_fileobj(data, remote_file_name)
        except Exception as e:
            logging.error(str(e))
            return False

        return True

    def create_folder(self, foldername: str) -> bool:
        """
        Create an AWS S3 bucket
        """
        try:
            self._s3_resource.create_bucket(
                Bucket=foldername,
                CreateBucketConfiguration={"LocationConstraint": self._aws_region},
            )
        except Exception as err:
            self._logger.error("Could not create the S3 bucket")
            self._logger.error(str(err))
            return False

        return True

    def read_file(self, foldername: str, filename: str, mode: str = "bytes") -> Bytes:
        """
        Read an AWS S3 file
        """
        try:
            s3_object = self._s3_resource.Object(foldername, filename)

            if mode == "text":
                data = s3_object.get()["Body"].read().decode()
            else:
                data = s3_object.get()["Body"].read()
        except Exception as err:
            self._logger.error(
                "Could not locate file: " + filename + " in " + foldername
            )
            self._logger.error(str(err))
            return None

        return data

    def delete_file(self, foldername: str, filename: str):
        """
        Delete a file within AWS
        Returns True if success, False otherwise
        """

        try:
            self._s3_client.delete_object(Bucket=foldername, Key=filename)
        except Exception as err:
            self._logger.error(
                "Could not delete file: " + filename + " in " + foldername
            )
            self._logger.error(str(err))
            return False

        return True

    def list_directory(self, foldername: str):
        """
        List all of the files in a bucket
        """
        try:
            remote_bucket = self._s3_resource.Bucket(foldername)

            results = []
            for bucket in remote_bucket.objects_all():
                results.append(bucket.key)

            return results

        except Exception as err:
            self._logger.error("Could not not list files in Bucket: " + foldername)
            self._logger.error(str(err))
            return False
