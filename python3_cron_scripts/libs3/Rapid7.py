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
This module manages interactions with the Rapid7 OpenData service.
Access to the service requires a complicated handshake with their Okta plugin.
"""

import configparser
import json
import logging
import subprocess
import time
from html.parser import HTMLParser

import requests
from requests.auth import HTTPBasicAuth

from libs3.ConnectorUtil import ConnectorUtil


class MyHTMLParser(HTMLParser):
    """
    Create a subclass to find the files within the authenticated HTML page.
    """

    any_url = ""
    a_url = ""
    aaaa_url = ""
    mx_url = ""
    cname_url = ""
    txt_url = ""
    txt_mx_dmarc = ""
    txt_mx_mta_sts = ""
    rdns_url = ""
    base_url = ""

    def set_base_location(self, base_location):
        self.base_url = base_location

    def handle_starttag(self, tag, attrs):
        logger = logging.getLogger(__name__)
        if tag == "a":
            for attr in attrs:
                if (
                    self.any_url == ""
                    and attr[0] == "href"
                    and attr[1].endswith("fdns_any.json.gz")
                ):
                    logger.info(attr[1])
                    self.any_url = self.base_url + attr[1]
                elif (
                    self.a_url == ""
                    and attr[0] == "href"
                    and attr[1].endswith("fdns_a.json.gz")
                ):
                    logger.info(attr[1])
                    self.a_url = self.base_url + attr[1]
                elif (
                    self.aaaa_url == ""
                    and attr[0] == "href"
                    and attr[1].endswith("fdns_aaaa.json.gz")
                ):
                    logger.info(attr[1])
                    self.aaaa_url = self.base_url + attr[1]
                elif (
                    self.mx_url == ""
                    and attr[0] == "href"
                    and attr[1].endswith("fdns_mx.json.gz")
                ):
                    logger.info(attr[1])
                    self.mx_url = self.base_url + attr[1]
                elif (
                    self.cname_url == ""
                    and attr[0] == "href"
                    and attr[1].endswith("fdns_cname.json.gz")
                ):
                    logger.info(attr[1])
                    self.cname_url = self.base_url + attr[1]
                elif (
                    self.txt_url == ""
                    and attr[0] == "href"
                    and attr[1].endswith("fdns_txt.json.gz")
                ):
                    logger.info(attr[1])
                    self.txt_url = self.base_url + attr[1]
                elif (
                    self.txt_mx_dmarc == ""
                    and attr[0] == "href"
                    and attr[1].endswith("fdns_txt_mx_dmarc.json.gz")
                ):
                    logger.info(attr[1])
                    self.txt_mx_dmarc = self.base_url + attr[1]
                elif (
                    self.txt_mx_mta_sts == ""
                    and attr[0] == "href"
                    and attr[1].endswith("fdns_txt_mx_mta-sts.json.gz")
                ):
                    logger.info(attr[1])
                    self.txt_mx_mta_sts = self.base_url + attr[1]
                elif (
                    self.rdns_url == ""
                    and attr[0] == "href"
                    and attr[1].endswith("rdns.json.gz")
                ):
                    logger.info(attr[1])
                    self.rdns_url = self.base_url + attr[1]


class MySAMLParser(HTMLParser):
    """
    This sub-class searches an HTML response for the SAML data
    """

    saml_response = ""
    relay_state = ""

    def handle_starttag(self, tag, attrs):
        if tag == "input":
            found_saml = False
            found_relay = False
            for attr in attrs:
                if (
                    self.saml_response == ""
                    and attr[0] == "name"
                    and attr[1] == "SAMLResponse"
                ):
                    found_saml = True
                elif (
                    self.relay_state == ""
                    and attr[0] == "name"
                    and attr[1] == "RelayState"
                ):
                    found_relay = True
                elif found_saml and attr[0] == "value":
                    self.saml_response = attr[1]
                elif found_relay and attr[0] == "value":
                    self.relay_state = attr[1]


class Rapid7(object):
    """
    This class is designed for interacting with Rapid7
    """

    rapid7_config_file = "connector.config"
    USERNAME = None
    PASSWORD = None
    AUTH_URL = None
    BASE_URL = "https://opendata.rapid7.com"
    FDNS_PATH = "/sonar.fdns_v2/"
    RDNS_PATH = "/sonar.rdns_v2/"
    PID_FILE = None
    _logger = None

    def _log(self):
        """
        Get the log
        """
        return logging.getLogger(__name__)

    def _init_Rapid7(self, config):
        self.AUTH_URL = ConnectorUtil.get_config_setting(
            self._logger, config, "Rapid7", "rapid7.auth_url"
        )
        self.USERNAME = ConnectorUtil.get_config_setting(
            self._logger, config, "Rapid7", "rapid7.username"
        )
        self.PASSWORD = ConnectorUtil.get_config_setting(
            self._logger, config, "Rapid7", "rapid7.password"
        )

    def __init__(self, config_file="", log_level=None):
        if config_file != "":
            self.rapid7_config_file = config_file

        self._logger = self._log()
        if log_level is not None:
            self._logger.setLevel(log_level)

        config = configparser.ConfigParser()
        list = config.read(self.rapid7_config_file)
        if len(list) == 0:
            self._logger.error("Error: Could not find the config file")
            exit(1)

        self._init_Rapid7(config)

    def find_file_locations(self, s, list_type, jobs_manager):
        """
        In order to login, it is necessary go through several Okta steps since Rapid 7 doesn't have an API key.
        """
        if list_type == "rdns":
            list_location = self.BASE_URL + self.RDNS_PATH
        else:
            list_location = self.BASE_URL + self.FDNS_PATH

        # Assembled as a string because their site is extremely picky on the format.
        auth_payload = (
            '{"username":"'
            + self.USERNAME
            + '","password":"'
            + self.PASSWORD.replace('"', '\\"')
            + '",'
        )
        auth_payload = (
            auth_payload
            + '"options":{"warnBeforePasswordExpired":true,"multiOptionalFactorEnroll":true}}'
        )

        res = requests.post(
            self.AUTH_URL,
            data=auth_payload,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "X-Okta-User-Agent-Extended": "okta-signin-widget-2.6.0",
                "Host": "rapid7ipimseu.okta-emea.com",
                "Origin": "https://insight.rapid7.com",
            },
        )

        if res.status_code != 200:
            self._logger.error("Failed login")
            self._logger.error(res.text)
            jobs_manager.record_job_error()
            exit(1)

        data = json.loads(res.text)

        # This URL is embedded in the JS from the login page. Should try to dynamically extract it in the next revision
        # view-source:https://insight.rapid7.com/login
        res = s.get(
            "https://rapid7ipimseu.okta-emea.com/login/sessionCookieRedirect?checkAccountSetupComplete=true&token="
            + data["sessionToken"]
            + "&redirectUrl=https://rapid7ipimseu.okta-emea.com/home/template_saml_2_0/0oatgdg8ruitg9ZTr0i6/3079"
        )

        if res.status_code != 200:
            self._logger.error("Unable to do cookie redirect")
            self._logger.error(res.text)
            jobs_manager.record_job_error()
            exit(1)

        # Fetch the SAML Tokens for the Rapid7 site
        saml_parser = MySAMLParser()
        saml_parser.feed(res.text)
        saml_data = {
            "RelayState": saml_parser.relay_state,
            "SAMLResponse": saml_parser.saml_response,
        }

        res = s.post("https://insight.rapid7.com/saml/SSO", data=saml_data)

        if res.status_code != 200:
            self._logger.error("SSO Failure!")
            self._logger.error(res.text)
            jobs_manager.record_job_error()
            exit(1)

        # A final redirect step for the Open Data site
        res = s.get("https://insight.rapid7.com/redirect/doRedirect")

        # Finally download the list of files available to authenticated users.
        req = s.get(list_location)

        if req.status_code != 200:
            self._logger.error("Bad Request")
            jobs_manager.record_job_error()
            exit(1)

        parser = MyHTMLParser()
        parser.set_base_location(self.BASE_URL)
        parser.feed(req.text)
        return parser
