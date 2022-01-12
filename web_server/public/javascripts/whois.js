"use strict";

/**
 * Copyright 2022 Adobe. All rights reserved.
 * This file is licensed to you under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under
 * the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR REPRESENTATIONS
 * OF ANY KIND, either express or implied. See the License for the specific language
 * governing permissions and limitations under the License.
 */

var DnssecValues = ["signed", "unsigned", "inactive", "unknown"];

var DnsServerList = [];
var DnsEmails = [];


function assignDNSEmailList(result) {
    for (let entry in result['DNS_Admins']) {
        DnsEmails.push(result['DNS_Admins'][entry]);
    }
    DnsEmails.push("none");
    initialize_whois_list();
}

function assignDNSServerList(result) {
    for (let entry in result['name_server_groups']) {
        DnsServerList.push(result['name_server_groups'][entry]);
    }
    make_get_request(api_map['config'] + "?field=DNS_Admins", assignDNSEmailList)
}
make_get_request(api_map['whois_db'] + "?distinct_groups=1", assignDNSServerList)


if (DynamicWhoisEnabled) {
    createWhoisSearchBox();
}

function initialize_whois_list() {
    let dns_server_list = document.getElementById("dnsServers");
    let dns_server_list_html = create_new_div_section("dnsServerColumn", "DNS Servers") + create_new_list("dnsServerList");
    for (let i = 0; i < DnsServerList.length; i++) {
        dns_server_list_html += create_list_entry(DnsServerList[i], DnsServerList[i] + " count: ", "#tableTitle", true);
    }
    dns_server_list_html += end_list() + end_div();
    dns_server_list.innerHTML = dns_server_list_html;

    for (let i = 0; i < DnsServerList.length; i++) {
        make_get_request("/api/v1.0/whois_db?name_server=" + DnsServerList[i] + "&count=1", displayWhoisCountData, DnsServerList[i] + "_count")
    }

    make_get_request("/api/v1.0/whois_db?count=1", displayWhoisCountData, "whois_count");


    let dnssec_list = document.getElementById("dnsSec");
    let dnssec_list_html = create_new_div_section("dnsSecColumn", "DNSSEC") + create_new_list("dnsSecList");
    for (let i = 0; i < DnssecValues.length; i++) {
        dnssec_list_html += create_list_entry(DnssecValues[i], DnssecValues[i] + " count: ", "#tableTitle", true);
    }
    dnssec_list_html += end_list() + end_div();
    dnssec_list.innerHTML = dnssec_list_html;

    for (let i = 0; i < DnssecValues.length; i++) {
        make_get_request("/api/v1.0/whois_db?dnssec=" + DnssecValues[i] + "&count=1", displayWhoisCountData, DnssecValues[i] + "_count");
    }


    let dns_email_list = document.getElementById("dnsEmails");
    let dns_email_list_html = create_new_div_section("dnsEmailColumn", "DNS Emails") + create_new_list("dnsEmailList");
    for (let i = 0; i < DnsEmails.length; i++) {
        dns_email_list_html += create_list_entry(DnsEmails[i], DnsEmails[i] + " count: ", "#tableTitle", true);
    }
    dns_email_list_html += end_list() + end_div();
    dns_email_list.innerHTML = dns_email_list_html;

    for (let key in DnsEmails) {
        make_get_request("/api/v1.0/whois_db?email=" + DnsEmails[key] + "&count=1", displayWhoisCountData, DnsEmails[key]);
    }

    window.setTimeout(assignWhoisEventListeners, 3000);
}

function displayWhoisList(jsonResults) {
    var resultDiv = document.getElementById("dnsQueryResult");
    var resultHTML = "";
    for (let i = 0; i < jsonResults.length; i++) {
        resultHTML += "<a href='/zone?search=" + jsonResults[i]['zone'] + "'>" + jsonResults[i]['zone'] + "</a><br/>";
        if (jsonResults[i].hasOwnProperty("name_servers") && jsonResults[i]['name_servers'] != null && jsonResults[i]['name_servers'].length > 0) {
            resultHTML += " - " + jsonResults[i]['name_servers'].toString() + "<br/>";
        }
        resultHTML += "<br/>";
    }
    resultDiv.innerHTML = resultHTML;
}

function getWhoisList() {
    clearErrorHandler();
    var id = this.id.split("_link")[0];
    var url;
    if (DnssecValues.indexOf(id) !== -1) {
        url = "/api/v1.0/whois_db?dnssec=" + id;
        document.getElementById("tableTitle").innerHTML = "<h3>" + id + " Results</h3>";
    } else if (DnsServerList.indexOf(id) !== -1) {
        url = "/api/v1.0/whois_db?name_server=" + id;
        document.getElementById("tableTitle").innerHTML = "<h3>" + id + " Results</h3>";
    } else {
        var email_id;
        for (var key in DnsEmails) {
            if (DnsEmails[key] === id) {
                email_id = DnsEmails[key];
            }
        }
        url = "/api/v1.0/whois_db?email=" + email_id;
        document.getElementById("tableTitle").innerHTML = "<h3>" + id + " Results</h3>";
    }

    make_get_request(url, displayWhoisList);
}

function assignWhoisEventListeners() {
    for (let i = 0; i < DnsServerList.length; i++) {
        add_click_event_listeners(DnsServerList[i], "link", getWhoisList);
    }

    for (let i = 0; i < DnssecValues.length; i++) {
        add_click_event_listeners(DnssecValues[i], "link", getWhoisList);
    }

    for (let i = 0; i < DnsEmails.length; i++) {
        add_click_event_listeners(DnsEmails[i], "link", getWhoisList);
    }
}

function displayWhoisCountData(res, divRef) {
    var cSpan = document.getElementById(divRef);
    if (cSpan == null && (divRef.indexOf("@") >= 0 || divRef === "none")) {
        cSpan = document.getElementById(divRef + "_count");
    }

    if (cSpan == null) {
        document.getElementById('errorMessage').innerHTML = "Page rendering error";
    } else if (res.hasOwnProperty("count")) {
        cSpan.innerHTML = res.count;
    } else if (res.hasOwnProperty("message")) {
        cSpan.innerHTML = "Error: " + res.message;
    } else {
        cSpan.innerHTML = "Error parsing response";
    }
}
