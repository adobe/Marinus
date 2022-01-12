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

window.addEventListener("load", buildPage);
var lastCensysResult;
var useCensys = false;

var divRefTable = {};

function add_table_row(displayName, cellID) {
    let tableRef = document.getElementById('ipRangeTable').getElementsByTagName('tbody')[0];
    let newRow = tableRef.insertRow(tableRef.rows.length);

    let newCell = newRow.insertCell(0);
    let newText = document.createTextNode(displayName);
    newCell.appendChild(newText);

    let newCell2 = newRow.insertCell();
    newCell2.id = cellID;
    newCell2.style.padding = "10px";
    let newText2 = document.createTextNode("");
    newCell2.appendChild(newText2);
}

function buildPage() {
    make_get_request("/api/v1.0/dns/sources", populateDivRefTable);
}

function continueBuildPage() {
    document.getElementById("search_form").addEventListener("submit", queries);


    if (ScanDataSources.includes("censys")) {
        useCensys = true;
    }

    var searchVal = qs("search");
    if (searchVal) {
        document.getElementById("search_input").value = searchVal;
        queries();
    }

    if (DynamicWhoisEnabled) {
        let whois_header = document.createElement('h4');
        whois_header.innerHTML = "Dynamic Whois";
        let whois_div = document.createElement('div');
        whois_div.id = "dynamic_whois";
        whois_div.style = "bg-light";
        whois_div.appendChild(create_button("Perform lookup", "whoisLookup"));
        document.getElementById("dynamic_whois_section").appendChild(whois_div);
        document.getElementById("whoisLookup").addEventListener("click", whois_lookup);
    }
}

function populateDivRefTable(results) {
    for (let result in results['sources']) {
        let val = results['sources'][result];
        divRefTable[val] = val;
    }
    continueBuildPage();
}

function whois_lookup() {
    dynamic_whois(document.getElementById("search_input").value, "dynamic_whois");
}

function displayCensys(result_text) {
    var results = JSON.parse(result_text);
    if (results.length === 0) {
        document.getElementById("rangeInfo").innerHTML = "<b>No records found.</b><br/>";
        return;
    }
    var displayHTML = create_new_table();
    displayHTML += create_table_head(["IP"]);
    displayHTML += create_table_body();

    for (var i = 0; i < results.length; i++) {
        displayHTML += create_table_row();
        displayHTML += create_table_row(create_anchor("/ip?search=" + results[i]['ip'], results[i]['ip']));
        displayHTML += end_table_row();
    }

    displayHTML += end_table();

    document.getElementById("rangeInfo").innerHTML = "<h4>Censys Records</h4>" + displayHTML;
}

function displaySRDNS(results) {
    if (results.length === 0) {
        document.getElementById("rangeInfo").innerHTML = "<b>No records found.</b><br/>";
        return;
    }
    var displayHTML = create_new_table();
    displayHTML += create_table_head(["IP", "Domain", "Zone", "Status"]);
    displayHTML += create_table_body();

    for (var i = 0; i < results.length; i++) {
        displayHTML += create_table_row();
        displayHTML += create_table_entry(create_anchor("/ip?search=" + results[i]['ip'], results[i]['ip']));
        displayHTML += create_table_entry(create_anchor("/domain?search=" + results[i]['fqdn'], results[i]['fqdn']));
        displayHTML += create_table_entry(create_anchor("/zone?search=" + results[i]['zone'], results[i]['zone']));
        displayHTML += create_table_entry(results[i]['status']);
        displayHTML += end_table_row();
    }

    displayHTML += end_table();

    document.getElementById("rangeInfo").innerHTML = "<h4>RDNS Results</h4>" + displayHTML;
}

function displayDNS(results) {
    if (results.length === 0) {
        document.getElementById("rangeInfo").innerHTML = "<b>No records found.</b><br/>";
        return;
    }
    var displayHTML = create_new_table();
    displayHTML += create_table_head(["Value", "Domain", "Zone", "Status"]);
    displayHTML += create_table_body();

    for (var i = 0; i < results.length; i++) {
        displayHTML += create_table_row();
        displayHTML += create_table_entry(create_anchor("/ip?search=" + results[i]['value'], results[i]['value']));
        displayHTML += create_table_entry(create_anchor("/domain?search=" + results[i]['fqdn'], results[i]['fqdn']));
        displayHTML += create_table_entry(create_anchor("/zone?search=" + results[i]['zone'], results[i]['zone']));

        let sourceString = "";
        for (let j = 0; j < results[i]['sources'].length; j++) {
            sourceString += results[i]['sources'][j]['source'] + ", ";
        }
        sourceString = sourceString.substring(0, sourceString.length - 2);
        displayHTML += create_table_entry(sourceString);
        displayHTML += end_table_row();
    }

    displayHTML += end_table();

    document.getElementById("rangeInfo").innerHTML = "<h4>DNS Results</h4>" + displayHTML;
}

function get_details() {
    var range = document.getElementById("search_input").value;
    var ipv4 = /^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/([0-9]|[1-2][0-9]|3[0-2]))$/;
    if (!(range.match(ipv4))) {
        document.getElementById('errorMessage').innerHTML = "Invalid Range '" + range + "'";
        return false;
    }
    var callId = this.id;
    var url;
    var callback;

    if (callId.startsWith("censys") && useCensys) {
        url = "/api/v1.0/censys/ips?range=" + range;
        callback = displayCensys;
    } else if (callId.startsWith("sonar_rdns")) {
        url = "/api/v1.0/sonar/rdns?range=" + range;
        callback = displaySRDNS;
    } else {
        url = "/api/v1.0/dns?source=" + callId.substring(0, callId.length - 5) + "&range=" + range;
        callback = displayDNS;
    }

    make_get_request(url, callback, null, "errorMessage", "[]");
}

function displayCountData(results, divRef) {
    if (results.count > 0) {
        add_table_row(divRefTable[divRef], divRef);
        document.getElementById(divRef).innerHTML = "";
        document.getElementById(divRef).appendChild(create_button(results.count, divRef + 'Count', 'variant'));
        document.getElementById(divRef + "Count").addEventListener("click", get_details);
    }
}

function queries(event) {
    var range = document.getElementById("search_input").value;
    var ipv4 = /^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/([0-9]|[1-2][0-9]|3[0-2]))$/;

    if (!(range.match(ipv4))) {
        errorHandler("Invalid Range: " + range);
        return;
    }

    if (useCensys) {
        get_counts("/api/v1.0/censys/ips?count=1&range=" + range, "censys");
    }

    for (let entry in divRefTable) {
        if (entry === "sonar_rdns") {
            make_get_request("/api/v1.0/sonar/rdns?count=1&range=" + range, displayCountData, "sonar_rdns");
        } else {
            make_get_request("/api/v1.0/dns?count=1&source=" + entry + "&range=" + range, displayCountData, entry);
        }
    }

    if (event) {
        event.preventDefault();
    }
    return false;
}
