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

function buildPage() {
    if (ScanDataSources.includes("censys")) {
        let mainTable = document.getElementById("certCountTable");
        mainTable.className = "table";
        let censysRow = mainTable.insertRow();
        let cell1 = censysRow.insertCell(0);
        cell1.innerHTML = "Censys Records";
        let cell2 = censysRow.insertCell(1);
        cell2.id = "censysRecords";
        cell2.innerHTML = "";
    }
    if (ScanDataSources.includes("zgrab")) {
        let mainTable = document.getElementById("certCountTable");
        mainTable.className = "table";
        let censysRow = mainTable.insertRow();
        let cell1 = censysRow.insertCell(0);
        cell1.innerHTML = "ZScan Records";
        let cell2 = censysRow.insertCell(1);
        cell2.id = "zscanRecords";
        cell2.innerHTML = "";
    }
    document.getElementById("search_form").addEventListener("submit", queries);
    document.getElementById("sn_search_form").addEventListener("submit", sn_queries);

    var searchVal = qs("search");
    if (searchVal) {
        document.getElementById("search_input").value = searchVal;
        queries();
    }

    var snSearchVal = qs("sn");
    if (snSearchVal) {
        document.getElementById("sn_search_input").value = snSearchVal;
        sn_queries();
    }
}

function displayCensys(results) {
    if (results.length === 0) {
        document.getElementById("certDetails").innerHTML = "<b>No records found.</b><br/>";
        return;
    }

    var displayHTML = create_new_table();
    displayHTML += create_table_head(["IP"]);
    displayHTML += create_table_body("scroll-body");


    for (var i = 0; i < results.length; i++) {
        displayHTML += create_table_row();
        displayHTML += create_table_entry(create_anchor("/ip?search=" + results[i]['ip'], results[i]['ip']));
        displayHTML += end_table_row();
    }

    displayHTML += end_table();

    document.getElementById("certDetails").innerHTML = "<h3>Censys Records</h3>" + displayHTML;
}

function displayZscan(results) {
    if (results.length === 0) {
        document.getElementById("certDetails").innerHTML = "<b>No records found.</b><br/>";
        return;
    }

    var displayHTML = create_new_table();
    displayHTML += create_table_head(["IP/Domain"]);
    displayHTML += create_table_body("scroll-body");

    for (var i = 0; i < results.length; i++) {
        if (results[i]['ip'] !== "<nil>") {
            displayHTML += create_table_row();
            displayHTML += create_table_entry(create_anchor("ip/search?=" + results[i]['ip'], results[i]['ip']));
            displayHTML += end_table_row();
        } else {
            displayHTML += create_table_row();
            displayHTML += create_table_entry(create_anchor("domain/search?=" + results[i]['domain'], results[i]['domain']));
            displayHTML += end_table_row();
        }
    }

    displayHTML += end_table();

    document.getElementById("certDetails").innerHTML = "<h3>ZScan Records</h3>" + displayHTML;
}

function displayCT(results) {
    var displayHTML = "";
    if (Array.isArray(results)) {
        for (let i = 0; i < results.length; i++) {
            displayHTML += create_h3("Certificate " + i.toString());
            displayHTML += create_anchor("/api/v1.0/ct/download/" + results[i]['_id'], "Click to download the DER file") + "<br/";
            displayHTML += '<div class="bg-light"><pre>' + results[i]['full_certificate'] + "</pre></div><br/><br/>";
        }
        document.getElementById("certDetails").innerHTML = displayHTML;
    } else {
        displayHTML = create_anchor("/api/v1.0/ct/download/" + results['_id'], "Click to download the DER file") + "<br/";
        displayHTML += '<div class="bg-light"><pre>' + results['full_certificate'] + "</pre></div><br/>";
        document.getElementById("certDetails").innerHTML = "<h3>Certificate</h3>" + displayHTML;
    }
}

function get_details() {
    var sha_hash = document.getElementById("search_input").value.trim().toLowerCase();
    var callId = this.id;
    var url;
    var callback

    if (sha_hash != null && sha_hash != "") {
        if (callId.startsWith("censys") && sha_hash.length === 40) {
            url = "/api/v1.0/censys/certs?fingerprint_sha1=" + sha_hash;
            callback = displayCensys;
        } else if (callId.startsWith("censys")) {
            url = "/api/v1.0/censys/certs?fingerprint_sha256=" + sha_hash;
            callback = displayCensys;
        } else if (callId.startsWith("zscan") && sha_hash.length === 40) {
            url = "/api/v1.0/zgrab/443/certs?fingerprint_sha1=" + sha_hash;
            callback = displayZscan;
        } else if (callId.startsWith("zscan")) {
            url = "/api/v1.0/zgrab/443/certs?fingerprint_sha256=" + sha_hash;
            callback = displayZscan;
        } else if (callId.startsWith("cert")) {
            url = "/api/v1.0/ct/fingerprint/" + sha_hash;
            callback = displayCT;
        }
    } else {
        let serial_number = document.getElementById("sn_search_input").value.trim().toLowerCase();
        if (callId.startsWith("censys")) {
            url = "/api/v1.0/censys/certs?serial_number=" + serial_number;
            callback = displayCensys;
        } else if (callId.startsWith("zscan")) {
            url = "/api/v1.0/zgrab/443/certs?serial_number=" + serial_number;
            callback = displayZscan;
        } else if (callId.startsWith("cert")) {
            url = "/api/v1.0/ct/serial_number/" + serial_number;
            callback = displayCT;
        }
    }

    make_get_request(url, callback, null, "", []);
}

function displayCountData(results, divRef) {
    document.getElementById(divRef).innerHTML = "";
    document.getElementById(divRef).appendChild(create_button(results.count, divRef + 'Count', "variant"));
    document.getElementById(divRef + "Count").addEventListener("click", get_details);
}

function get_counts(url, divRef) {
    make_get_request(url, displayCountData, divRef, "", { "count": 0 });
}

function queries(event) {
    var sha_hash = document.getElementById("search_input").value.trim().toLowerCase();
    document.getElementById("sn_search_input").value = "";

    if (sha_hash.length === 40) {
        get_counts("/api/v1.0/ct/fingerprint/" + sha_hash + "?count=1", "certTransparency");
        if (ScanDataSources.includes("censys")) {
            get_counts("/api/v1.0/censys/certs?count=1&fingerprint_sha1=" + sha_hash, "censysRecords");
        }
        if (ScanDataSources.includes("zgrab")) {
            get_counts("/api/v1.0/zgrab/443/certs?count=1&fingerprint_sha1=" + sha_hash, "zscanRecords");
        }
    } else {
        get_counts("/api/v1.0/ct/fingerprint/" + sha_hash + "?count=1", "certTransparency");
        if (ScanDataSources.includes("censys")) {
            get_counts("/api/v1.0/censys/certs?count=1&fingerprint_sha256=" + sha_hash, "censysRecords");
        }
        if (ScanDataSources.includes("zgrab")) {
            get_counts("/api/v1.0/zgrab/443/certs?count=1&fingerprint_sha256=" + sha_hash, "zscanRecords");
        }
    }

    if (event) {
        event.preventDefault();
    }
    return false;
}

function sn_queries(event) {
    var serial_number = document.getElementById("sn_search_input").value.trim().toLowerCase();
    document.getElementById("search_input").value = "";

    get_counts("/api/v1.0/ct/serial_number/" + serial_number + "?count=1", "certTransparency");
    if (ScanDataSources.includes("censys")) {
        get_counts("/api/v1.0/censys/certs?count=1&serial_number=" + serial_number, "censysRecords");
    }
    if (ScanDataSources.includes("zgrab")) {
        get_counts("/api/v1.0/zgrab/443/certs?count=1&serial_number=" + serial_number, "zscanRecords");
    }

    if (event) {
        event.preventDefault();
    }
    return false;
}

