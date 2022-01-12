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

var vtTypes = ["referrer", "communicating", "downloaded", "urls", "pcaps"];

function buildPage() {
    var path = window.location.pathname;
    if (path === "/reports/amazon") {
        fetch_amazon_records("all", false);
    } else if (path === "/reports/virustotal_threats") {
        for (let vttype in vtTypes) {
            fetch_vt_records(vtTypes[vttype], true);
        }
        window.setTimeout(assignVTEventListeners, 1000);
    } else if (path === "/reports/dead_dns") {
        performDeadDnsLookup();
    }
}

function draw_table(results) {
    if (results.length === 0) {
        return ("<b>N/A</b><br/>");
    }

    var displayHTML = create_new_table();
    displayHTML += create_table_head(["Type", "Value", "Domain", "Zone", "Status"]);
    displayHTML += create_table_body();

    for (let i = 0; i < results.length; i++) {
        displayHTML += create_table_row();
        displayHTML += create_table_entry(results[i]['type']);
        displayHTML += create_table_entry(results[i]['value']);
        displayHTML += create_table_entry(create_anchor("/domain?search=" + results[i]['fqdn'], results[i]['fqdn']));
        displayHTML += create_table_entry(create_anchor("/zone?search=" + results[i]['zone'], results[i]['zone']));
        displayHTML += create_table_entry(results[i]['status']);
        displayHTML += end_table_row();
    }

    displayHTML += end_table() + "<br/><br/>";

    return (displayHTML);
}

function display_amazon_records(results) {
    if (results.length === 0) {
        document.getElementById("sonar_amazonaws").innerHTML = "<b>N/A</b><br/>";
        return;
    }
    var s3Entries = [];
    var elbEntries = [];
    var computeEntries = [];
    var otherEntries = [];


    for (let i = 0; i < results.length; i++) {
        if (results[i]['value'].includes("s3.amazonaws.") || results[i]['value'].includes("s3-website-us-east-1") || results[i]['value'].includes("s3-1-w.amazonaws.")) {
            s3Entries.push(results[i]);
        } else if (results[i]['value'].includes("elb.amazonaws")) {
            elbEntries.push(results[i]);
        } else if (results[i]['value'].includes("compute")) {
            computeEntries.push(results[i]);
        } else {
            otherEntries.push(results[i]);
        }
    }

    document.getElementById("sonar_amazonaws").innerHTML = "<h3>S3 entries</h3>";
    document.getElementById("sonar_amazonaws").innerHTML += draw_table(s3Entries);
    document.getElementById("sonar_amazonaws").innerHTML += "<h3>Compute entries</h3>";
    document.getElementById("sonar_amazonaws").innerHTML += draw_table(computeEntries);
    document.getElementById("sonar_amazonaws").innerHTML += "<h3>ELB entries</h3>";
    document.getElementById("sonar_amazonaws").innerHTML += draw_table(elbEntries);
    document.getElementById("sonar_amazonaws").innerHTML += "<h3>Unclassified entries</h3>";
    document.getElementById("sonar_amazonaws").innerHTML += draw_table(otherEntries);

}

function fetch_amazon_records(subdomain, count) {
    var url = "/api/v1.0/dns";
    var query = "?amazonSearch=" + subdomain;
    if (count) {
        query += "&count=1";
    }

    make_get_request(url + query, display_amazon_records, null, "sonar_amazonaws");
}

function displayVtList(jsonResults, id) {
    var resultDiv = document.getElementById("report_details");
    var resultHTML = "";
    if (id !== "pcaps") {
        for (let i = 0; i < jsonResults.length; i++) {
            resultHTML += create_h3(jsonResults[i]['zone']);
            resultHTML += create_new_table();
            resultHTML += create_table_head(["Date", "Positives", "Scanners", "Sample/URL"]);
            resultHTML += create_table_body();
            var did = "detected_" + id;
            if (id !== "urls") {
                did += "_samples";
            }
            for (let j = 0; j < jsonResults[i][did].length; j++) {
                resultHTML += create_table_row();
                if (id === "referrer") {
                    resultHTML += create_table_entry("N/A");
                } else if (id === "downloaded" || id === "communicating") {
                    resultHTML += create_table_entry(jsonResults[i][did][j]['date']);
                } else if (id === "urls") {
                    resultHTML += create_table_entry(jsonResults[i][did][j]['scan_date']);
                }
                resultHTML += create_table_entry(jsonResults[i][did][j]['positives']);
                resultHTML += create_table_entry(jsonResults[i][did][j]['total']);
                if (id !== "urls") {
                    resultHTML += create_table_entry(jsonResults[i][did][j]['sha256']);
                } else {
                    resultHTML += create_table_entry(jsonResults[i][did][j]['url']);
                }
                resultHTML += end_table_row();
            }
            resultHTML += end_table() + "<br/>";
        }
    } else {
        for (let i = 0; i < jsonResults.length; i++) {
            resultHTML += create_h3(jsonResults[i]['zone']);
            resultHTML += create_new_table();
            resultHTML += create_table_head(["ID"]);
            resultHTML += create_table_body();
            for (let j = 0; j < jsonResults[i]['pcaps'].length; j++) {
                resultHTML += create_table_row();
                resultHTML += create_table_entry(jsonResults[i]['pcaps'][j]);
                resultHTML += end_table_row();
            }
            resultHTML += end_table() + "<br/>";
        }
    }
    resultDiv.innerHTML = resultHTML;
}

function getVTList() {
    clearErrorHandler();
    var id = this.id.split("Button")[0];
    var url;
    if (vtTypes.indexOf(id) !== -1 && id !== "pcaps") {
        url = "/api/v1.0/virustotal/domainDetected?type=" + id;
    } else {
        url = "/api/v1.0/virustotal/domainPcaps";
    }
    document.getElementById("tableTitle").innerHTML = "<h3>" + id + " Results</h3>";

    make_get_request(url, displayVtList, id);
}

function assignVTEventListeners() {
    for (let i = 0; i < vtTypes.length; i++) {
        var elem = document.getElementById(vtTypes[i] + "Button");
        if (elem != null) {
            elem.addEventListener("click", getVTList);
        }
    }
}

function displayVtCountData(obj, divRef) {
    var cSpan = document.getElementById(divRef)
    if (obj.hasOwnProperty("count")) {
        cSpan.innerHTML = obj.count;
    } else if (obj.hasOwnProperty("message")) {
        cSpan.innerHTML = "Error: " + obj.message;
    } else {
        cSpan.innerHTML = "Error parsing response";
    }
}

function fetch_vt_records(type, count) {
    var url, query;
    if (type === "pcaps") {
        url = "/api/v1.0/virustotal/domainPcaps";
        if (count) {
            query = "?count=1";
        }
    } else {
        url = "/api/v1.0/virustotal/domainDetected";
        query = "?type=" + type;

        if (count) {
            query += "&count=1";
        }
    }

    make_get_request(url + query, displayVtCountData, type + "Count");
}

function displayDeadDNS(results) {
    let displayHTML = create_new_table();
    displayHTML += create_table_head(["Zone", "FQDN", "Type", "Value"]);
    displayHTML += create_table_body();

    for (let i = 0; i < results.length; i++) {
        displayHTML += create_table_row();
        displayHTML += create_table_entry(results[i]['zone']);
        displayHTML += create_table_entry(results[i]['fqdn']);
        displayHTML += create_table_entry(results[i]['type']);
        displayHTML += create_table_entry(results[i]['value']);
        displayHTML += end_table_row();
    }

    displayHTML += end_table() + "<br/><br/>";

    var deadDnsSummary = document.getElementById("deadDnsDiv");
    deadDnsSummary.innerHTML = displayHTML;
}

function performDeadDnsLookup() {
    var url = "/api/v1.0/dead_dns";
    var query = "?";

    make_get_request(url + query, displayDeadDNS);
}
