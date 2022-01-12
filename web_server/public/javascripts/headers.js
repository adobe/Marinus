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

window.addEventListener("load", custom_check);

var headerSource = "zgrab";
var headerPort = "443";

function custom_check() {
    if (CustomScriptSourcesEnabled) {
        var scr = document.createElement('script');
        scr.type = 'text/javascript';
        scr.addEventListener('load', build_page);
        scr.src = CustomScriptSrc;
        document.head.appendChild(scr);
    } else {
        build_page();
    }
}

function build_page() {
    if (CustomScriptSourcesEnabled) {
        zgrab_http_headers = Object.assign({}, zgrab_http_headers, custom_http_headers_map);
    }
    let path = window.location.pathname;
    headerSource = qs("source");
    if (headerSource == null) {
        headerSource = ScanDataSources;
    }
    if (path === "/meta/headers") {
        let headSelect = document.getElementById("headerSelect");
        headSelect.addEventListener("change", headerLookupSelection);
        let portSelect = document.getElementById("portInfo");
        portSelect.addEventListener("change", resetPort);
        for (let key in zgrab_http_headers) {
            buildReportsSelect(key, "", "");
        }
        let updateButton = document.getElementById("updateZone");
        updateButton.addEventListener("click", updateFilter);
        let updateForm = document.getElementById("zoneFilter");
        updateForm.addEventListener("submit", updateFilter);
    } else if (path === "/meta/header_details") {
        let header = qs("header");
        let value = qs("value");
        let zone = qs("zone");
        doHeaderValueLookup(header, value, zone);
    }
}

function addHeaderSelectItem(result, args) {
    let name = args[0];
    let selected = args[1];
    var headSelect = document.getElementById("headerSelect");
    for (var header in zgrab_http_headers) {
        if (header === name) {
            let opt = document.createElement('option');
            opt.appendChild(document.createTextNode(header + " - " + result["count"]));
            opt.value = header;

            if (name === selected) {
                opt.selected = true;
            }
            headSelect.appendChild(opt);
        }
    }
}


function buildReportsSelect(header, zone, selected) {
    let url;
    if (headerSource === "censys") {
        url = "/api/v1.0/censys/headers/" + header;
    } else {
        if (headerPort === "443") {
            url = "/api/v1.0/zgrab/443/headers/" + header;
        } else {
            url = "/api/v1.0/zgrab/80/headers/" + header;
        }
    }
    let query = "?count=1"
    if (zone != null && zone !== "") {
        query += "&zone=" + zone;
    }
    query += "&header_type=" + zgrab_http_headers[header];

    make_get_request(url + query, addHeaderSelectItem, [header, selected]);
}

function displayHeaderSummary(results, args) {
    let header = args[0];
    let zone = args[1];
    let displayHTML = create_new_table();
    displayHTML += create_table_head(["Value", "Count"]);
    displayHTML += create_table_body();

    for (let i = 0; i < results.length; i++) {
        displayHTML += create_table_row();
        let url = "/meta/header_details?header=" + header + '&value=' +
            encodeURIComponent(results[i]['_id']) + '&header_type=' + zgrab_http_headers[header];

        if (zone != null && zone !== "") {
            url += "&zone=" + zone;
        }
        displayHTML += create_table_entry(create_anchor(url, "<br/>" + results[i]['_id'] + "<br/><br/>", results[i]['_id'], "_blank"));
        displayHTML += create_table_entry(results[i]['count']);
        displayHTML += end_table_row();
    }

    displayHTML += end_table() + "<br/><br/>";

    let headerSummary = document.getElementById("headerList");
    headerSummary.innerHTML = displayHTML;
}

function doHeaderLookup(header, zone) {
    let url;
    if (headerSource === "censys") {
        url = "/api/v1.0/censys/headers/" + header;
    } else {
        if (headerPort === "443") {
            url = "/api/v1.0/zgrab/443/headers/" + header;
        } else {
            url = "/api/v1.0/zgrab/80/headers/" + header;
        }
    }
    let query = "?distinct=1";

    if (zone != null && zone !== "") {
        query += "&zone=" + zone;
    }
    query += "&header_type=" + zgrab_http_headers[header];

    make_get_request(url + query, displayHeaderSummary, [header, zone], "", []);
}

function headerLookupSelection(ev) {
    clearErrorHandler();
    let header = ev.target.value;
    let zone = document.getElementById("zone").value;
    doHeaderLookup(header, zone);
}

function resetPort(ev) {
    if (headerSource === "zgrab") {
        let port = ev.target.value;
        headerPort = port;
        for (let key in zgrab_http_headers) {
            buildReportsSelect(key, "", "");
        }
    } else {
        let temp = document.getElementById("p443");
        temp.checked = true;
    }
}

function updateFilter(ev) {
    clearErrorHandler();
    let selectList = document.getElementById("headerSelect");
    let header = selectList.value;
    let zone = document.getElementById("zone").value;
    if (header != null) {
        doHeaderLookup(header, zone);
    }

    //Rebuild select menu with new values
    let selectDiv = document.getElementById("selectDiv");
    selectDiv.innerHTML = '<select class="custom-select" id="headerSelect" name="headerSelect" placeholder="Choose a header"></select>';
    for (let name in zgrab_http_headers) {
        buildReportsSelect(name, zone, header);
    }

    //Reassign event listener to new select element
    let headSelect = document.getElementById("headerSelect");
    headSelect.addEventListener("change", headerLookupSelection);

    ev.preventDefault();
    return false;

}

function displayValueSummary(results, args) {
    let header = args[0];
    let value = args[1];
    let zone = args[2];
    let displayHTML = '<h3>Details of hosts';

    if (zone != null && zone !== "") {
        displayHTML += " in " + zone;
    }

    displayHTML += ' with the header: <i><u>' + header + ': ' + value + '</u></i></h3>'
    displayHTML += create_new_table();
    if (headerSource === "censys") {
        displayHTML += create_table_head(["IP", "Zones"]);
    } else {
        displayHTML += create_table_head(["Domain/IP", "Zones"]);
    }

    displayHTML += create_table_body();

    if (headerSource === "censys") {
        for (let i = 0; i < results.length; i++) {
            displayHTML += create_table_row();
            displayHTML += create_table_entry(create_anchor("ip?search=" + results[i]['ip'], results['ip']));
            displayHTML += create_table_entry(results[i]['zones']);
            displayHTML += end_table_row();
        }
    } else {
        for (let i = 0; i < results.length; i++) {
            if (results[i]['domain'] !== "<nil>") {
                displayHTML += create_table_row();
                displayHTML += create_table_entry(create_anchor("/domain?search=" + results[i]['domain'], results[i]['domain']));
                displayHTML += create_table_entry(results[i]['zones']);
                displayHTML += end_table_row();
            } else {
                displayHTML += create_table_row();
                displayHTML += create_table_entry(create_anchor("/ip?search=" + results[i]['ip'], results[i]['ip']));
                displayHTML += create_table_entry(results[i]['zones']);
                displayHTML += end_table_row();
            }
        }
    }

    displayHTML += end_table() + "<br/><br/>";

    let hostSummary = document.getElementById("hostDetails");
    hostSummary.innerHTML = displayHTML;
}

function doHeaderValueLookup(header, value, zone) {
    let url;
    if (headerSource === "censys") {
        url = "/api/v1.0/censys/headers/" + header;
    } else {
        if (headerPort === "443") {
            url = "/api/v1.0/zgrab/443/headers/" + header;
        } else {
            url = "/api/v1.0/zgrab/80/headers/" + header;
        }
    }
    let query = "?value=" + value;
    if (zone != null && zone !== "") {
        query += "&zone=" + zone;
    }
    query += "&header_type=" + zgrab_http_headers[header];

    make_get_request(url + query, displayValueSummary, [header, value, zone]);
}
