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

var portSource;

var PortList = ["21", "22", "23", "25", "53", "80", "110", "143", "443", "465", "502", "993", "995", "7547", "47808"];

var ScanServicesList = ["22", "25", "80", "443", "465"];

var DomainListPorts = ["80", "443"];

var SrvRecords = {};

var currentPort = 0;

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
    var path = window.location.pathname;
    if (path === "/meta/zone_list") {
        fetch_zone_list(null);
        document.getElementById("zone_search").addEventListener("submit", fetch_zone_pattern);
    } else if (path === "/meta/port_list") {
        portSource = qs("portSource");
        if (ScanDataSources.includes("censys") && portSource === "censys") {
            portSource = "censys";
            initialize_port_page();
        } else {
            portSource = "zgrab";
            initialize_scan_port_page();
        }
        get_srv_records();
    } else if (path === "/meta/ip_zone_list") {
        fetch_ip_zone_list();
    } else if (path === "/meta/ipv6_zone_list") {
        fetch_ipv6_zone_list();
    } else if (path === "/meta/tpd_list") {
        initialize_tpd_list();
    } else if (path === "/meta/tpd_list_detail") {
        var tpd = qs("tpd");
        if (!tpd) {
            document.getElementById('errorMessage').innerHTML = "<b>A TPD value must be provided!</b>";
            return;
        }
        display_tpd_detail(tpd);
    }
}

function createWhoisSearchBox() {
    let whoisHTML = '<h3>Whois</h3>\n';
    whoisHTML += '<form id="whois_search"><label id="zoneLabel" for="whois_input">Please enter a zone.</label>\n';
    whoisHTML += '<input type="text" value="" name="whoisSearch" id="whois_input"></input></form>\n';
    whoisHTML += '<div id="dynamic_whois" class="bg-light"></div>\n';
    document.getElementById("dynamicWhoisSection").innerHTML = whoisHTML;
    document.getElementById("whois_search").addEventListener("submit", whois_lookup);
}

function display_zone_list(results) {
    var display_list = '<div class="list-group" id="0">';
    var current_alpha_index = 0;
    var alphabet = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '\\', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'];
    var false_positives = [];
    var expired = [];

    for (let i = 0; i < results.length; i++) {
        if (results[i]['status'] === "false_positive") {
            false_positives.push(results[i]);
        } else if (results[i]['status'] === "expired") {
            expired.push(results[i]);
        } else {
            if (!(results[i]['zone'].startsWith(alphabet[current_alpha_index])) && current_alpha_index < alphabet.length) {
                display_list += end_list();
                current_alpha_index = current_alpha_index + 1;

                while (!(results[i]['zone'].startsWith(alphabet[current_alpha_index])) && (current_alpha_index < alphabet.length)) {
                    current_alpha_index = current_alpha_index + 1;
                }

                if (current_alpha_index != alphabet.length) {
                    display_list += create_new_list(alphabet[current_alpha_index]);
                } else {
                    display_list += create_new_list("other");
                }
            }

            display_list += create_list_entry(results[i]['zone'], results[i]['zone'], "/zone?search=" + results[i]['zone'], false)
        }
    }

    display_list += end_list() + '<br/><br/>';


    display_list += '<h3>Expired</h3>';
    display_list += create_new_list("expired");

    for (let i = 0; i < expired.length; i++) {
        display_list += create_list_entry(expired[i]['zone'], expired[i]['zone'], "/zone?search=" + expired[i]['zone'], false);
    }

    display_list += end_list() + '<br/><br/>';

    display_list += '<h3>False Positives</h3>';
    display_list += create_new_list("false_positives");

    for (let i = 0; i < false_positives.length; i++) {
        display_list += create_list_entry(false_positives[i]['zone'], false_positives[i]['zone'], "/zone?search=" + false_positives[i]['zone'], false);
    }

    display_list += end_list();

    document.getElementById('zoneList').innerHTML = display_list;
    document.getElementById('zoneCount').innerHTML = "Zones identified: " + results.length.toString();
}

function fetch_zone_pattern(event) {
    clearErrorHandler();
    var zone = document.getElementById("zone_input").value;
    fetch_zone_list(zone);
    event.preventDefault();
    return (false);
}

function fetch_zone_list(txtSearch) {
    var url = "/api/v1.0/zones/list";
    var query = "?include_all=1";

    if (txtSearch != null && txtSearch.length > 0) {
        query += "&pattern=" + txtSearch;
    }

    make_get_request(url + query, display_zone_list)

    return;
}

function create_table(results, type) {
    var displayHTML = create_new_table();
    displayHTML += create_table_head(["Zone", "Source", "Status", "Notes"]);
    displayHTML += create_table_body();

    for (let i = 0; i < results.length; i++) {
        displayHTML += create_table_row();
        if (type === "ip") {
            displayHTML += create_table_entry(create_anchor("/ip_range?search=" + results[i]['zone'], results[i]['zone']));
        } else {
            displayHTML += create_table_entry(results[i]['zone']);
        }
        displayHTML += create_table_entry(results[i]['source']);
        displayHTML += create_table_entry(results[i]['status']);
        if (results[i].hasOwnProperty("notes")) {
            displayHTML += create_table_entry(results[i]['notes'].toString());
        } else {
            displayHTML += create_table_entry("");
        }
        displayHTML += end_table_row();
    }

    displayHTML += end_table();
    return (displayHTML);
}

function display_ip_list(results, type) {
    var positive_results = [];
    var false_positives = [];

    for (let i = 0; i < results.length; i++) {
        if (results[i]['status'] === "false_positive") {
            false_positives.push(results[i]);
        } else {
            positive_results.push(results[i]);
        }
    }

    var countHTML = "(" + positive_results.length.toString() + ")";
    document.getElementById("ipPosCount").innerHTML = countHTML;
    document.getElementById("ipPosList").innerHTML = create_table(positive_results, type);

    countHTML = "(" + false_positives.length.toString() + ")";
    document.getElementById("falsePosCount").innerHTML = countHTML;
    document.getElementById("falsePosList").innerHTML = create_table(false_positives, type);
}

function fetch_ip_zone_list() {
    var url = "/api/v1.0/zones/ip_list";
    var query = "?include_fp=1";

    make_get_request(url + query, display_ip_list, "ip", "ipList");
}

function fetch_ipv6_zone_list() {
    var url = "/api/v1.0/zones/ipv6_list";
    var query = "?include_fp=1";

    make_get_request(url + query, display_ip_list, "ipv6", "ipv6List");
}

/**
 * Port list page
 */

function update_aws_ip(result_data, ip) {
    var knownResult = document.getElementById(ip + "-aws-mark");

    if (result_data === undefined || result_data.length === 0 || result_data['result'] === false) {
        return;
    }

    var knownNotes = document.getElementById(ip + "-notes");
    var dynHTML = "";
    if (result_data['record']) {
        dynHTML += "Region: " + result_data['record']['region'].toString() + " ";
    }
    knownNotes.innerHTML += dynHTML;

    knownResult.src = '/stylesheets/octicons/svg/check.svg';
}


function check_aws_ip(ip) {
    var url = "/api/v1.0/aws/ip_check";
    var query = "?ip=" + ip;

    make_get_request(url + query, update_aws_ip, ip);

    if (CustomScriptSourcesEnabled) {
        custom_code_handler("port_aws_check", ip);
    }
}

function update_azure_ip(result_data, ip) {
    var knownResult = document.getElementById(ip + "-azure-mark");

    if (result_data === undefined || result_data.length === 0 || result_data['result'] === false) {
        return;
    }

    var knownNotes = document.getElementById(ip + "-notes");
    var dynHTML = "";
    if (result_data['record']) {
        dynHTML += "Region: " + result_data['record']['region'].toString();
    }
    knownNotes.innerHTML = dynHTML;

    knownResult.src = '/stylesheets/octicons/svg/check.svg';
}


function check_azure_ip(ip) {
    var url = "/api/v1.0/azure/ip_check";
    var query = "?ip=" + ip;

    make_get_request(url + query, update_azure_ip, ip);
}

function update_gcp_ip(result_data, ip) {
    var knownResult = document.getElementById(ip + "-gcp-mark");

    if (result_data === undefined || result_data.length === 0 || result_data['result'] === false) {
        return;
    }

    var knownNotes = document.getElementById(ip + "-notes");
    var dynHTML = "";
    if (result_data['record']) {
        dynHTML += "Prefix: " + result_data['record']['ip_prefix'].toString() + " ";
    }
    knownNotes.innerHTML += dynHTML;

    knownResult.src = '/stylesheets/octicons/svg/check.svg';
}


function check_gcp_ip(ip) {
    var url = "/api/v1.0/gcp/ip_check";
    var query = "?ip=" + ip;

    make_get_request(url + query, update_gcp_ip, ip);
}

function update_known_ip(results, ip) {
    var knownResult = document.getElementById(ip + "-tracked-mark");
    if (results['result'] === true) {
        knownResult.src = '/stylesheets/octicons/svg/check.svg';
        var knownNotes = document.getElementById(ip + "-notes");
        var dynHTML = results['zone'];
        if (results['notes'] && results['notes'].length > 0) {
            dynHTML += " - " + results['notes'].toString();
        }
        knownNotes.innerHTML = dynHTML;
    }
}

function check_known_ip(ip) {
    var url = "/api/v1.0/zones/ip_zone_check";
    var query = "?ip=" + ip;

    make_get_request(url + query, update_known_ip, ip);
}

function displayIPList(json_results) {
    var old_tbody = document.getElementById("outputBody");
    var new_tbody = document.createElement('tbody');

    if (json_results.length >= LIMIT || PAGE > 1) {
        document.getElementById("ipTableTitle").innerHTML = "<b>Port " + currentPort + " Results</b>" + add_paging_html("ip", displayIPList);
        document.getElementById("prevPage-ip").addEventListener("click", port_page_back);
        document.getElementById("nextPage-ip").addEventListener("click", port_page_forward);
        document.getElementById("pageLimit-ip").addEventListener("change", function () { update_limit("ip") });
    } else {
        document.getElementById("ipTableTitle").innerHTML = "<b> Port " + currentPort + " Results</b>";
    }

    for (let i = 0; i < json_results.length; i++) {
        var row = new_tbody.insertRow(0);
        var cell1 = row.insertCell(0);
        var cell2 = row.insertCell(1);
        var cell3 = row.insertCell(2);
        var cell4 = row.insertCell(3);
        var cell5 = row.insertCell(4);
        var cell6 = row.insertCell(5);
        cell1.innerHTML = create_anchor("/ip?search=" + json_results[i]['ip'], json_results[i]['ip']);
        cell2.innerHTML = "<img id='" + json_results[i]['ip'] + "-tracked-mark' src='/stylesheets/octicons/svg/x.svg'/><br/>";
        cell2.style = "text-align:center";
        cell3.innerHTML = "<img id='" + json_results[i]['ip'] + "-aws-mark' src='/stylesheets/octicons/svg/x.svg'/><br/>";
        cell3.style = "text-align:center";
        cell4.innerHTML = "<img id='" + json_results[i]['ip'] + "-azure-mark' src='/stylesheets/octicons/svg/x.svg'/><br/>";
        cell4.style = "text-align:center";
        cell5.innerHTML = "<img id='" + json_results[i]['ip'] + "-gcp-mark' src='/stylesheets/octicons/svg/x.svg'/><br/>";
        cell5.style = "text-align:center";
        cell6.innerHTML = "<span id='" + json_results[i]['ip'] + "-notes'></span><br/>";

        if (json_results[i]['aws'] === true) {
            check_aws_ip(json_results[i]['ip']);
        } else if (json_results[i]['azure'] === true) {
            check_azure_ip(json_results[i]['ip']);
        } else if (json_results[i]['tracked'] === true) {
            check_known_ip(json_results[i]['ip']);
        } else if (json_results[i]['gcp'] === true) {
            check_gcp_ip(json_results[i]['ip']);
        }
    }
    old_tbody.parentNode.replaceChild(new_tbody, old_tbody)
    new_tbody.id = "outputBody";
}

function getPortIPList() {
    clearErrorHandler();
    PAGE = 1;
    var id = this.id.substring(1);
    var url;
    currentPort = id;
    if (portSource === "censys") {
        url = api_map["censys_ports"] + "?port=" + id + "&type=ip_only&";
    } else {
        url = api_map["zgrab_root"] + id + "/ips?";
    }

    PAGING_URLS["ip"] = url;

    url = url + "limit=" + LIMIT.toString() + "&page=" + PAGE.toString();

    make_get_request(url, displayIPList);
}

function displayDomainList(json_results) {
    if (json_results.length >= LIMIT || PAGE > 1) {
        document.getElementById("httpTableTitle").innerHTML = "<b>Port " + currentPort + " Results</b>" + add_paging_html("domain", displayDomainList);
        document.getElementById("prevPage-domain").addEventListener("click", domain_page_back);
        document.getElementById("nextPage-domain").addEventListener("click", domain_page_forward);
        document.getElementById("pageLimit-domain").addEventListener("change", function () { update_limit("domain") });
    } else {
        document.getElementById("httpTableTitle").innerHTML = "<b> Port " + currentPort + " Results</b>";
    }

    var old_tbody = document.getElementById("httpOutputBody");
    var new_tbody = document.createElement('tbody');
    for (let i = 0; i < json_results.length; i++) {
        var row = new_tbody.insertRow(0);
        var cell1 = row.insertCell(0);
        var cell2 = row.insertCell(1);
        cell1.innerHTML = create_anchor("/domain?search=" + json_results[i]['domain'], json_results[i]['domain']);
        let zoneList = "";
        for (let entry in json_results[i]['zones']) {
            zoneList += create_anchor("/zone?search=" + json_results[i]['zones'][entry], json_results[i]['zones'][entry]) + ", ";
        }
        zoneList = zoneList.substring(0, zoneList.length - 2);
        cell2.innerHTML = zoneList;
        cell2.style = "text-align:center";
    }
    old_tbody.parentNode.replaceChild(new_tbody, old_tbody)
    new_tbody.id = "httpOutputBody";
}

function getPortDomainList() {
    clearErrorHandler();
    PAGE = 1;
    var id = this.id.substring(2);
    var url;
    currentPort = id;
    if (portSource === "censys") {
        return;
    } else {
        url = api_map["zgrab_root"] + id + "/domains?";
    }

    PAGING_URLS["domain"] = url;

    url = url + "limit=" + LIMIT.toString() + "&page=" + PAGE.toString();
    make_get_request(url, displayDomainList);
}

function assignPortEventListeners() {
    let ports;
    if (ScanDataSources.includes("censys") && portSource === "censys") {
        ports = PortList;
    } else {
        ports = ScanServicesList;
    }

    for (let i = 0; i < ports.length; i++) {
        var elem = document.getElementById("p" + ports[i]);
        if (elem != null) {
            elem.addEventListener("click", getPortIPList);
        }
    }
}

function assignDomainPortEventListeners() {
    if (ScanDataSources.includes("censys") && portSource === "censys") {
        return;
    }

    for (let i = 0; i < DomainListPorts.length; i++) {
        var elem = document.getElementById("dp" + DomainListPorts[i]);
        if (elem != null) {
            elem.addEventListener("click", getPortDomainList);
        }
    }
}

function displayPortCountData(obj, divRef) {
    var elem = document.getElementById("portListBody");
    var parts = divRef.split(":");
    var port = parts[1];
    var row = elem.insertRow(0);
    var cell1 = row.insertCell(0);
    cell1.style = "text-align:center; padding: 10px;";
    var cell2 = row.insertCell(1);
    cell2.style = "text-align:center; padding: 10px;";
    cell1.innerHTML = "Port " + port;
    if (obj.hasOwnProperty("count")) {
        cell2.appendChild(create_button(obj.count, 'p' + port, 'variant'));
    } else if (obj.hasOwnProperty("message")) {
        cell2.innerHTML = "Error: " + obj.message;
    } else {
        cell2.innerHTML = "Error parsing response";
    }
}

function displayDomainPortCountData(obj, divRef) {
    var elem = document.getElementById("httpPortListBody");
    var parts = divRef.split(":");
    var port = parts[1];
    var row = elem.insertRow(0);
    var cell1 = row.insertCell(0);
    cell1.style = "text-align:center; padding: 10px;";
    var cell2 = row.insertCell(1);
    cell2.style = "text-align:center; padding: 10px;";
    cell1.innerHTML = "Port " + port;
    if (obj.hasOwnProperty("count")) {
        cell2.appendChild(create_button(obj.count, 'dp' + port, 'variant'));
    } else if (obj.hasOwnProperty("message")) {
        cell2.innerHTML = "Error: " + obj.message;
    } else {
        cell2.innerHTML = "Error parsing response";
    }
}

function getSrvPortIPList() {
    let port = this.id.substring(4);

    let data = SrvRecords[port];
    let old_tbody = document.getElementById("srvOutputBody");
    let new_tbody = document.createElement('tbody');

    document.getElementById("srvTableTitle").innerHTML = "<b> Port " + port + " Results</b>";

    for (let entry in data) {
        let row = new_tbody.insertRow(0);
        let cell1 = row.insertCell(0);
        cell1.style = "text-align:left; padding: 10px;";
        let cell2 = row.insertCell(1);
        cell2.style = "text-align:left; padding: 10px;";
        cell1.innerHTML = data[entry][0];
        cell2.innerHTML = data[entry][1];
    }

    old_tbody.parentNode.replaceChild(new_tbody, old_tbody)
    new_tbody.id = "srvOutputBody";
}

function process_srv(results) {

    for (let result in results) {
        let value = results[result]['value'];
        let parts = value.split(" ");
        let port = parts[2];
        if (!(SrvRecords.hasOwnProperty(port))) {
            SrvRecords[port] = [];
        }
        SrvRecords[port].push([results[result]['fqdn'], results[result]['value']])
    }

    let ports = Object.keys(SrvRecords);

    for (let portValue in ports) {
        var elem = document.getElementById("srvPortListBody");
        var row = elem.insertRow(0);
        var cell1 = row.insertCell(0);
        cell1.style = "text-align:center; padding: 10px;";
        var cell2 = row.insertCell(1);
        cell2.style = "text-align:center; padding: 10px;";
        cell1.innerHTML = "Port " + ports[portValue];
        cell2.appendChild(create_button(SrvRecords[ports[portValue]].length.toString(), 'srv-' + ports[portValue], 'variant'));
    }

    for (let portValue in ports) {
        let elem2 = document.getElementById("srv-" + ports[portValue]);
        if (elem2 != null) {
            elem2.addEventListener("click", getSrvPortIPList);
        }
    }
}

function get_srv_records() {
    let url = api_map['dns_srv'];
    let query = "?dnsType=srv";

    make_get_request(url + query, process_srv);
}

function domain_page_back() {
    let url = api_map["zgrab_root"] + currentPort + "/domains";
    let query = "";
    page_back(url, query, "domain");
}

function domain_page_forward() {
    let url = api_map["zgrab_root"] + currentPort + "/domains";
    let query = "";
    page_forward(url, query, "domain");
}

function port_page_back() {
    let url, query;
    if (portSource === "censys") {
        url = api_map["censys_ports"]
        query = "?port=" + currentPort + "&type=ip_only";
    } else {
        url = api_map["zgrab_root"] + currentPort + "/ips";
        query = "";
    }
    page_back(url, query, "ip");
}

function port_page_forward() {
    let url, query;
    if (portSource === "censys") {
        url = api_map["censys_ports"]
        query = "?port=" + currentPort + "&type=ip_only";
    } else {
        url = api_map["zgrab_root"] + currentPort + "/ips";
        query = "";
    }
    page_forward(url, query, "ip");
}

function get_counts(url, divRef) {
    make_get_request(url, displayPortCountData, divRef)
}

function get_domain_counts(url, divRef) {
    make_get_request(url, displayDomainPortCountData, divRef)
}

function initialize_port_page() {
    for (let i = 0; i < PortList.length; i++) {
        get_counts(api_map["censys_ports"] + "?port=" + PortList[i] + "&type=count", "portCount:" + PortList[i]);
    }
    window.setTimeout(assignPortEventListeners, 3000);
}

function initialize_scan_port_page() {
    for (let i = 0; i < ScanServicesList.length; i++) {
        get_counts(api_map["zgrab_root"] + ScanServicesList[i] + "/ips?count=1", "p:" + ScanServicesList[i]);
    }
    window.setTimeout(assignPortEventListeners, 3000);

    document.getElementById("zgrab_domain_scans").style.display = "block";

    for (let i = 0; i < DomainListPorts.length; i++) {
        get_domain_counts(api_map["zgrab_root"] + DomainListPorts[i] + "/domains?count=1", "dp:" + DomainListPorts[i]);
        window.setTimeout(assignDomainPortEventListeners, 3000);
    }
}

/**
 * TPD results page
 */

function display_tpd_object(results) {
    if (results.length === 0) {
        document.getElementById("tpd_detail").innerHTML = '<b>N/A</b><br/>';
        return;
    }
    var display_html = '<h3>' + results['tld'] + '</h3>';
    display_html += create_anchor("/graph?tpd=" + results['tld'], "Click here for the network graph") + "<br/><br/>";

    for (let i = 0; i < results['zones'].length; i++) {
        display_html += '<br><b>' + results['zones'][i]['zone'] + '</b><br>';
        display_html += create_new_table();
        display_html += create_table_head(["Tracked hostname", "CNAME target"]);
        display_html += create_table_body();

        for (var j = 0; j < results['zones'][i]['records'].length; j++) {
            display_html += create_table_row();
            display_html += create_table_entry(create_anchor("/domain?search=" + results['zones'][i]['records'][j]['host'], results['zones'][i]['records'][j]['host']));
            display_html += create_table_entry(results['zones'][i]['records'][j]['target']);
            display_html += end_table_row();
        }
        display_html += end_table();
    }
    document.getElementById("tpd_detail").innerHTML = display_html;
}

function display_tpd_detail(target) {
    var url = "/api/v1.0/tpds/search";
    var query = "?dataType=tpd&value=" + target;

    make_get_request(url + query, display_tpd_object, null, "tpds");
}

function display_tpd(event) {
    window.open("/meta/tpd_list_detail?tpd=" + event.target.id, "_blank");
    return (false);
}

function display_tpds(results) {
    if (results.length === 0) {
        document.getElementById("tpds").innerHTML = '<b>N/A</b><br/>';
        return;
    }

    var displayHTML = create_new_table();
    displayHTML += create_table_head(["TPD", "Count"]);
    displayHTML += create_table_body();

    for (let i = 0; i < results.length; i++) {
        displayHTML += create_table_row();
        displayHTML += create_table_entry(create_anchor("", results[i]['tld'], "", results[i]['tld']));
        displayHTML += create_table_entry(results[i]['total']);
        displayHTML += end_table_row();
    }

    displayHTML += end_table();
    document.getElementById("tpds").innerHTML = displayHTML;

    for (let i = 0; i < results.length; i++) {
        document.getElementById(results[i]['tld']).addEventListener("click", display_tpd);
    }
}

function initialize_tpd_list() {
    var url = "/api/v1.0/tpds/search";
    var query = "";

    make_get_request(url + query, display_tpds, "", "tpds");
}


function whois_lookup(event) {
    dynamic_whois(document.getElementById("whois_input").value, "dynamic_whois");
    event.preventDefault();
    return false;
}
