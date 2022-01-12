'use strict';

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

var lastCensysResult;

function build_page() {
    document.getElementById("search_form").addEventListener("submit", queries);
    var searchVal = qs("search");
    if (searchVal) {
        document.getElementById("search_input").value = searchVal;
        queries();
    }
}

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

function clear_divs(handles) {
    for (let entry in handles) {
        document.getElementById(handles[entry]).innerHTML = ""
    }
}

function whois_lookup() {
    dynamic_whois(document.getElementById("search_input").value.trim().toLowerCase(), "dynamic_whois");
}

function queries(event) {
    clearErrorHandler();
    lastCensysResult = [];

    var value = document.getElementById("search_input").value.trim().toLowerCase();
    var path = window.location.pathname;

    if (path === "/domain") {
        clear_divs(["hostingLocation", "ownershipInformation", "dnsRecords", "reverseDnsRecords", "certificateRecords"]);
        // Check Ownership
        do_nslookup(value);
        ibloxOwner('host', value);
        // Check Location
        search_all_dns('domain', value);
        search_sonar_rdns('domain', value);
        // Certificate Checks
        search_ct('domain', value);
        // Scan Information
        if (ScanDataSources.includes("censys")) {
            clear_divs(["censysInformation"]);
            document.getElementById("censysInformation").style.display = "none";
            censys_rec('domain', value);
        }
        if (ScanDataSources.includes("zgrab")) {
            document.getElementById("scanInformation").style.display = "none";
            document.getElementById("scanTitleRow").innerHTML = "";
            document.getElementById("scanDataRow").innerHTML = "";
            document.getElementById("scanOutput").innerHTML = "";
            zgrab_rec('domain', value);
        }
        // Whois Information
        if (DynamicWhoisEnabled) {
            clear_divs(["dynamic_whois"]);
            document.getElementById("dynamic_whois").style.display = "bg-light";
            document.getElementById("dynamic_whois").appendChild(create_button('Perform lookup', 'whoisLookup'));
            document.getElementById("whoisLookup").addEventListener("click", whois_lookup);
        }
        if (CustomScriptSourcesEnabled) {
            custom_code_handler('/domain', 'domain', value);
        }
    } else if (path === '/ip') {
        clear_divs(["hostingLocation", "ownershipInformation", "dnsRecords", "reverseDnsRecords", "certificateRecords"]);

        // Check Ownership
        do_nslookup(value);
        ibloxOwner('ip', value);
        // Check Location
        aws_check('ip', value);
        azure_check(value);
        akamai_check('ip', value);
        gcp_check('ip', value);
        tracked_ip_range_check('ip', value);
        // DNS Records
        search_all_dns('ip', value);
        search_sonar_rdns('ip', value);
        // Certificate Checks
        search_ct('ip', value);
        // Scan Information
        if (ScanDataSources.includes("censys")) {
            clear_divs(["censysInformation"]);
            document.getElementById("censysInformation").style.display = "none";
            censys_rec('ip', value);
        }
        if (ScanDataSources.includes("zgrab")) {
            document.getElementById("scanInformation").style.display = "none";
            document.getElementById("scanTitleRow").innerHTML = "";
            document.getElementById("scanDataRow").innerHTML = "";
            document.getElementById("scanOutput").innerHTML = "";
            zgrab_rec('ip', value);
        }
        // Whois information
        if (DynamicWhoisEnabled) {
            clear_divs(["dynamic_whois"]);
            document.getElementById("dynamic_whois").style.display = "bg-light";
            document.getElementById("dynamic_whois").appendChild(create_button('Perform lookup', 'whoisLookup'));
            document.getElementById("whoisLookup").addEventListener("click", whois_lookup);
        }
        if (CustomScriptSourcesEnabled) {
            custom_code_handler('/ip', 'ip', value);
        }
    } else if (path === "/ipv6") {
        clear_divs(["hostingLocation", "ownershipInformation", "dnsRecords"]);

        // Check Ownership
        do_nslookup(value);
        ibloxOwner('ipv6', value);
        // Check Location
        aws_check('ipv6', value);
        akamai_check('ipv6', value);
        gcp_check('ipv6', value);
        tracked_ip_range_check('ipv6', value);
        // DNS Records
        search_all_dns('ipv6', value);
        // Whois information
        if (DynamicWhoisEnabled) {
            clear_divs(["dynamic_whois"]);
            document.getElementById("dynamic_whois").style.display = "bg-light";
            document.getElementById("dynamic_whois").appendChild(create_button('Perform lookup', 'whoisLookup'));
            document.getElementById("whoisLookup").addEventListener("click", whois_lookup);
        }
        if (CustomScriptSourcesEnabled) {
            custom_code_handler('/ipv6', 'ipv6', value);
        }
    }

    if (event) {
        event.preventDefault();
    }
    return false;
}

function display_nslookup(results) {
    var resDiv = document.getElementById('hostingLocation');
    var displayHTML = create_h3("NSLookup Results");
    if (results.hasOwnProperty("ips")) {
        for (let i = 0; i < results['ips'].length; i++) {
            displayHTML += create_anchor("/ip?search=" + results["ips"][i]["address"], results["ips"][i]["address"], "_blank") + ", ";
        }
        displayHTML = displayHTML.substring(0, displayHTML.length - 2);
    } else if (results.hasOwnProperty["Error"]) {
        resDiv.innerHTML = results["Error"].toString();
    } else if (results.hasOwnProperty("domains")) {
        for (let i = 0; i < results['domains'].length; i++) {
            displayHTML += results['domains'][i] + " ";
        }
    } else if (typeof results === "string") {
        displayHTML += results;
    } else {
        displayHTML += "Unknown Response";
    }
    resDiv.innerHTML += displayHTML + "<br/><br/>";
}

function do_nslookup(target) {
    var url = "/api/v1.0/utilities/nslookup";
    var query_string = "?target=" + target;

    make_get_request(url + query_string, display_nslookup);
}

function allDNSResult(results) {
    var displayHTML = create_h3("DNS Records");
    if (results.length === 0) {
        document.getElementById("dnsRecords").innerHTML = displayHTML + "<b>No DNS Records Found</b><br/><br/>";
        return;
    }
    displayHTML += create_new_table();
    displayHTML += create_table_head(["Type", "Value", "Domain", "Zone", "Sources", "Accounts"]);
    displayHTML += create_table_body();

    for (let i = 0; i < results.length; i++) {
        displayHTML += create_table_row();
        displayHTML += create_table_entry(results[i]['type']);
        displayHTML += create_table_entry(results[i]['value']);
        displayHTML += create_table_entry(create_anchor("/domain?search=" + results[i]['fqdn'], results[i]['fqdn']));
        displayHTML += create_table_entry(create_anchor("/zone?search=" + results[i]['zone'], results[i]['zone']));

        let sources = "";
        for (let source in results[i]['sources']) {
            sources += results[i]['sources'][source]['source'] + ", ";
        }
        sources = sources.substring(0, sources.length - 2);
        displayHTML += create_table_entry(sources);

        if (results[i].hasOwnProperty("accountInfo")) {
            let text = "";
            for (let entry in results[i]['accountInfo']) {
                text += results[i]['accountInfo'][entry]['key'] + " : " + results[i]['accountInfo'][entry]['value'] + ", ";
            }
            text = text.substring(0, text.length - 2);
            displayHTML += create_table_entry(text);
        } else {
            displayHTML += create_table_entry("unknown")
        }
        displayHTML += end_table_row();
    }

    displayHTML += end_table() + "<br/>";

    document.getElementById("dnsRecords").innerHTML = displayHTML;
}

function search_all_dns(type, value) {
    var url = "/api/v1.0/dns";
    var query = "";
    if (type === 'domain') {
        query = "?domain=" + value;
    } else if (type === 'zone') {
        query = "?zone=" + value;
    } else if (type === 'ip') {
        query = "?ip=" + value;
    } else if (type === 'ipv6') {
        query = "?ipv6=" + value;
    }

    make_get_request(url + query, allDNSResult, null, "sonar_dns");
}

function sonarRDNSResult(results) {
    var displayHTML = create_h3("Reverse DNS Records");
    if (results.length === 0) {
        document.getElementById("reverseDnsRecords").innerHTML = displayHTML + "<b>No RDNS Records Found</b><br/><br/>";
        return;
    }
    displayHTML += create_new_table();
    displayHTML += create_table_head(["IP", "Domain", "Zone", "Status"]);
    displayHTML += create_table_body();

    for (let i = 0; i < results.length; i++) {
        displayHTML += create_table_row();
        displayHTML += create_table_entry(create_anchor("/ip?search=" + results[i]['ip'], results[i]['ip']));
        displayHTML += create_table_entry(results[i]['fqdn']);
        displayHTML += create_table_entry(results[i]['zone']);
        displayHTML += create_table_entry(results[i]['status']);
        displayHTML += end_table_row();
    }

    displayHTML += end_table() + "<br/>";

    document.getElementById("reverseDnsRecords").innerHTML = displayHTML;
}

function search_sonar_rdns(type, value) {
    var url = "/api/v1.0/sonar/rdns";
    var query = "";
    if (type === 'domain') {
        query = "?domain=" + value;
    } else if (type === 'zone') {
        query = "?zone=" + value;
    } else if (type === 'ip') {
        query = "?ip=" + value;
    }

    make_get_request(url + query, sonarRDNSResult, null, "sonar_rdns");
}

function aws_check_result(results, type) {
    if (results['result'] === true) {
        var awsResult = document.getElementById("hostingLocation");

        let displayHTML = create_h3("AWS Information");
        if (type === 'ipv6') {
            displayHTML += "Region: " + results['record']['region'] + ", Service: " + results['record']['service'] + ", CIDR: " + results['record']['ipv6_prefix'];
        } else {
            displayHTML += "Region: " + results['record']['region'] + ", Service: " + results['record']['service'] + ", CIDR: " + results['record']['ip_prefix'];
        }
        awsResult.innerHTML += displayHTML + "<br/><br/>"
    }
}

function aws_check(type, ip) {
    var url;
    if (type === "ipv6") {
        url = "/api/v1.0/aws/ipv6_check";
    } else {
        url = "/api/v1.0/aws/ip_check";
    }
    var query = "?ip=" + ip;

    make_get_request(url + query, aws_check_result, type, "awsResult");
}

function azure_check_result(results) {
    if (results['result'] === true) {
        var azureResult = document.getElementById("hostingLocation");
        let displayHTML = create_h3("Azure Information");
        displayHTML += "True - Region: " + results['record']['region'] + ", CIDR: " + results['record']['ip_prefix'];
        azureResult.innerHTML += displayHTML + "<br/><br/>";
    }
}

function azure_check(ip) {
    var url = "/api/v1.0/azure/ip_check";
    var query = "?ip=" + ip;

    make_get_request(url + query, azure_check_result, null, "azureResult");
}

function akamai_check_result(results) {
    if (results['result'] === true) {
        var akamaiResult = document.getElementById("hostingLocation");
        let displayHTML = create_h3("Akamai Information");
        displayHTML += "Confirmed Akamai Host";
        akamaiResult.innerHTML += displayHTML + "<br/><br/>";
    }
}

function akamai_check(type, ip) {
    var url;
    if (type === "ipv6") {
        url = "/api/v1.0/akamai/ipv6_check";
    } else {
        url = "/api/v1.0/akamai/ip_check";
    }
    var query = "?ip=" + ip;

    make_get_request(url + query, akamai_check_result, null, "akamaiResult");
}

function gcp_check_result(results, type) {
    if (results['result'] === true) {
        var gcpResult = document.getElementById("hostingLocation");

        let displayHTML = create_h3("GCP Information");
        if (type === 'ipv6') {
            displayHTML += "CIDR: " + results['record']['ipv6_prefix'];
        } else {
            displayHTML += "CIDR: " + results['record']['ip_prefix'];
        }
        gcpResult.innerHTML += displayHTML + "<br/><br/>"
    }
}

function gcp_check(type, ip) {
    var url;
    if (type === "ipv6") {
        url = "/api/v1.0/gcp/ipv6_check";
    } else {
        url = "/api/v1.0/gcp/ip_check";
    }
    var query = "?ip=" + ip;

    make_get_request(url + query, gcp_check_result, type, "gcpResult");
}

function tracked_range_result(results) {
    if (results['result'] === true) {
        var hostingLocation = document.getElementById("hostingLocation");

        let displayHTML = create_h3("Confirmed Tracked CIDR Range");

        displayHTML += results['zone'];
        if (results['notes'] && results['notes'].length > 0) {
            displayHTML += " - " + results['notes'].toString();
        }
        hostingLocation.innerHTML += displayHTML + "<br/><br/>";
    }
}

function tracked_ip_range_check(type, ip) {
    var url;
    if (type === "ipv6") {
        url = "/api/v1.0/zones/ipv6_zone_check";
    } else {
        url = "/api/v1.0/zones/ip_zone_check";
    }
    var query = "?ip=" + ip;

    make_get_request(url + query, tracked_range_result, null, "hostingLocation");
}


/**
 * Fetches JSON response.
 * @returns {promise} Promise jqXHR object
 */
function retrieve_results(url, response_element) {
    return $.getJSON(url).fail(function (jqXHR, textStatus, errorThrown) {
        if (jqXHR.status === 200 && errorThrown.message.length) {
            $('#' + response_element).text('<H3>Infoblox Owner Information</H3>Infoblox Owner Error: Bad JSON! ' + errorThrown.message).addClass('boldElem');
        }
        errorHandler();
    });
}

/**
 * Renders the owner details.
 * @param owner_details: The owner information
 * @param type: The type of search performed
 * @param div_id: The div id to be populated
 */
function owner_detail_renderer(owner_details, type, div_id) {
    if (!owner_details.length) {
        return;
    }
    switch (type) {
        case 'host':
            host_owner_detail_renderer(owner_details, div_id);
            break;
        case 'ip':
            ip_owner_detail_renderer(owner_details, div_id);
            break;
    }
}

/**
 * Renders the ownership information of the domain.
 * @param owner_details: The owner information
 * @param div_id: The div id to be populated
 */
function host_owner_detail_renderer(owner_details, div_id) {
    var displayHTML = create_h3("Infoblox Owner Information");
    displayHTML += "Owner(s): " + owner_details[0]['owners'];
    document.getElementById(div_id).innerHTML += displayHTML + "<br/><br/>";
}

/**
 * Renders the ownership information of the ip.
 * @param owner_details: The owner information
 * @param div_id: The div id to be populated
 */
function ip_owner_detail_renderer(owner_details, div_id) {
    var displayHTML = create_h3("Infoblox Owner Information");
    displayHTML += create_new_table();
    displayHTML += create_table_head(["Domain", "Owners"]);
    displayHTML += create_table_body();

    for (let i = 0; i < owner_details.length; i++) {
        displayHTML += create_table_row();
        displayHTML += create_table_entry(decodeURIComponent(owner_details[i]['meta']));
        displayHTML += create_table_entry(owner_details[i]['owners']);
        displayHTML += end_table_row();
    }
    displayHTML += end_table();
    document.getElementById(div_id).innerHTML += displayHTML;
}

/**
 * Fetches the owner details.
 * @param type: The search type. IP and Host are expected values.
 * @param value: The value to be searched.
 */
function ibloxOwner(type, value) {
    var url = new URI('/api/v1.0/iblox/owners');
    url.addSearch({
        'type': type,
        'value': value
    });

    retrieve_results(url.toString(), 'ownershipInformation')
        .then(function (owner_details) {
            owner_detail_renderer(owner_details, type, 'ownershipInformation');
        });
}

function ctResults(results) {
    if (results.length === 0) {
        return;
    }

    var displayHTML = create_h3("Certificate Transparency Logs");
    displayHTML += create_new_table();
    displayHTML += create_table_head(["Common Name", "Organization"]);
    displayHTML += create_table_body();

    for (let i = 0; i < results.length; i++) {
        displayHTML += create_table_row();
        displayHTML += create_table_entry(create_anchor("/reports/display_cert?id=" + results[i]['_id'], results[i]['subject_common_names'].toString()));
        displayHTML += create_table_entry(results[i]['subject_organization_name'].toString());
        displayHTML += end_table_row();
    }

    displayHTML += end_table();

    document.getElementById("certificateRecords").innerHTML += displayHTML + "<br/>";
}

function search_ct(type, value) {
    var url = "";
    var query = "";
    if (type === "ip") {
        url = "/api/v1.0/ct/ip";
        query = "?ip=" + value;
    } else if (type === "domain") {
        url = "/api/v1.0/ct/common_name";
        query = "?cn=" + value;
    }

    make_get_request(url + query, ctResults, null, "ct");
}

function update_censys_preview(ev) {
    if (ev == null || ev.detail == null) {
        return;
    }
    ev.preventDefault();
    var id = ev.currentTarget.id;
    var parts = id.split(/:/);
    var index = parts[1].split(/_/);
    var result = lastCensysResult[index[0]][parts[0]];
    var temp = JSON.stringify(result);
    var parsed = temp.replace(/\</g, "&lt;");
    parsed = parsed.replace(/\>/g, "&gt;");
    parsed = parsed.replace(/\{/g, "<br>{");


    var cpc = document.getElementById("censysOutput");
    cpc.innerHTML = '<div id="cp_well" class="bg-light"><pre>' + parsed + '</pre></div>';
}

function censysResult(results) {
    var portList = {
        'p21': 'ftp',
        'p22': 'ssh',
        'p23': 'telnet',
        'p25': 'smtp',
        'p53': 'dns',
        'p80': 'http',
        'p110': 'pop3',
        'p143': 'imap',
        'p443': 'https',
        'p465': 'smtps',
        'p502': 'modbus',
        'p8080': 'http',
        'p993': 'imaps',
        'p995': 'pop3s',
        'p47808': 'bacnet',
        'p7547': 'cwmp'
    };
    var staticList = ["location", "ip", "autonomous_system", "createdAt", "tags", "zones", "domains", "ipint", "aws", "azure", "ports"];
    if (results.length === 0) {
        return;
    }

    var htmlOut = "";
    var censysTag = document.getElementById("censysInformation");
    document.getElementById("censysInformation").style.display = "block";

    htmlOut += '\
    <div class="table">\
      <div class="tableRow">\
        <div class="tableCell">';
    htmlOut += create_new_list();

    for (var i = 0; i < results.length; i++) {

        if (!(results[i].hasOwnProperty("tags")) || results[i]["tags"].length === 0) {
            for (let val in results[i]) {
                if (val !== "_id") {
                    htmlOut += create_list_entry(val + ':' + i.toString(), val, "#");
                }
            }
        } else {
            for (let val in results[i]) {
                if (staticList.indexOf(val) != -1) {
                    htmlOut += create_list_entry(val + ':' + i.toString(), val, "#");
                } else if ((val.startsWith("p")) && val !== "ports" && (results[i]["tags"].indexOf(portList[val]) !== -1)) {
                    htmlOut += create_list_entry(val + ':' + i.toString(), '<img src="/stylesheets/octicons/svg/file.svg" alt="data"></img>&nbsp;' + val + ' (' + portList[val] + ')', "#");
                } else if (val.startsWith("p") && val !== "ports") {
                    htmlOut += create_list_entry(val + ':' + i.toString(), val + ' (' + portList[val] + ')', "#");
                }
            }
        }
    }
    htmlOut += end_list();
    htmlOut += '</div>';
    htmlOut += '<div class="tableCell bg-light" id="censysOutput"></div>';
    htmlOut += '</div></div><br/>';


    censysTag.innerHTML = htmlOut;
    lastCensysResult = results;
    for (let i = 0; i < results.length; i++) {
        for (let val in results[i]) {
            if (val !== "_id") {
                document.getElementById(val + ":" + i.toString() + "_link").addEventListener("click", update_censys_preview);
            }
        }
    }
}

function censys_rec(type, value) {
    var url, query;
    if (type === "domain") {
        url = "/api/v1.0/censys/certs";
        query = "?common_name=" + value;
    } else {
        url = "/api/v1.0/censys/ips";
        query = "?ip=" + value;
    }

    make_get_request(url + query, censysResult, null, "scanInformation");
}

function display_scan_output(results, port) {
    let data = "";
    if (port === "22") {
        data = results[0]['data']['xssh'];
    } else if (port === "25") {
        data = results[0]['data']['smtp'];
    } else if (port === "80") {
        data = results[0]['data']['http'];
    } else if (port === "443") {
        data = results[0]['data']['http'];
    } else if (port === "465") {
        data = results[0]['data']['smtps'];
    }

    document.getElementById("scanOutput").textContent = JSON.stringify(data);
}

function display_scan_records(ev) {
    var id = ev.currentTarget.id;
    var parts = id.split(/_/);
    let port = parts[0];
    let url, query;
    if (window.location.pathname === "/ip") {
        url = "/api/v1.0/zgrab/ip";
        query = "?ip=" + document.getElementById("search_input").value.toLowerCase();
    } else {
        url = "/api/v1.0/zgrab/domain";
        query = "?domain=" + document.getElementById("search_input").value.toLowerCase();
    }
    query += "&port=" + port;
    make_get_request(url + query, display_scan_output, port, "scanOutput");
}


function create_div_title(idRef, title) {
    let displayDiv = document.createElement('div');
    displayDiv.setAttribute("id", idRef + "_title");
    displayDiv.setAttribute("class", "tableCell noWrap");
    displayDiv.innerHTML = "<b>" + title + "</b><br/>";
    return (displayDiv);
}

function create_div_data(idRef, data) {
    let displayDiv = document.createElement('div');
    displayDiv.setAttribute("id", idRef + "_data");
    displayDiv.setAttribute("class", "tableCell tableBorder alignCenter");
    if (typeof data === "string") {
        displayDiv.innerHTML = data;
    } else {
        displayDiv.appendChild(data);
    }
    return (displayDiv);
}

function addCountBox(results, source) {
    if (results['count'] !== 0) {
        document.getElementById("scanInformation").style.display = "block";
        let dataRow = document.getElementById("scanDataRow");
        dataRow.appendChild(create_div_data(source, create_button(results.count, source + "_button", "icon", "M", "search")));
        let titleRow = document.getElementById("scanTitleRow");

        if (source === "22") {
            titleRow.appendChild(create_div_title(source, "SSH"));
        } else if (source === "25") {
            titleRow.appendChild(create_div_title(source, "SMTP"));
        } else if (source === "80") {
            titleRow.appendChild(create_div_title(source, "HTTP"));
        } else if (source === "443") {
            titleRow.appendChild(create_div_title(source, "HTTPS"));
        } else if (source === "465") {
            titleRow.appendChild(create_div_title(source, "SMTPS"));
        } else {
            titleRow.appendChild(create_div_title(source, "Other"));
        }

        document.getElementById(source + "_button").addEventListener("click", display_scan_records);
    }
}

function zgrab_rec(type, value) {

    if (type === "ip") {
        let url = "/api/v1.0/zgrab/ip";
        let query = "?ip=" + value + "&count=1";
        for (let entry in ScanSupportedPorts) {
            let final_url = url + query + "&port=" + ScanSupportedPorts[entry];
            make_get_request(final_url, addCountBox, ScanSupportedPorts[entry], "scanOutput");
        }
    } else if (type === "domain") {
        var url = "/api/v1.0/zgrab/domain";
        let query = "?domain=" + value + "&count=1";
        for (let entry in ScanSupportedPorts) {
            let final_url = url + query + "&port=" + ScanSupportedPorts[entry];
            make_get_request(final_url, addCountBox, ScanSupportedPorts[entry], "scanOutput");
        }
    }
}
