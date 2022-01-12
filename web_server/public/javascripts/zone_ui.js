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

var layout = {};


function custom_check() {
    if (CustomScriptSourcesEnabled) {
        var scr = document.createElement('script');
        scr.type = 'text/javascript';
        scr.addEventListener('load', start_page);
        scr.src = CustomScriptSrc;
        document.head.appendChild(scr);
    } else {
        start_page();
    }
}

function start_page() {
    if (CustomScriptSourcesEnabled) {
        api_map = Object.assign({}, api_map, custom_api_map);
    }

    var zone = qs("search");
    document.getElementById("search_form").addEventListener("submit", search_click);

    if (zone) {
        document.getElementById("search_input").value = zone;
        initialize_data(zone);
    }

    if (DynamicWhoisEnabled) {
        let whoisHTML = create_button("Whois Lookup", "whoisLookup", "icon", "S", "search");
        document.getElementById("whois_button").innerHTML = whoisHTML;
        document.getElementById("whoisLookup").addEventListener("click", whois_lookup);
    }
}

function search_click(event) {
    document.getElementById("htTitleRow").innerHTML = "";
    document.getElementById("htDataRow").innerHTML = "";
    document.getElementById("dnsTitleRow").innerHTML = "";
    document.getElementById("dnsDataRow").innerHTML = "";
    document.getElementById("dnsSection").style.display = "none";
    document.getElementById("ownTitleRow").innerHTML = "";
    document.getElementById("ownDataRow").innerHTML = "";
    document.getElementById("ownMiscRow").innerHTML = "";
    document.getElementById("ownSection").style.display = "none";
    document.getElementById("secTitleRow").innerHTML = "";
    document.getElementById("secDataRow").innerHTML = "";
    document.getElementById("secSection").style.display = "none";
    document.getElementById("miscTitleRow").innerHTML = "";
    document.getElementById("miscDataRow").innerHTML = "";
    document.getElementById("scanSection").style.display = "none";
    document.getElementById("scanTitleRow").innerHTML = "";
    document.getElementById("scanDataRow").innerHTML = "";
    document.getElementById("output").innerHTML = "";
    initialize_data(document.getElementById("search_input").value.trim().toLowerCase());
    event.preventDefault();
    return false;
}

function initialize_data(zone) {
    clearErrorHandler();
    fetch_zone_request(zone);
}

function fetch_zone_request(zone) {
    let url = api_map["zones"] + zone;
    make_get_request(url, display_zone_data, null, "", { "message": "Zone not found" });
}

function display_zone_data(results) {
    if ('message' in results) {
        document.getElementById("overviewTable").innerHTML = "<b>Zone not found!</b>";
        return;
    }

    let innerHTML = create_new_div_section("zoneOverview", "Overview");
    innerHTML += create_new_table();
    innerHTML += create_table_head(["Zone", "Sources", "Status", "Notes"]);
    innerHTML += create_table_body();
    innerHTML += create_table_row();
    innerHTML += create_table_entry(results["zone"]);

    let sources = '';
    for (let result in results['reporting_sources']) {
        sources = sources + results['reporting_sources'][result]['source'];

        if (results['reporting_sources'][result]['source'] == "UltraDNS") {
            if ('accountName' in results['reporting_sources'][result]) {
                sources = sources + " - accountName: " + results['reporting_sources'][result]['accountName'];
            }
        }

        sources = sources + ", ";
    }
    sources = sources.substring(0, sources.length - 2);

    innerHTML += create_table_entry(sources);
    innerHTML += create_table_entry(results["status"]);

    if (results.hasOwnProperty("notes") && results['notes'] != null && results['notes'].length > 0) {
        innerHTML += create_table_entry(results['notes'].toString());
    } else {
        innerHTML += create_table_entry("-");
    }
    innerHTML += end_table_row();
    innerHTML += end_table();
    innerHTML += end_div() + "<br/>";
    document.getElementById("overviewTable").innerHTML = innerHTML;

    //We know we are tracking this zone, so do the rest of the searches.
    zone_data_requests(results['zone']);
}

function zone_data_requests(zone) {
    // Hosting table
    layout['network_graph'] = { 'target': 'ht', 'desc': 'Network Graph' };
    fetch_request("network_graph", zone, true);
    fetch_whois_count(zone);

    // Security Information
    layout['ct'] = { 'target': 'sec', 'desc': "CT Log Records" };
    fetch_request("ct", zone, true);
    if (ScanDataSources.includes("censys")) {
        layout['censys_certs'] = { 'target': 'sec', 'desc': "Certificate Hosts (Censys)" };
        fetch_request("censys_certs", zone, true);
        layout['censys_algorithm'] = { 'target': 'sec', 'desc': "SHA1 TLS Servers (Censys)" };
        fetch_request("censys_algorithm", zone, true);
    }
    if (ScanDataSources.includes("zgrab")) {
        layout['scan_certs'] = { 'target': 'sec', 'desc': "Certificate Hosts (Zgrab)" };
        fetch_request("scan_certs", zone, true);
        layout['scan_algorithm'] = { 'target': 'sec', 'desc': "SHA1 TLS Servers (Zgrab)" };
        fetch_request("scan_algorithm", zone, true);
        layout['scan_zone_port_22'] = { 'target': 'scan', 'desc': "SSH Services" };
        fetch_request("scan_zone_port_22", zone, true);
        layout['scan_zone_port_25'] = { 'target': 'scan', 'desc': "SMTP Services" };
        fetch_request("scan_zone_port_25", zone, true);
        layout['scan_zone_port_80'] = { 'target': 'scan', 'desc': "HTTP Services" };
        fetch_request("scan_zone_port_80", zone, true);
        layout['scan_zone_port_443'] = { 'target': 'scan', 'desc': "HTTPS Services" };
        fetch_request("scan_zone_port_443", zone, true);
        layout['scan_zone_port_465'] = { 'target': 'scan', 'desc': "SMTPS Services" };
        fetch_request("scan_zone_port_465", zone, true);
    }

    // DNS information
    layout['all_dns'] = { 'target': 'dns', 'desc': "Total DNS Records" };
    fetch_request("all_dns", zone, true);
    layout['dns_mx'] = { 'target': 'dns', 'desc': "DNS MX Records" };
    fetch_request("dns_mx", zone, true);
    layout['dns_spf'] = { 'target': 'dns', 'desc': "DNS SPF Records" };
    fetch_request("dns_spf", zone, true);
    layout['dns_soa'] = { 'target': 'dns', 'desc': "DNS SOA Records" };
    fetch_request("dns_soa", zone, true);
    layout['dns_a'] = { 'target': 'dns', 'desc': "DNS A Records" };
    fetch_request("dns_a", zone, true);
    layout['dns_aaaa'] = { 'target': 'dns', 'desc': "DNS AAAA Records" };
    fetch_request("dns_aaaa", zone, true);
    layout['dns_cname'] = { 'target': 'dns', 'desc': "DNS CNAME Records" };
    fetch_request("dns_cname", zone, true);
    layout['dns_txt'] = { 'target': 'dns', 'desc': "DNS TXT Records" };
    fetch_request("dns_txt", zone, true);
    layout['dns_srv'] = { 'target': 'dns', 'desc': "DNS SRV Records" };
    fetch_request("dns_srv", zone, true);
    layout['sonar_rdns'] = { 'target': 'dns', 'desc': "RDNS Records" };
    fetch_request("sonar_rdns", zone, true);

    // Miscellaneous
    layout['vt_domains'] = { 'target': 'misc', 'desc': "VirusTotal Domains" };
    fetch_request("vt_domains", zone, true);
    layout['vt_ips'] = { 'target': 'misc', 'desc': "VirusTotal IPs" };
    fetch_request("vt_ips", zone, true);
    layout['vt_meta'] = { 'target': 'misc', 'desc': "VirusTotal Metadata" };
    fetch_request("vt_meta", zone, true);

    // Ownership Information
    layout['iblox_owners'] = { 'target': 'own', 'desc': "Infoblox Ownership" };
    fetch_request("iblox_owners", zone, false);

    if (CustomScriptSourcesEnabled) {
        custom_code_handler("zone_ui_data_requests", zone, true);
    }
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

function display_graph_link(results) {
    if (!('message' in results)) {
        document.getElementById("htTitleRow").prepend(create_div_title("net_graph", "Network Graph"));
        document.getElementById("htDataRow").prepend(create_div_data("net_graph", create_button("View Graph", "net_graph_button", "icon", "S", "search")));

        document.getElementById("net_graph_button").addEventListener("click", function () { window.open('/graph?zone=' + document.getElementById("search_input").value); });
    }
}

function display_cert_graph_link(results) {
    if (!('message' in results) && document.getElementById('cert_graph_button') == null) {
        document.getElementById("secDataRow").prepend(create_div_data("cert_graph", create_button("View Certificate Graph", "cert_graph_button", "icon", "S", "search")));
        document.getElementById("secTitleRow").prepend(create_div_title("cert_graph", "TLS Certificate Graph"));

        document.getElementById("cert_graph_button").addEventListener("click", function () { window.open('/cert_graph?zone=' + document.getElementById("search_input").value); });
    }
}

function display_whois_data(results) {
    if ('message' in results) {
        return;
    }
    var dnsResults = results['name_servers'];
    var names = "Not Found";
    if (dnsResults != null && dnsResults.length > 0) {
        names = "";
        for (name in dnsResults) {
            names += dnsResults[name] + ", ";
        }
    }
    names = names.slice(0, -2);

    document.getElementById("htTitleRow").appendChild(create_div_title("whois", "Whois Lookup"));
    document.getElementById("htDataRow").appendChild(create_div_data("whois", create_button("View Whois", "whois_db_button", "icon", "S", "search")));

    document.getElementById("htTitleRow").appendChild(create_div_title("dns_servers", "DNS Servers"));
    document.getElementById("htDataRow").appendChild(create_div_data("dns_servers", names));

    document.getElementById("whois_db_button").addEventListener("click", display_records)
}

function display_response(results, source) {
    var displayHTML = create_new_table();

    if (source === "sonar_rdns") {
        displayHTML += create_table_head(["Domain", "IP"]);
    } else if (source === "all_dns" || source.substring(0, 4) === "dns_") {
        displayHTML += create_table_head(["Domain", "Type", "Value"]);
    } else if (source === "ct") {
        displayHTML += create_table_head(["Common Name", "Organization", "SHA256"]);
    } else if (source === "censys_algorithm" || source === "scan_algorithm") {
        displayHTML += create_table_head(["IP", "Common Name", "Organization"]);
    } else if (source === "censys_certs" || source === "scan_certs") {
        displayHTML += create_table_head(["IP", "Certificate", "Common Name", "Organization"]);
    } else if (source === "iblox_cnames") {
        displayHTML += create_table_head(["Domain", "CNAME"]);
    } else if (source === "vt_domains") {
        displayHTML += create_table_head(["Domain"]);
    } else if (source === "vt_ips") {
        displayHTML += create_table_head(["IP", "Last Resolved"]);
    } else if (source === "vt_meta") {
        displayHTML += create_table_head(["VirusTotal Metadata"]);
    } else if (source === "whois_db") {
        displayHTML += create_table_head(["Name", "Value"]);
    } else if (source.substring(0, 15) === "scan_zone_port_") {
        displayHTML += create_table_head(["IP/Domain", "Location"]);
    } else if (CustomScriptSourcesEnabled) {
        displayHTML += custom_code_handler("zone_ui_table_header", source);
    }

    displayHTML += create_table_body();

    if (source === "whois_db") {
        let temp = [results];
        results = temp;
    }

    for (let i = 0; i < results.length; i++) {
        displayHTML += create_table_row();
        if (source === "sonar_rdns") {
            displayHTML += create_table_entry(create_anchor("/domain?search=" + results[i]['fqdn'], results[i]['fqdn']));
            displayHTML += create_table_entry(create_anchor("/ip?search=" + results[i]['ip'], results[i]['ip']));
        } else if (source === "all_dns" || source.substring(0, 4) === "dns_") {
            displayHTML += create_table_entry(create_anchor("/domain?search=" + results[i]['fqdn'], results[i]['fqdn']));
            displayHTML += create_table_entry(results[i]['type']);
            if (results[i]['type'] === "a") {
                displayHTML += create_table_entry(create_anchor("/ip?search=" + results[i]['value'], results[i]['value']));
            } else if (results[i]['type'] === "cname") {
                displayHTML += create_table_entry(create_anchor("/domain?search=" + results[i]['value'], results[i]['value']));
            } else {
                displayHTML += create_table_entry(results[i]['value']);
            }
        } else if (source === "ct") {
            displayHTML += create_table_entry(results[i]['subject_common_names'].toString());
            displayHTML += create_table_entry(results[i]['subject_organization_name'].toString());
            let sha256 = results[i]['fingerprint_sha256'].toString();
            displayHTML += create_table_entry(create_anchor("/reports/display_cert?type=ct_sha256&sha256=" + sha256, sha256, "_blank"));
        } else if (source === "censys_algorithm" || source === "censys_certs") {
            displayHTML += create_table_entry(create_anchor("/ip?search=" + results[i]['ip'], results[i]['ip']));
            if (source == "censys_certs") {
                let sha256 = results[i]['p443']['https']['tls']['certificate']['parsed']['sha256'];
                displayHTML += create_table_entry(create_anchor("/reports/display_cert?type=censys_sha256&sha256=" + sha256, sha256, "_blank"));
            }
            displayHTML += create_table_entry(results[i]['p443']['https']['tls']['certificate']['parsed']['subject']['common_name']);
            displayHTML += create_table_entry(results[i]['p443']['https']['tls']['certificate']['parsed']['subject']['organization']);
        } else if (source === "scan_algorithm" || source === "scan_certs") {
            if (results[i]['ip'] !== '<nil>') {
                displayHTML += create_table_entry(create_anchor("/ip?search=" + results[i]['ip'], results[i]['ip']));
            } else {
                displayHTML += create_table_entry(create_anchor("/domain?search=" + results[i]['domain'], results[i]['domain']));
            }

            if (source == "scan_certs") {
                let tls_log = get_tls_log(results, i);

                let sha256 = tls_log['server_certificates']['certificate']['parsed']['fingerprint_sha256'];
                displayHTML += create_table_entry(create_anchor("/reports/display_cert?type=zgrab_sha256&sha256=" + sha256, sha256, "_blank"));
                displayHTML += create_table_entry(tls_log['server_certificates']['certificate']['parsed']['subject']['common_name']);
                displayHTML += create_table_entry(tls_log['server_certificates']['certificate']['parsed']['subject']['organization']);
            } else {
                let tls_log = get_tls_log(results, i);

                displayHTML += create_table_entry(tls_log['server_certificates']['certificate']['parsed']['subject']['common_name']);
                displayHTML += create_table_entry(tls_log['server_certificates']['certificate']['parsed']['subject']['organization']);
            }
        } else if (source === "vt_domains") {
            let data = "";
            if (results[i]['subdomains']) {
                for (let j = 0; j < results[i]['subdomains'].length; j++) {
                    data += create_anchor("/domain?search=" + results[i]['subdomains'][j], results[i]['subdomains'][j]) + '<br/>';
                }
            }
            if (results[i]['domain_siblings']) {
                for (let j = 0; j < results[i]['domain_siblings'].length; j++) {
                    data += create_anchor("/domain?search=" + results[i]['domain_siblings'][j], results[i]['domain_siblings'][j]) + '<br/>';
                }
            }
            displayHTML += create_table_entry(data);
        } else if (source === "vt_ips") {
            let data = ""
            if (results[i]['resolutions']) {
                for (let j = 0; j < results[i]['resolutions'].length; j++) {
                    if (j != 0) {
                        data += create_table_row();
                    }
                    data += create_table_entry(create_anchor("/ip?search=" + results[i]['resolutions'][j]['ip_address'], results[i]['resolutions'][j]['ip_address']));
                    data += create_table_entry(results[i]['resolutions'][j]['last_resolved']);
                    if (j != results[i]['resolutions'].length - 1) {
                        data += end_table_row();
                    }
                }
            }
            displayHTML += data;
        } else if (source === "vt_meta") {
            let data = "Alexa category: " + results[i]["Alexa category"] + "<br/>";
            data += "Alexa rank: " + results[i]["Alexa rank"] + "<br/>";
            data += "Alexa domain info: " + results[i]["Alexa domain info"] + "<br/>";

            data += "WOT domain info: " + JSON.stringify(results[i]["WOT domain info"]) + "<br/>";
            data += "Webutation domain info: " + JSON.stringify(results[i]["Webutation domain info"]) + "<br/>";
            data += "categories: " + JSON.stringify(results[i]["categories"]) + "<br/>";

            data += "Websense ThreatSeeker category: " + results[i]["Websense ThreatSeeker category"] + "<br/>";
            data += "BitDefender category: " + results[i]["BitDefender category"] + "<br/>";
            data += "TrendMicro category: " + results[i]["TrendMicro category"] + "<br/>";
            displayHTML += create_table_entry(data);
        } else if (source === "whois_db") {
            let temp = "";
            let tr_end = end_table_row();
            for (let key in results[0]) {
                if (temp.endsWith(tr_end)) {
                    temp += create_table_row();
                }
                temp += create_table_entry("<b>" + key + "</b>");
                temp += create_table_entry(results[0][key]);
                temp += tr_end;
            }
            temp = temp.substring(0, temp.length - tr_end.length);
            displayHTML += temp;
        } else if (source.substring(0, 15) === "scan_zone_port_") {
            if (results[i]['ip'] === "<nil>") {
                displayHTML += create_table_entry(create_anchor("/domain?search=" + results[i]['domain'], results[i]['domain'], "_blank"));
            } else {
                displayHTML += create_table_entry(create_anchor("/ip?search=" + results[i]['ip'], results[i]['ip'], "_blank"));
            }
            if (results[i]['azure']) {
                displayHTML += create_table_entry("Azure");
            } else if (results[i]['aws']) {
                displayHTML += create_table_entry("AWS");
            } else if (results[i]['tracked']) {
                displayHTML += create_table_entry("Owned CIDR");
            } else {
                displayHTML += create_table_entry("Unknown");
            }
        } else {
            if (CustomScriptSourcesEnabled) {
                displayHTML += custom_code_handler("zone_ui_table_row", source, results, i);
            }
        }
        displayHTML += end_table_row();
    }

    displayHTML += end_table();

    document.getElementById("output").innerHTML = displayHTML;
}

function display_records() {
    document.getElementById("errorMessage").innerHTML = "";

    var reqID = this.id;
    var reqName = reqID.slice(0, -7);
    var url = api_map[reqName];
    var zone = document.getElementById("search_input").value;
    var query = "?zone=" + zone;

    if (reqName === "dns_spf") {
        query += "&txtSearch=spf";
    } else if (reqName.substring(0, 4) === "dns_") {
        query += "&dnsType=" + reqName.substring(4);
    } else if (reqName.substring(0, 15) === "scan_zone_port_") {
        query += "&port=" + reqName.substring(15);
    }

    make_get_request(url + query, display_response, reqName, "output");
}

/**
 * Displays the infoblox owner information.
 * @param results: Owner information.
 */
function display_infoblox_owners(results) {
    if (results.length) {
        document.getElementById("ownTitleRow").appendChild(create_div_title("iblox_owner", "Infoblox Owners"));
        document.getElementById("ownDataRow").appendChild(create_div_data("iblox_owner", results[0]['owners']));
    }
}

function fetch_whois_count(zone) {
    let url = api_map["whois_db"] + "?zone=" + zone;
    make_get_request(url, display_whois_data);
}

function addCountBox(source, results) {
    let dataRow = document.getElementById(layout[source]['target'] + "DataRow");
    dataRow.appendChild(create_div_data(source, create_button(results.count, source + "_button", "icon", "M", "search")));
    let titleRow = document.getElementById(layout[source]['target'] + "TitleRow");
    titleRow.appendChild(create_div_title(source, layout[source]['desc']));

    document.getElementById(source + "_button").addEventListener("click", display_records);
}

function display_response_count(results, source) {

    if (source === "iblox_owners" && results.length > 0) {
        document.getElementById("ownSection").style.display = "block";
        display_infoblox_owners(results);
    } else if (results.count > 0) {
        if (layout[source]['target'] === "misc" || layout[source]['target'] === "sec") {
            document.getElementById("secSection").style.display = "block";
        } else if (layout[source]['target'] === "ht" || layout[source]['target'] === "dns") {
            document.getElementById("dnsSection").style.display = "block";
        } else if (layout[source]['target'] === "own") {
            document.getElementById("ownSection").style.display = "block";
        } else if (layout[source]['target'] === "scan") {
            document.getElementById("scanSection").style.display = "block";
        }

        if (source === "network_graph") {
            display_graph_link(results);
        } else {
            addCountBox(source, results);
        }
        if (source === "ct" || source === "censys_certs" || source === "scan_certs") {
            display_cert_graph_link(results);
        }
    }
}

function fetch_request(source, zone, count) {
    var url = new URI(api_map[source]);
    var query = {};
    switch (source) {
        case 'network_graph':
            url.segment(zone);
            break;
        case 'iblox_owners':
            query = {
                'type': 'zone',
                'value': zone
            };
            break;
        default:
            query = {
                'zone': zone
            };
    }
    if (count) {
        query = $.extend({}, query, { 'count': 1 });
    }

    if (source === "dns_spf") {
        query = $.extend({}, query, { 'txtSearch': 'spf' });
    } else if (source.substring(0, 4) === "dns_") {
        let dns_type = source.substring(4);
        query = $.extend({}, query, { 'dnsType': dns_type });
    } else if (source.substring(0, 15) === "scan_zone_port_") {
        let port = source.substring(15);
        query = $.extend({}, query, { 'port': port });
    }

    url = url.search(query).toString();

    make_get_request(url, display_response_count, source, "", { 'count': 0 });
}


function whois_lookup() {
    if (document.getElementById("search_input").value.length === 0) {
        document.getElementById("output").innerHTML = "No domain set.";
        return;
    }
    document.getElementById("errorMessage").innerHTML = "";
    dynamic_whois(document.getElementById("search_input").value, "output");
}
