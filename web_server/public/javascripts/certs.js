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

window.addEventListener("load", buildPage);

var IssuerList = {};
var toggleState = false;
var certSource = "zgrab";
var recursiveResponse = false;
var current_ca_name = "";

function buildPage() {
    var path = window.location.pathname;
    certSource = qs("source");
    if (certSource == null) {
        certSource = "zgrab";
    }

    recursiveResponse = qs("recursive");
    if (recursiveResponse == null) {
        recursiveResponse = true;
    }

    if (path === "/reports/ct_corp_ssl") {
        document.getElementById("excludeExpired").addEventListener("change", reload_corp_certs);
        fetch_ct_corp_certs(toggleState);
    } else if (path === "/reports/scan_corp_certs") {
        fetch_corp_certs();
    } else if (path === "/reports/scan_expired_ssl") {
        fetch_expired_certs_2k();
        fetch_expired_certs();
    } else if (path === "/reports/scan_algorithm_ssl") {
        fetch_algorithm_certs();
    } else if (path === "/reports/display_cert") {
        fetch_certificate();
    } else if (path === "/reports/ct_issuers") {
        fetch_issuer_list();
    } else if (path === "/reports/hosts_by_cas") {
        fetch_scan_ca_list();
    }
}

function display_ct_corp_certs(results) {
    if (results.length === 0) {
        document.getElementById("ct_corp_certs").innerHTML = "<b>N/A</b><br/>";
        return;
    }
    var displayHTML = create_new_table();
    displayHTML += create_table_head(["CertID", "Common Names", "isSelfSigned", "isExpired"]);
    displayHTML += create_table_body();

    for (var i = 0; i < results.length; i++) {
        displayHTML += create_table_row();
        displayHTML += create_table_entry(create_anchor("/reports/display_cert?id=" + results[i]['_id'], results[i]['_id'], "_blank"));

        var cns = results[i]['subject_common_names'];
        var dns = results[i]['subject_dns_names'];
        displayHTML += '<td class="td-word-wrap">';
        var j = 0;
        for (j = 0; j < cns.length; j++) {
            displayHTML += cns[j] + ", ";
        }
        for (j = 0; j < dns.length; j++) {
            displayHTML += dns[j] + ", ";
        }

        displayHTML += '</td>';

        if (results[i]['isSelfSigned']) {
            displayHTML += create_table_entry(create_check_mark());
        } else {
            displayHTML += create_table_entry("");
        }

        if (results[i]['isExpired']) {
            displayHTML += create_table_entry(create_check_mark());
        } else {
            displayHTML += create_table_entry("");
        }

        displayHTML += end_table_row();
    }

    displayHTML += end_table();

    document.getElementById("ct_corp_certs").innerHTML = displayHTML;
}

function reload_corp_certs(ev) {
    toggleState = !toggleState;
    document.getElementById("ct_corp_certs").innerHTML = '<img src="/stylesheets/octicons/svg/gear.svg" class="rotateAnimation" alt="timer"/>';
    fetch_ct_corp_certs(toggleState);
}

function fetch_ct_corp_certs(excludeExpired) {
    var url = "/api/v1.0/ct/corp_certs";
    let query;
    if (excludeExpired === true) {
        query = "?exclude_expired=1"
    } else {
        query = "";
    }

    make_get_request(url + query, display_ct_corp_certs, null, "ct_corp_certs");
}


function display_corp_certs(results) {
    if (results.length === 0) {
        document.getElementById("scan_corp_certs").innerHTML = "<b>N/A</b><br/>";
        return;
    }
    var displayHTML = create_new_table();
    displayHTML += create_table_head(["IP", "Common Names", "isSelfSigned", "Valid"]);
    displayHTML += create_table_body();

    for (var i = 0; i < results.length; i++) {
        displayHTML += create_table_row();
        displayHTML += create_table_entry(create_anchor("/ip?search=" + results[i]['ip'], results[i]['ip']));

        let cns, dns;

        // Not necessary for Censys but it will fail gracefully
        let tls_log = get_port_tls_log(results, i);

        if (certSource === "censys") {
            cns = results[i]['p443']['https']['tls']['certificate']['parsed']['subject']['common_name'];
            dns = results[i]['p443']['https']['tls']['certificate']['parsed']['extensions']['subject_alt_name']['dns_names'];
        } else {
            cns = tls_log['server_certificates']['certificate']['parsed']['subject']['common_name'];
            dns = tls_log['server_certificates']['certificate']['parsed']['extensions']['subject_alt_name']['dns_names'];
        }

        displayHTML += '<td class="td-word-wrap">';

        var j = 0;
        for (j = 0; j < cns.length; j++) {
            displayHTML += cns[j] + ", ";
        }
        for (j = 0; j < dns.length; j++) {
            displayHTML += dns[j] + ", ";
        }

        displayHTML += '</td>';

        let self_signed;
        if (certSource === "censys") {
            self_signed = results[i]['p443']['https']['tls']['certificate']['parsed']['signature']['self_signed'];
        } else {
            self_signed = tls_log['server_certificates']['certificate']['parsed']['signature']['self_signed'];
        }
        if (self_signed) {
            displayHTML += create_table_entry(create_check_mark());
        } else {
            displayHTML += create_table_entry("");
        }

        let valid;
        if (certSource === "censys") {
            valid = results[i]['p443']['https']['tls']['certificate']['parsed']['signature']['valid'];
        } else {
            valid = tls_log['server_certificates']['certificate']['parsed']['signature']['valid'];
        }
        if (valid) {
            displayHTML += create_table_entry(create_check_mark());
        } else {
            displayHTML += create_table_entry("");
        }

        displayHTML += end_table_row();
    }

    displayHTML += end_table();

    document.getElementById("scan_corp_certs").innerHTML = displayHTML;
}


function fetch_corp_certs(exclude_expired = false) {
    let url, query;
    if (certSource === "censys") {
        url = "/api/v1.0/censys/corp_certs";
        query = "";
    } else {
        url = "/api/v1.0/zgrab/443/corp_certs";
        query = "";
    }

    make_get_request(url + query, display_corp_certs, null, "scan_corp_certs");
}

function display_expired_certs(results, year) {
    if (results.length === 0) {
        document.getElementById("scan_expired_certs").innerHTML = '<b>Displaying results for ' + year + '</b><br/><b>N/A</b><br/>';
        return;
    }

    var end;
    if (certSource === "censys") {
        end = results[0]['p443']['https']['tls']['certificate']['parsed']['validity']['end'];
    } else {
        if (results[0]['data']['http']['response']['request'].hasOwnProperty('tls_log')) {
            end = results[0]['data']['http']['response']['request']['tls_log']['handshake_log']['server_certificates']['certificate']['parsed']['validity']['end'];
        } else {
            end = results[0]['data']['http']['response']['request']['tls_handshake']['server_certificates']['certificate']['parsed']['validity']['end'];
        }
    }

    var today = new Date();
    var this_year = today.getFullYear().toString();
    var displayYear = "";
    var parts = end.split("-");
    if (end.startsWith(this_year)) {
        displayYear = parts[0] + "-" + parts[1];
    } else {
        displayYear = parts[0];
    }
    var yearDiv = document.getElementById(displayYear);

    var displayHTML = '<b>Displaying results for ' + year + '</b><br/>';
    displayHTML += create_new_table();
    displayHTML += create_table_head(["Host", "Common Names", "Expiration", "Self Signed"]);
    displayHTML += create_table_body();

    for (var i = 0; i < results.length; i++) {
        displayHTML += create_table_row();

        let cns, dns;
        if (certSource === "censys") {
            displayHTML += create_table_entry(create_anchor("/ip?search=" + results[i]['ip'], results[i]['ip']));
            cns = results[i]['p443']['https']['tls']['certificate']['parsed']['subject']['common_name'];
            dns = results[i]['p443']['https']['tls']['certificate']['parsed']['extensions']['subject_alt_name']['dns_names'];
        } else {
            if (results[i]['ip'] === "<nil>") {
                displayHTML += create_table_entry(create_anchor("/domain?search=" + results[i]['domain'], results[i]['domain']));
            } else {
                displayHTML += create_table_entry(create_anchor("/ip?search=" + results[i]['ip'], results[i]['ip']));
            }

            try {
                if (results[i]['data']['http']['response']['request'].hasOwnProperty('tls_log')) {
                    cns = results[i]['data']['http']['response']['request']['tls_log']['handshake_log']['server_certificates']['certificate']['parsed']['subject']['common_name'];
                } else {
                    cns = results[i]['data']['http']['response']['request']['tls_handshake']['server_certificates']['certificate']['parsed']['subject']['common_name'];
                }
            } catch (error) {
                cns = [];
            }
            try {
                if (results[i]['data']['http']['response']['request'].hasOwnProperty('tls_log')) {
                    dns = results[i]['data']['http']['response']['request']['tls_log']['handshake_log']['server_certificates']['certificate']['parsed']['extensions']['subject_alt_name']['dns_names'];
                } else {
                    dns = results[i]['data']['http']['response']['request']['tls_handshake']['server_certificates']['certificate']['parsed']['extensions']['subject_alt_name']['dns_names'];
                }
            } catch (error) {
                dns = [];
            }
        }
        displayHTML += '<td class="td-word-wrap">';

        if (cns === undefined) { cns = []; }
        if (dns === undefined) { dns = []; }

        var j = 0;
        for (j = 0; j < cns.length; j++) {
            displayHTML += cns[j] + ", ";
        }
        for (j = 0; j < dns.length; j++) {
            displayHTML += dns[j] + ", ";
        }

        displayHTML += '</td>';

        if (certSource === "censys") {
            displayHTML += create_table_entry(results[i]['p443']['https']['tls']['certificate']['parsed']['validity']['end']);
            if (results[i]['p443']['https']['tls']['certificate']['parsed']['signature']['self_signed']) {
                displayHTML += create_table_entry(create_check_mark());
            } else {
                displayHTML += create_table_entry("");
            }
        } else {
            let zgrab_self_signed = false;
            let end;

            if (results[i]['data']['http']['response']['request'].hasOwnProperty('tls_log')) {
                zgrab_self_signed = results[i]['data']['http']['response']['request']['tls_log']['handshake_log']['server_certificates']['certificate']['parsed']['signature']['self_signed'];
                end = results[i]['data']['http']['response']['request']['tls_log']['handshake_log']['server_certificates']['certificate']['parsed']['validity']['end'];
            } else {
                zgrab_self_signed = results[i]['data']['http']['response']['request']['tls_handshake']['server_certificates']['certificate']['parsed']['signature']['self_signed'];
                end = results[i]['data']['http']['response']['request']['tls_handshake']['server_certificates']['certificate']['parsed']['validity']['end'];
            }

            displayHTML += create_table_entry(end);
            if (zgrab_self_signed) {
                displayHTML += create_table_entry(create_check_mark());
            } else {
                displayHTML += create_table_entry("");
            }
        }

        displayHTML += end_table_row();
    }

    displayHTML += end_table() + "<br/>";

    yearDiv.innerHTML = displayHTML;
}

function fetch_expired_certs() {
    var today = new Date();
    for (let i = 2010; i < today.getFullYear(); i++) {
        let newDiv = document.createElement("div");
        newDiv.id = i.toString();
        document.getElementById("scan_expired_certs").appendChild(newDiv);
        fetch_expired_certs_by_year(i.toString());
    }

    var this_year = today.getFullYear().toString();

    for (let i = 1; i < today.getMonth() + 1; i++) {
        var year_month = "";
        if (i.toString().length === 1) {
            year_month = this_year + "-0" + i.toString();
        } else {
            year_month = this_year + "-" + i.toString();
        }

        let newDiv = document.createElement("div");
        newDiv.id = year_month;
        document.getElementById("scan_expired_certs").appendChild(newDiv);
        fetch_expired_certs_by_year(year_month);
    }
}

function fetch_expired_certs_by_year(year) {
    var url;
    if (certSource === "censys") {
        url = "/api/v1.0/censys/expired_certs_by_year";
    } else {
        url = "/api/v1.0/zgrab/443/expired_certs_by_year";
    }
    var query = "?year=" + year;

    make_get_request(url + query, display_expired_certs, year, "scan_expired_certs");
}

function display_expired_certs_2k(results) {
    if (results.length === 0) {
        document.getElementById("scan_expired_certs_2k").innerHTML = '<b>N/A</b><br/>';
        return;
    }

    var displayHTML = create_new_table();
    displayHTML += create_table_head(["Host", "Common Names", "Expiration", "Self Signed"]);
    displayHTML += create_table_body();

    for (var i = 0; i < results.length; i++) {
        displayHTML += create_table_row();
        let cns, dns;
        let tls_log;
        if (certSource === "censys") {
            displayHTML += create_table_entry(create_anchor("/ip?search=" + results[i]['ip'], results[i]['ip']));
            cns = results[i]['p443']['https']['tls']['certificate']['parsed']['subject']['common_name'];
            dns = results[i]['p443']['https']['tls']['certificate']['parsed']['extensions']['subject_alt_name']['dns_names'];
        } else {
            if (results[i]['ip'] === "<nil>") {
                displayHTML += create_table_entry(create_anchor("/domain?search=" + results[i]['domain'], results[i]['domain']));
            } else {
                displayHTML += create_table_entry(create_anchor("/ip?search=" + results[i]['ip'], results[i]['ip']));
            }

            try {
                if (results[i]['data']['http']['response']['request'].hasOwnProperty('tls_log')) {
                    cns = results[i]['data']['http']['response']['request']['tls_log']['handshake_log']['server_certificates']['certificate']['parsed']['subject']['common_name'];
                } else {
                    cns = results[i]['data']['http']['response']['request']['tls_handshake']['server_certificates']['certificate']['parsed']['subject']['common_name'];
                }
            } catch (error) {
                cns = [];
            }
            try {
                if (results[i]['data']['http']['response']['request'].hasOwnProperty('tls_log')) {
                    dns = results[i]['data']['http']['response']['request']['tls_log']['handshake_log']['server_certificates']['certificate']['parsed']['extensions']['subject_alt_name']['dns_names'];
                } else {
                    dns = results[i]['data']['http']['response']['request']['tls_handshake']['server_certificates']['certificate']['parsed']['extensions']['subject_alt_name']['dns_names'];
                }
            } catch (error) {
                dns = "";
            }
        }

        displayHTML += '<td class="td-word-wrap">';

        if (cns === undefined) { cns = []; }
        if (dns === undefined) { dns = []; }

        var j = 0;
        for (j = 0; j < cns.length; j++) {
            displayHTML += cns[j] + ", ";
        }
        for (j = 0; j < dns.length; j++) {
            displayHTML += dns[j] + ", ";
        }

        displayHTML += '</td>';

        if (certSource === "censys") {
            displayHTML += create_table_entry(results[i]['p443']['https']['tls']['certificate']['parsed']['validity']['end']);
        } else {
            if (results[i]['data']['http']['response']['request'].hasOwnProperty('tls_log')) {
                displayHTML += create_table_entry(results[i]['data']['http']['response']['request']['tls_log']['handshake_log']['server_certificates']['certificate']['parsed']['validity']['end']);
            } else {
                displayHTML += create_table_entry(results[i]['data']['http']['response']['request']['tls_handshake']['server_certificates']['certificate']['parsed']['validity']['end']);
            }
        }

        let zgrab_self_signed = false;
        if (certSource == "zgrab") {
            if (results[i]['data']['http']['response']['request'].hasOwnProperty('tls_log')) {
                zgrab_self_signed = results[i]['data']['http']['response']['request']['tls_log']['handshake_log']['server_certificates']['certificate']['parsed']['signature']['self_signed'];
            } else {
                zgrab_self_signed = results[i]['data']['http']['response']['request']['tls_handshake']['server_certificates']['certificate']['parsed']['signature']['self_signed'];
            }
        }

        if ((certSource === "censys" && results[i]['p443']['https']['tls']['certificate']['parsed']['signature']['self_signed'])
            || (certSource === "zgrab" && zgrab_self_signed)) {
            displayHTML += create_table_entry(create_check_mark());
        } else {
            displayHTML += create_table_entry("");
        }

        displayHTML += end_table_row();
    }

    displayHTML += end_table();

    document.getElementById("scan_expired_certs_2k").innerHTML = displayHTML;
}


function fetch_expired_certs_2k() {
    var url;
    if (certSource === "censys") {
        url = "/api/v1.0/censys/expired_certs_2k";
    } else {
        url = "/api/v1.0/zgrab/443/expired_certs_2k";
    }
    var query = "";

    make_get_request(url + query, display_expired_certs_2k);
}

function display_algorithm_certs(results) {
    if (results.length === 0) {
        document.getElementById("scan_algorithm_certs").innerHTML = '<b>N/A</b><br/>';
        return;
    }
    var displayHTML = create_new_table();
    displayHTML += create_table_head(["Host", "Common Names", "Algorithm", "Expires", "Fingerprint"]);
    displayHTML += create_table_body();

    for (var i = 0; i < results.length; i++) {
        displayHTML += create_table_row();
        let cns = [];
        let dns = [];
        if (certSource === "censys") {
            displayHTML += create_table_entry(create_anchor("/ip?search=" + results[i]['ip'], results[i]['ip']));
            cns = results[i]['p443']['https']['tls']['certificate']['parsed']['subject']['common_name'];
            dns = results[i]['p443']['https']['tls']['certificate']['parsed']['extensions']['subject_alt_name']['dns_names'];
        } else {
            if (results[i]['ip'] === "<nil>") {
                displayHTML += create_table_entry(create_anchor("/domain?search=" + results[i]['domain'], results[i]['domain']));
            } else {
                displayHTML += create_table_entry(create_anchor("/ip?search=" + results[i]['ip'], results[i]['ip']));
            }
            let tls_log = get_tls_log(results, i);
            try {
                cns = tls_log['server_certificates']['certificate']['parsed']['subject']['common_name'];
            } catch (error) {
                cns = [];
            }
            try {
                dns = tls_log['server_certificates']['certificate']['parsed']['extensions']['subject_alt_name']['dns_names'];
            } catch (error) {
                dns = [];
            }
        }

        displayHTML += '<td class="td-word-wrap">';
        var j = 0;

        if (cns === undefined) { cns = []; }
        if (dns === undefined) { dns = []; }

        for (j = 0; j < cns.length; j++) {
            displayHTML += cns[j] + ", ";
        }
        for (j = 0; j < dns.length; j++) {
            displayHTML += dns[j] + ", ";
        }

        displayHTML += '</td>';

        if (certSource === "censys") {
            displayHTML += create_table_entry(results[i]['p443']['https']['tls']['certificate']['parsed']['signature']['signature_algorithm']['name']);
            displayHTML += create_table_entry(results[i]['p443']['https']['tls']['certificate']['parsed']['validity']['end']);
            displayHTML += create_table_entry(create_anchor("/reports/display_cert?type=censys_sha1&sha1=" + results[i]['p443']['https']['tls']['certificate']['parsed']['fingerprint_sha1'], results[i]['p443']['https']['tls']['certificate']['parsed']['fingerprint_sha1'], "_blank"));
        } else {
            let tls_log = get_tls_log(results, i);
            displayHTML += create_table_entry(tls_log['server_certificates']['certificate']['parsed']['signature']['signature_algorithm']['name']);
            displayHTML += create_table_entry(tls_log['server_certificates']['certificate']['parsed']['validity']['end']);
            displayHTML += create_table_entry(create_anchor("/reports/display_cert?type=zgrab_sha1&sha1=" + tls_log['server_certificates']['certificate']['parsed']['fingerprint_sha1'], tls_log['server_certificates']['certificate']['parsed']['fingerprint_sha1'], "_blank"));
        }
        displayHTML += end_table_row();
    }

    displayHTML += end_table();

    document.getElementById("scan_algorithm_certs").innerHTML = displayHTML;
}

function fetch_algorithm_certs(algorithm = 'SHA1WithRSA') {
    var url;
    if (certSource === "censys") {
        url = "/api/v1.0/censys/algorithm/" + algorithm;
    } else {
        url = "/api/v1.0/zgrab/443/algorithm/" + algorithm;
    }

    make_get_request(url, display_algorithm_certs, null, "scan_algorithm_certs");
}

function display_certificate(results, req_type) {
    var displayHTML = "";
    if (req_type === "ct_id" || req_type === "ct_sha1" || req_type === "ct_sha256") {
        displayHTML = '<a href="/api/v1.0/ct/download/' + results['_id'] + '">Click to download the DER file</a><br/>';
        displayHTML += '<div class="bg-light"><pre>' + results['full_certificate'] + "</pre></div><br/>";
    } else if (req_type === "censys_sha1" || req_type === "censys_sha256") {
        let cert_string = JSON.stringify(results[0]['p443']['https']['tls']['certificate']['parsed'], null, 2);
        displayHTML += '<div class="bg-light"><pre>' + cert_string + "</pre></div><br/>";
    } else {
        let tls_log;
        if (results[0]['data']['http']['response']['request'].hasOwnProperty('tls_log')) {
            // ZGrab 2.0
            tls_log = results[0]['data']['http']['response']['request']['tls_log']['handshake_log'];
        } else {
            // ZGrab
            tls_log = results[0]['data']['http']['response']['request']['tls_handshake'];
        }
        let cert_string = JSON.stringify(tls_log['server_certificates']['certificate']['parsed'], null, 2);
        displayHTML += '<div class="bg-light"><pre>' + cert_string + "</pre></div><br/>";
    }

    document.getElementById("cert_info").innerHTML = displayHTML;
}

function fetch_certificate() {
    var id = qs("id");
    var sha1 = qs("sha1");
    var sha256 = qs("sha256");
    var req_type = ""
    var url = "";
    if (id) {
        url = "/api/v1.0/ct/id/" + id;
        req_type = "ct_id";
    } else if (sha1) {
        let rec_type = qs("type");
        if (rec_type === "ct_sha1") {
            url = "/api/v1.0/ct/fingerprint/" + sha1;
            req_type = "ct_sha1";
        } else if (rec_type === "censys_sha1") {
            url = "/api/v1.0/censys/certs?fingerprint_sha1=" + sha1;
            req_type = "censys_sha1";
        } else {
            url = "/api/v1.0/zgrab/443/certs?fingerprint_sha1=" + sha1;
            req_type = "zgrab_sha1";
        }
    } else if (sha256) {
        let rec_type = qs("type");
        if (rec_type === "ct_sha256") {
            url = "/api/v1.0/ct/fingerprint/" + sha256;
            req_type = "ct_sha256";
        } else if (rec_type === "censys_sha1") {
            url = "/api/v1.0/censys/certs?fingerprint_sha256=" + sha256;
            req_type = "censys_sha256";
        } else {
            url = "/api/v1.0/zgrab/443/certs?fingerprint_sha256=" + sha256;
            req_type = "zgrab_sha256";
        }
    }

    if (url === "") {
        document.getElementById("cert_info").innerHTML = "<b>No ID was provided!</b>";
    }

    make_get_request(url, display_certificate, req_type, "cert_info");
}

function display_issuers(results, name) {
    var displayHTML = create_new_list("issuers");

    for (let result in results) {
        displayHTML += create_list_entry("", results[result]['subject_common_names'].toString(), "/reports/display_cert?id=" + results[result]['_id'], false, "lockOn", "_blank");
    }

    displayHTML += end_list();

    document.getElementById("tableTitle").innerHTML = name;
    document.getElementById("report_details").innerHTML = displayHTML;
}


function fetch_issuer(name, count) {
    var url = "/api/v1.0/ct/issuers/" + name;
    var query = "";
    if (count) {
        query += "?count=1";
    }

    var xhr = new XMLHttpRequest();
    xhr.addEventListener("error", errorHandler);
    xhr.onreadystatechange = function () {
        if (xhr.readyState === 4 && xhr.status === 200) {
            try {
                var myObj = JSON.parse(xhr.responseText);
            } catch (err) {
                document.getElementById('cert_info').innerHTML = "<b>Error: Bad JSON! " + err.message + "</b>";
                return;
            }
            if (count) {
                var safeName = name.replace(/ /g, "");
                document.getElementById(safeName + "_count").innerHTML = myObj['count'];
            } else {
                display_issuers(myObj, name);
            }
        } else if (xhr.status === 500 || xhr.status === 400) {
            document.getElementById('cert_info').innerHTML = xhr.responseText;
        }
    };

    xhr.open("GET", url + query);
    xhr.send();
    return (false);
}

function fetch_CA_details() {
    var caName = IssuerList[this.id.replace("_link", "")];
    fetch_issuer(caName, false);
}

function display_issuer_list(results) {
    var displayHTML = create_new_list("issuerList");
    for (let result in results) {
        var safeName = results[result].replace(/ /g, "");
        IssuerList[safeName] = results[result];
        displayHTML += create_list_entry(safeName, results[result] + ": ", "#", true, "lockOn");
    }

    displayHTML += end_list();

    document.getElementById("summaryList").innerHTML = displayHTML;

    for (let name in IssuerList) {
        fetch_issuer(IssuerList[name], true);
        document.getElementById(name + "_link").addEventListener("click", fetch_CA_details);
    }
}


function fetch_issuer_list() {
    var url = "/api/v1.0/ct/issuers";
    make_get_request(url, display_issuer_list, null, "cert_info");
}


function display_scan_cas(results) {
    if (results.length >= LIMIT || PAGE > 1) {
        document.getElementById("tableTitle").innerHTML = "<b>" + current_ca_name + "</b><br/>" + add_paging_html("certs", display_scan_cas);
        document.getElementById("prevPage-certs").addEventListener("click", cert_page_back);
        document.getElementById("nextPage-certs").addEventListener("click", cert_page_forward);
        document.getElementById("pageLimit-certs").addEventListener("change", function () { update_limit("certs") });
    } else {
        document.getElementById("tableTitle").innerHTML = "<b>" + current_ca_name + "</b>";
    }

    let displayHTML = create_new_list("CASList");

    for (let result in results) {
        if (certSource === "censys") {
            displayHTML += '<a class="list-group-item list-group-item-action" href="/reports/display_cert?type=censys_sha1&sha1=' +
                results[result]['p443']['https']['tls']['certificate']['parsed']['fingerprint_sha1'] + '" target="_blank">' +
                results[result]['ip'].toString() + '-' + results[result]['p443']['https']['tls']['certificate']['parsed']['subject']['common_name'][0] + '</a>';
        } else {
            let tls_log;
            if ('tls_log' in results[result]['data']['http']['response']['request']) {
                tls_log = results[result]['data']['http']['response']['request']['tls_log']['handshake_log'];
            } else {
                tls_log = results[result]['data']['http']['response']['request']['tls_handshake'];
            }

            if (results[result]['ip'] === "<nil>") {
                displayHTML += '<a class="list-group-item list-group-item-action" href="/reports/display_cert?type=zgrab_sha1&sha1=' +
                    tls_log['server_certificates']['certificate']['parsed']['fingerprint_sha1'] +
                    '" target="_blank">' + results[result]['domain'].toString() + '-' + tls_log['server_certificates']['certificate']['parsed']['subject']['common_name'][0] + '</a>';
            } else {
                displayHTML += '<aclass="list-group-item list-group-item-action" href="/reports/display_cert?type=zgrab_sha1&sha1=' +
                    tls_log['server_certificates']['certificate']['parsed']['fingerprint_sha1'] +
                    '" target="_blank">' + results[result]['ip'].toString() + '-' + tls_log['server_certificates']['certificate']['parsed']['subject']['common_name'][0] + '</a>';
            }
        }
    }

    displayHTML += end_list();

    document.getElementById("report_details").innerHTML = displayHTML;
}

function cert_page_back(event) {
    var url;
    if (certSource === "censys") {
        url = "/api/v1.0/censys/cert_ca/" + current_ca_name;
    } else {
        url = api_map["zgrab_root"] + "443/cert_ca/" + current_ca_name;
    }
    let query = "";
    event.preventDefault();
    page_back(url, query, "certs");
}

function cert_page_forward(event) {
    var url;
    if (certSource === "censys") {
        url = "/api/v1.0/censys/cert_ca/" + current_ca_name;
    } else {
        url = api_map["zgrab_root"] + "443/cert_ca/" + current_ca_name;
    }
    let query = "";
    event.preventDefault();
    page_forward(url, query, "certs");
}

function fetch_scan_issuer(name) {
    var url;
    if (certSource === "censys") {
        url = "/api/v1.0/censys/cert_ca/" + name + "?";
    } else {
        url = api_map["zgrab_root"] + "443/cert_ca/" + name + "?";
    }
    var query = "limit=" + LIMIT.toString() + "&page=" + PAGE.toString();

    PAGING_URLS["certs"] = url;
    current_ca_name = name;

    make_get_request(url + query, display_scan_cas);
}

function fetch_scan_CA_details() {
    var caName = IssuerList[this.id.substring(0, this.id.length - 5)];
    fetch_scan_issuer(caName);
}

function display_scan_list(results) {
    let displayHTML = create_new_list("scanList");
    for (let result in results) {
        if (results[result]['_id'] != null) {
            let safeName = results[result]['_id'].replace(/ /g, "");
            IssuerList[safeName] = results[result]['_id'];
            displayHTML += create_list_entry(safeName, results[result]['_id'] + ": ", "#", true, "lockOn")
        }
    }

    displayHTML += end_list();

    document.getElementById("summaryList").innerHTML = displayHTML;

    for (let name in IssuerList) {
        document.getElementById(name + "_link").addEventListener("click", fetch_scan_CA_details);
    }

    for (let result in results) {
        if (results[result]['_id'] != null) {
            let safeName = results[result]['_id'].replace(/ /g, "");
            document.getElementById(safeName + "_count").innerHTML = results[result]['count'];
        }
    }
}

function fetch_scan_ca_list() {
    var url;
    if (certSource === "censys") {
        url = "/api/v1.0/censys/cert_ca";
    } else {
        url = "/api/v1.0/zgrab/443/cert_ca";
    }

    make_get_request(url, display_scan_list);
}
