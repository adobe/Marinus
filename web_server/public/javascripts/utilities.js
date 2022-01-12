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


/*
 * This Javascript file is loaded into all pages and contains common functions.
 */

var api_map = {
    'all_dns': '/api/v1.0/dns',
    'config': '/api/v1.0/admin/config',
    'censys_ips': '/api/v1.0/censys/ips',
    'censys_ports': '/api/v1.0/censys/ports',
    'censys_certs': '/api/v1.0/censys/certs',
    'censys_algorithm': '/api/v1.0/censys/algorithm/SHA1WithRSA',
    'ct': '/api/v1.0/ct/zone',
    'dns_mx': '/api/v1.0/dns',
    'dns_spf': '/api/v1.0/dns',
    'dns_soa': '/api/v1.0/dns',
    'dns_a': '/api/v1.0/dns',
    'dns_aaaa': '/api/v1.0/dns',
    'dns_txt': '/api/v1.0/dns',
    'dns_cname': '/api/v1.0/dns',
    'dns_srv': '/api/v1.0/dns',
    'iblox_owners': '/api/v1.0/iblox/owners',
    'network_graph': '/api/v1.0/graphs/',
    'scan_certs': '/api/v1.0/zgrab/443/certs',
    'scan_algorithm': '/api/v1.0/zgrab/443/algorithm/SHA1WithRSA',
    'scan_zone_port_22': '/api/v1.0/zgrab/zone',
    'scan_zone_port_25': '/api/v1.0/zgrab/zone',
    'scan_zone_port_80': '/api/v1.0/zgrab/zone',
    'scan_zone_port_443': '/api/v1.0/zgrab/zone',
    'scan_zone_port_465': '/api/v1.0/zgrab/zone',
    'sonar_rdns': '/api/v1.0/sonar/rdns',
    'vt_meta': '/api/v1.0/virustotal/domainMetaReport',
    'vt_ips': '/api/v1.0/virustotal/domainIPs',
    'vt_domains': '/api/v1.0/virustotal/domainSubdomains',
    'whois_db': '/api/v1.0/whois_db',
    'zones': '/api/v1.0/zones/zone/',
    'zgrab_root': '/api/v1.0/zgrab/'
};

function qs(key) {
    key = key.replace(/[*+?^$.\[\]{}()|\\\/]/g, "\\$&"); // escape RegEx meta chars
    var match = location.search.match(new RegExp("[?&]" + key + "=([^&]+)(&|$)"));
    return match && decodeURIComponent(match[1].replace(/\+/g, " "));
}


/**
 * ZGrab 2.0 and ZGrab have different schemas.
 * This is a convenience function to handle both conditions for full scans.
 */
function get_tls_log(results, index) {
    let tls_log;

    try {
        if (results[index]['data']['http'].hasOwnProperty('result')) {
            // ZGrab 2.0
            tls_log = results[index]['data']['http']['result']['response']['request']['tls_log']['handshake_log'];
        } else {
            // ZGrab
            tls_log = results[index]['data']['http']['response']['request']['tls_handshake'];
        }
    } catch (error) {
        tls_log = {};
    }

    return tls_log;
}

/**
 * ZGrab 2.0 and ZGrab have different schemas.
 * This is a convenience function to handle both conditions for HTTPS port scans.
 */
function get_port_tls_log(results, index) {
    let tls_log;

    try {
        if (results[index]['data']['tls'].hasOwnProperty('result')) {
            // ZGrab 2.0
            tls_log = results[index]['data']['tls']['result']['handshake_log'];
        } else {
            // ZGrab
            tls_log = rresults[index]['data']['tls']['tls_handshake'];
        }
    } catch (error) {
        tls_log = {};
    }

    return tls_log;
}


/**
 * Networking requests
 */

function make_get_request(url, return_function, additionalArgs = null, errorLocation = "errorMessage", defaultReturn = null) {
    var xhr = new XMLHttpRequest();
    xhr.addEventListener("error", errorHandler);
    xhr.onreadystatechange = function () {
        if (xhr.readyState === 4 && xhr.status === 200) {
            let data;
            try {
                data = JSON.parse(xhr.responseText);
            } catch (err) {
                if (errorLocation !== "") {
                    document.getElementById(errorLocation).innerHTML = "<b>Error: Bad JSON! " + err.message + "</b>";
                }
                return;
            }

            if (additionalArgs != null) {
                return_function(data, additionalArgs);
            } else {
                return_function(data);
            }
        } else if (xhr.status === 404 && defaultReturn != null) {
            if (additionalArgs != null) {
                return_function(defaultReturn, additionalArgs);
            } else {
                return_function(defaultReturn);
            }
        } else if (xhr.status === 500 || xhr.status === 400) {
            if (errorLocation !== "") {
                document.getElementById(errorLocation).innerHTML = xhr.responseText;
            }
        }
    };
    xhr.open("GET", url);
    xhr.send();
    return (false);
}

function dynamicWhoisResult(result, output) {
    var whoisWell = document.getElementById(output);
    var parsed = result['result'].replace(/\\n/g, "<br/>");
    parsed = parsed.replace(/\\r/g, "");
    whoisWell.innerHTML = parsed;
}

function dynamic_whois(range, output) {
    var url = "/api/v1.0/utilities/whois";
    var query = "?domain=" + range;

    make_get_request(url + query, dynamicWhoisResult, output, "dynamic_whois");
}

/**
 * Rendering functions
 */

function errorHandler(message = "<b>Error: An error occurred during transfer</b>") {
    document.getElementById('errorMessage').innerHTML = message;
}

function clearErrorHandler() {
    document.getElementById('errorMessage').innerHTML = "";
}

function create_h3(visible_text) {
    return ("<h4>" + visible_text + "</h4>");
}

function create_new_div(id, divClass = "") {
    let displayHTML = '<div id="' + id + '"';
    if (divClass !== "") {
        displayHTML += ' class="' + divClass + '"';
    }
    displayHTML += '>'
    return (displayHTML);
}

function create_new_div_section(column_name, visible_text) {
    let output_text = create_h3(visible_text);
    output_text = output_text + create_new_div(column_name + "_list");
    return (output_text);
}

function create_new_list(list_id) {
    return ('<div class="list-group">');
}

function create_list_entry(row_name, visible_text, href, include_count = false, icon_name = 'chevronRight', target_location = "") {
    let target_code = "";
    if (target_location !== "") {
        target_code = ' target="' + target_location + '" ';
    }

    let output_image = "";
    if (icon_name === "chevronRight") {
        output_image = '<img src="/stylesheets/octicons/svg/chevron-right.svg" alt="entry"/>&nbsp;';
    } else if (icon_name === "lockOn") {
        output_image = '<img src="/stylesheets/octicons/svg/lock.svg" alt="lock"/>&nbsp;';
    }
    let output_text = '<a class="list-group-item list-group-item-action" id="' + row_name + '_link" href="' + href + '"' + target_code + '>';
    output_text = output_text + output_image + visible_text;
    if (include_count) {
        output_text = output_text + '<span id="' + row_name + '_count"></span>';
    }
    output_text = output_text + '</a>';
    return (output_text);
}

function end_list() {
    return ('</div>');
}

function end_div() {
    return ('</div>');
}

function create_anchor(url, text, target = "", id = "") {
    let output_text = '<a';
    if (url !== "") {
        output_text += ' href="' + url + '"';
    }
    if (target !== "") {
        output_text += ' target="' + target + '"';
    }
    if (id !== "") {
        output_text += ' id="' + id + '"';
    }
    output_text += '>' + text + '</a>';
    return (output_text);
}

function create_new_table(class_string = "") {
    let output_text = '<table class="table';
    if (class_string !== "") {
        output_text += ' ' + class_string;
    }
    output_text += '">';
    return (output_text);
}

function create_table_head(names, class_string = "") {
    let output_text = '<thead';
    if (class_string !== "") {
        output_text += ' class=' + class_string + '"';
    }
    output_text += '>';
    output_text += '<tr>';
    for (let entry in names) {
        output_text += '<th>' + names[entry] + '</th>';
    }
    output_text += '</tr></thead>';
    return (output_text);
}

function create_table_body(class_string = "") {
    let output_text = '<tbody';
    if (class_string !== "") {
        output_text += ' class="' + class_string + '"';
    }
    output_text += '>';
    return (output_text);
}

function create_table_row() {
    return ('<tr>');
}

function create_table_entry(value, id = "", tdClass = "") {
    let output_text = '<td';
    if (tdClass !== "") {
        output_text += ' class="' + tdClass + '"';
    }

    if (id !== "") {
        output_text += ' id="' + id + '"';
    }
    output_text += '>' + value + '</td>';
    return (output_text);
}

function end_table_row() {
    return ("</tr>");
}

function end_table() {
    return ('</tbody></table>');
}

function create_check_mark() {
    return ('<img src="/stylesheets/octicons/svg/check.svg" alt="check"/>');
}

function create_button(visible_text, button_id, button_type = "icon", size = "S", icon = "search") {

    let settings = { "label": { "innerHTML": visible_text } };

    if (button_type === "icon" && icon === "search") {
        visible_text = visible_text + '&nbsp;<img src="/stylesheets/octicons/svg/search.svg" alt="search"/>';
    }

    var newButton = document.createElement("button");
    newButton.className = "btn btn-primary btn-lg";
    newButton.innerHTML = visible_text;
    newButton.id = button_id;

    return (newButton);
}

function add_click_event_listeners(row_name, row_type, row_function) {
    let object_handle = row_name + '_' + row_type;
    let elem = document.getElementById(object_handle);
    if (elem != null) {
        elem.addEventListener("click", row_function);
    }
}


/**
 * Paging code
 */

var LIMIT = 1000;
var PAGE = 1;
var PAGING_FUNCTIONS = {};
var PAGING_URLS = {};
var PAGING_CLICK_WAIT = false;

function kill_paging_form(formName) {
    document.getElementById('pagingForm-' + formName).onsubmit = function () {
        return false;
    };
}

function add_paging_html(formName, display_function) {
    let html = '<div>';
    html += '<form id="pagingForm-' + formName + '">';
    html += '<nav aria-label="Page navigation">';
    html += '<ul class="pagination">';
    html += '<li class="page-item"><label for="pageLimit-' + formName + '" id="label-aligned-0">Results per page:&nbsp;</label></li>';
    html += '<li class="page-item"><input type="number" style="width:100px;" value="' + LIMIT.toString() + '" step="100" name="pageLimit-' + formName + '" id="pageLimit-' + formName + '" min="100" max="1000"></input>&nbsp;</li>';
    html += '<li class="page-item">';
    html += '<a class="page-link" href="#" aria-label="Previous" id="prevPage-' + formName + '">';
    html += '<span aria-hidden="true">&laquo;</span>';
    html += '<span class="sr-only">Previous</span>';
    html += '</a></li>';
    html += '<li class="page-item">';
    html += '<a class="page-link" href="#" aria-label="Next" id="nextPage-' + formName + '">';
    html += '<span aria-hidden="true">&raquo;</span>';
    html += '<span class="sr-only">Next</span>';
    html += '</a></li></ul></nav>';
    html += '</form>';
    html += '</div>';


    PAGING_FUNCTIONS[formName] = display_function;

    window.setTimeout(function () { kill_paging_form(formName) }, 1000);

    return (html);
}

function do_page_refresh(formName) {
    LIMIT = document.getElementById("pageLimit-" + formName).value;
    PAGE = 1;
    PAGING_CLICK_WAIT = false;
    make_get_request(PAGING_URLS[formName] + "limit=" + LIMIT.toString() + "&page=1", PAGING_FUNCTIONS[formName]);
}

function update_limit(formName) {
    if (PAGING_CLICK_WAIT === false) {
        PAGING_CLICK_WAIT = true;
        window.setTimeout(function () { do_page_refresh(formName) }, 2000);
    }
    return false;
}

function refresh(url, base_query, formName) {
    if (base_query !== "") {
        PAGING_URLS[formName] = url + "&";
        base_query = base_query + "&limit=" + LIMIT.toString() + "&page=" + PAGE.toString();
    } else {
        PAGING_URLS[formName] = url + "?";
        base_query = "?limit=" + LIMIT.toString() + "&page=" + PAGE.toString();
    }

    make_get_request(url + base_query, PAGING_FUNCTIONS[formName]);
}


function page_back(url, base_query, formName) {
    if (PAGING_CLICK_WAIT) {
        return false;
    }

    PAGE = PAGE - 1;
    if (PAGE < 1) {
        PAGE = 1;
    }
    refresh(url, base_query, formName);
}


function page_forward(url, base_query, formName) {
    if (PAGING_CLICK_WAIT) {
        return false;
    }

    PAGE = PAGE + 1;
    refresh(url, base_query, formName);
}
