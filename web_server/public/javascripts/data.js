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
  document.getElementById("censysSection").style.display = "none";
  document.getElementById("scanSection").style.display = "none";

  /* Zone Statistics */
  get_counts("/api/v1.0/zones/stats", "activeZones");
  get_counts("/api/v1.0/zones/stats?status=expired", "expiredZones");
  get_counts("/api/v1.0/zones/stats?status=false_positive", "fpZones");
  get_counts("/api/v1.0/zones/ip_stats", "ipZones");
  get_counts("/api/v1.0/zones/ipv6_stats", "ipv6Zones");
  get_counts("/api/v1.0//whois_db?count=1", "whoisRecords")
  get_distinct_fields("/api/v1.0/zones/sources", "zoneSources");

  /* DNS Statistics */
  get_counts("/api/v1.0/sonar/rdns?count=1", "rdnsStatistics",);
  get_counts("/api/v1.0/dns?count=1", "dnsStatistics");
  get_counts("/api/v1.0/dead_dns?count=1", "deadDnsStatistics");
  get_distinct_fields("/api/v1.0/dns/sources", "dnsSources");

  /* CT Statistics */
  get_counts("/api/v1.0/ct/total_count", "ctStatistics");
  get_counts("/api/v1.0/ct/signature_algorithm?count=1", "sha1Statistics");
  get_counts("/api/v1.0/ct/corp_certs?exclude_expired=1&count=1", "corpStatistics");
  get_counts("/api/v1.0/ct/corp_certs?count=1", "corpExpStatistics");

  for (let org in TLSOrgs) {
    make_get_request("/api/v1.0/ct/org?org=" + encodeURIComponent(TLSOrgs[org]) + "&count=1", show_distinct_fields, [TLSOrgs[org], "trackedOrgs"], "errorMessage");
  }

  /* Censys Statistics */
  if (ScanDataSources.includes("censys")) {
    document.getElementById("censysSection").style.display = "block";
    get_counts("/api/v1.0/censys/corp_ssl_count", "CensysCorpSSLCount");
    get_counts("/api/v1.0/censys/protocol_count?protocol=ssl_2", "SSL2Count");
    get_counts("/api/v1.0/censys/protocol_count?protocol=ssl_3", "SSL3Count");
    get_counts("/api/v1.0/censys/protocol_count?protocol=tls", "TLSCount");
    get_counts("/api/v1.0/censys/protocol_count?protocol=dhe", "SSLDHECount");
    get_counts("/api/v1.0/censys/protocol_count?protocol=dhe_export", "SSLDHEExportCount");
    get_counts("/api/v1.0/censys/protocol_count?protocol=rsa_export", "SSLRSAExportCount");
    get_counts("/api/v1.0/censys/total_count", "censysCount");

    for (let org in TLSOrgs) {
      make_get_request("/api/v1.0/censys/certs?org=" + encodeURIComponent(TLSOrgs[org]) + "&count=1", show_distinct_fields, [TLSOrgs[org], "censysOrgs"], "errorMessage")
    }

    for (let i = 0; i < CensysSupportedPorts.length; i++) {
      make_get_request("/api/v1.0/censys/ports?port=" + CensysSupportedPorts[i] + "&type=count", show_distinct_fields, [CensysSupportedPorts[i], "censysPorts"], "errorMessage");
    }
  }

  /* Scan Statistics */
  if (ScanDataSources.includes("zgrab")) {
    document.getElementById("scanSection").style.display = "block";
    get_counts("/api/v1.0/zgrab/80/ips?count=1", "zgrab80IP");
    get_counts("/api/v1.0/zgrab/80/domains?count=1", "zgrab80Domain");
    get_counts("/api/v1.0/zgrab/counts?collection=zgrab80", "zgrab80Total");
    get_counts("/api/v1.0/zgrab/443/ips?count=1", "zgrab443IP");
    get_counts("/api/v1.0/zgrab/443/domains?count=1", "zgrab443Domain");
    get_counts("/api/v1.0/zgrab/counts?collection=zgrab443", "zgrab443Total");
    get_counts("/api/v1.0/zgrab/counts?collection=zgrabPort", "zgrabPortTotal");

    for (let org in TLSOrgs) {
      make_get_request("/api/v1.0/zgrab/443/certs?org=" + encodeURIComponent(TLSOrgs[org]) + "&count=1", show_distinct_fields, [TLSOrgs[org], "zgrabOrgs"], "errorMessage");
    }

    for (let i = 0; i < ScanSupportedPorts.length; i++) {
      make_get_request("/api/v1.0/zgrab/" + ScanSupportedPorts[i] + "/ips?count=1", show_distinct_fields, [ScanSupportedPorts[i], "zgrabPorts"], "errorMessage");
    }
  }

  return;
}

function displayCountData(obj, divRef) {
  var elem = document.getElementById(divRef);
  elem.className = "";

  if (obj.hasOwnProperty("count")) {
    elem.innerHTML = obj.count;
  } else if (obj.hasOwnProperty("message")) {
    elem.innerHTML = obj.message;
  } else {
    elem.innerHTML = "Error parsing response.";
  }
}

function show_distinct_fields(obj, values) {
  let innerHTML = values[0] + ": " + obj.count.toString() + "<br/>";
  let elem = document.getElementById(values[1]);
  elem.innerHTML += innerHTML;
}

function get_counts(url, field_name) {
  make_get_request(url, displayCountData, field_name, "errorMessage", JSON.parse('{"count": 0}'));
}

function fetch_field_stats(obj, field_name) {
  for (let entry in obj['sources']) {
    if (field_name === "zoneSources") {
      make_get_request("/api/v1.0/zones/stats?source=" + obj['sources'][entry], show_distinct_fields, [obj['sources'][entry], field_name], "errorMessage");
    } else if (field_name === "dnsSources") {
      make_get_request("/api/v1.0/dns?count=1&source=" + obj['sources'][entry], show_distinct_fields, [obj['sources'][entry], field_name], "errorMessage");
    }
  }
}

function get_distinct_fields(url, field_name) {
  make_get_request(url, fetch_field_stats, field_name, "errorMessage", "");
}
