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
 * This file is for universal constants and is included in all page loads.
 */

// Indicates whether to use zgrab or censys for port and SSL scan information.
// The check against this value is a JavaScript "includes" and not a strict match.
var ScanDataSources = ["zgrab"];
var ScanSupportedPorts = ["22", "25", "80", "443", "465"]
var CensysSupportedPorts = ["21", "22", "23", "25", "53", "80", "110", "143", "443", "465", "502", "993", "995", "7547", "47808"];

// This can be used to specify your primary Org value in TLS certificates
var TLSOrgs = [];

// Your company name for HTML UI purposes.
var CompanyName = "";

// Indicates whether the Whois record display is enabled.
// Depending on where your machine is deployed,
// outbound Whois queries may not be allowed through your firewall.
var DynamicWhoisEnabled = false;

// Custom APIs can be added beyond the core data sources.
var CustomScriptSourcesEnabled = true;

// The url containing the code for the custom APIs
var CustomScriptSrc = "/javascripts/custom_code.js"
