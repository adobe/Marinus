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

function buildPage() {
    document.getElementById("zone_search").addEventListener("submit", doZoneLookup);
    document.getElementById("fqdn_search").addEventListener("submit", doFQDNLookup);
    document.getElementById("ip_search").addEventListener("submit", doIPLookup);
}

function doZoneLookup(event) {
    event.preventDefault();
    window.document.location = "/zone?search=" + document.getElementById("zone_input").value;
    return false;
}

function doFQDNLookup(event) {
    event.preventDefault();
    window.document.location = "/domain?search=" + document.getElementById("fqdn_input").value;
    return false;
}

function doIPLookup(event) {
    event.preventDefault();
    window.document.location = "/ip?search=" + document.getElementById("ip_input").value;
    return false;
}
