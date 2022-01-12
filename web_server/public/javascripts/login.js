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
    if (document.getElementById('loginButton') != null) {
        document.getElementById('loginButton').addEventListener("click", doLogin);
    }
}

function login_qs(key) {
    key = key.replace(/[*+?^$.\[\]{}()|\\\/]/g, "\\$&"); // escape RegEx meta chars
    var match = location.search.match(new RegExp("[?&]" + key + "=([^&]+)(&|$)"));
    if (match == null) {
        return ("/");
    }
    return match && decodeURIComponent(match[1].replace(/\+/g, " "));
}

function doLogin() {
    window.document.location = "/auth/login?returnPath=" + login_qs("returnPath");
}
