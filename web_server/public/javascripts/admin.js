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
    var path = window.location.pathname;
    if (path === "/admin/user") {
        fetch_user_info();
        fetch_group_info();
    }
}


function display_group_info(results) {
    var groupList = "";
    for (var i = 0; i < results.length; i++) {
        if (i != 0) {
            groupList += ", "
        }
        groupList += results[i]['name'];
    }
    document.getElementById("groupInfo").innerHTML = groupList;
}


function fetch_group_info() {
    var url = "/api/v1.0/admin/self_group";
    var query = "";

    make_get_request(url + query, display_group_info);
}


function display_user_info(results) {
    document.getElementById("userid").innerHTML = results['userid'];
    document.getElementById("status").innerHTML = results['status'];
    document.getElementById("apiKey").innerHTML = results['apiKey'];
}


function fetch_user_info() {
    var url = "/api/v1.0/admin/self";
    var query = "";

    make_get_request(url + query, display_user_info);
}

