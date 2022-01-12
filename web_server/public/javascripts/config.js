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

var last_ipv6_id;
var last_ipv6;
var last_cidr_id;
var last_cidr;
var last_zone_id;
var last_zone;

var admin_api_map = {
    "users": "/api/v1.0/admin/users",
    "groups": "/api/v1.0/admin/groups",
    "zones": "/api/v1.0/admin/zones",
    "ip_zones": "/api/v1.0/admin/ip_zones",
    "ipv6_zones": "/api/v1.0/admin/ipv6_zones",
    "get_zones": "/api/v1.0/zones/zone/",
    "get_ip_zones": "/api/v1.0/zones/ipzone/",
    "get_ipv6_zones": "/api/v1.0/zones/ipv6zone/",
    "jobs": "/api/v1.0/admin/job_status"
}

function buildPage() {
    var path = window.location.pathname;
    if (path === "/admin/jobs") {
        display_jobs();
    } else if (path === "/admin/user_config") {
        display_config();
        document.getElementById("addUser").addEventListener("click", add_user);
        document.getElementById("addUserToGroup").addEventListener("click", add_user);
    } else {
        document.getElementById("addIPZone").addEventListener("click", add_zone);
        document.getElementById("addIPv6Zone").addEventListener("click", add_zone);
        document.getElementById("addZone").addEventListener("click", add_zone);
        document.getElementById("modify_ipv6").addEventListener("submit", find_zones);
        document.getElementById("modify_domain").addEventListener("submit", find_zones);
        document.getElementById("modify_cidr").addEventListener("submit", find_zones);
        document.getElementById("updateZoneStatus").addEventListener("click", patch_zone);
        document.getElementById("updateZoneNotes").addEventListener("click", patch_zone);
        document.getElementById("updateCIDRStatus").addEventListener("click", patch_zone);
        document.getElementById("updateCIDRNotes").addEventListener("click", patch_zone);
        document.getElementById("updateIPv6Status").addEventListener("click", patch_zone);
        document.getElementById("updateIPv6Notes").addEventListener("click", patch_zone);
        document.getElementById("zoneDetails").style.visibility = 'hidden';
        document.getElementById("ipZoneDetails").style.visibility = 'hidden';
        document.getElementById("ipv6ZoneDetails").style.visibility = 'hidden';
    }
}

function display_config() {
    get_request(admin_api_map["users"], display_user_table);
    get_request(admin_api_map["groups"], display_group_table);
}

function display_jobs() {
    get_request(admin_api_map["jobs"], display_jobs_table);
}

function confirm_patch_update(results, requestId) {
    if (requestId.includes("CIDR")) {
        document.getElementById("ipZonePatchResult").innerHTML = "Update Successful";
        get_request(admin_api_map["get_ip_zones"] + last_cidr, display_ip_zone);
    } else if (requestId.includes("IPv6")) {
        document.getElementById("ipv6ZonePatchResult").innerHTML = "Update Successful";
        get_request(admin_api_map["get_ipv6_zones"] + last_ipv6, display_ipv6_zone);
    } else {
        document.getElementById("zonePatchResult").innerHTML = "Update Successful";
        get_request(admin_api_map["get_zones"] + last_zone, display_zone);
    }
}

function patch_zone(ev) {
    var requestId = this.id;
    ev.preventDefault();
    var query = "";
    var url = "";
    if (requestId.includes("updateZoneStatus")) {
        url = admin_api_map["zones"] + "/" + last_zone_id;
        query = "status=" + document.getElementById("zoneStatus").value;
    } else if (requestId.includes("ZoneNotes")) {
        url = admin_api_map["zones"] + "/" + last_zone_id;
        query = "notes=" + document.getElementById("zoneNotes").value;
    } else if (requestId.includes("CIDRStatus")) {
        url = admin_api_map["ip_zones"] + "/" + last_cidr_id;
        query = "status=" + document.getElementById("ipZoneStatus").value;
    } else if (requestId.includes("CIDRNotes")) {
        url = admin_api_map["ip_zones"] + "/" + last_cidr_id;
        query = "notes=" + document.getElementById("cidrNotes").value;
    } else if (requestId.includes("IPv6Status")) {
        url = admin_api_map["ipv6_zones"] + "/" + last_ipv6_id;
        query = "status=" + document.getElementById("ipv6ZoneStatus").value;
    } else if (requestId.includes("IPv6Notes")) {
        url = admin_api_map["ipv6_zones"] + "/" + last_ipv6_id;
        query = "notes=" + document.getElementById("ipv6Notes").value;
    } else {
        return false;
    }

    var xhr = new XMLHttpRequest();
    xhr.addEventListener("error", errorHandler);
    xhr.onreadystatechange = function () {
        if (xhr.readyState === 4 && xhr.status === 201) {
            try {
                var myObj = JSON.parse(xhr.responseText);
            } catch (err) {
                document.getElementById('errorMessage').innerHTML = "<b>Error: Bad JSON! <pre>" + err.message + "</pre></b>";
                return;
            }
            confirm_patch_update(myObj, requestId);
        } else if (xhr.status === 500) {
            document.getElementById('errorMessage').innerHTML = xhr.responseText;
        }
    };

    xhr.open("PATCH", url);
    xhr.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
    xhr.send(query);
    return false;
}


function confirm_user_update(results, requestID) {
    if (requestID.includes("roup")) {
        document.getElementById("groupResult").innerHTML = "Update Successful";
        get_request("/api/v1.0/admin/groups", display_group_table);
    } else {
        document.getElementById("userResult").innerHTML = "Update Successful";
        get_request("/api/v1.0/admin/users", display_user_table);
    }
}

function add_user(ev) {
    var requestId = this.id;
    var query = "";
    var url = "";
    document.getElementById('errorMessage').innerHTML = "";
    if (requestId.includes("Group")) {
        if (document.getElementById("selectGroup").value.length === 0) {
            document.getElementById('errorMessage').innerHTML = "<b>Error: A group must be provided</b>";
            return false;
        }
        url = admin_api_map["groups"] + "/" + document.getElementById("selectGroup").value;
        query = "member=" + document.getElementById("groupUser").value;
    } else {
        if (document.getElementById("newUser").value.length === 0) {
            document.getElementById('errorMessage').innerHTML = "<b>Error: A user must be provided</b>";
            return false;
        }
        url = admin_api_map["users"];
        query = "userid=" + document.getElementById("newUser").value;
    }

    var xhr = new XMLHttpRequest();
    xhr.addEventListener("error", errorHandler);
    xhr.onreadystatechange = function () {
        if (xhr.readyState === 4 && xhr.status === 201) {
            try {
                var myObj = JSON.parse(xhr.responseText);
            } catch (err) {
                document.getElementById('errorMessage').innerHTML = "<b>Error: Bad JSON! <pre>" + err.message + "</pre></b>";
                return false;
            }
            confirm_user_update(myObj, requestId);
        } else if (xhr.readyState === 4 && xhr.status === 400) {
            var error = JSON.parse(xhr.responseText)
            document.getElementById('errorMessage').innerHTML = error['message'];
        } else if (xhr.readyState === 4 && xhr.status === 500) {
            document.getElementById('errorMessage').innerHTML = xhr.responseText;
        }
    };

    if (requestId.includes("Group")) {
        xhr.open("PATCH", url);
    } else {
        xhr.open("POST", url);
    }
    xhr.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
    xhr.send(query);
    ev.preventDefault();
    return false;
}

function find_zones(ev) {
    var requestId = this.id;
    ev.preventDefault();
    if (requestId.includes("cidr")) {
        let zone = document.getElementById("cidr_search_input").value;
        get_request(admin_api_map["get_ip_zones"] + encodeURIComponent(zone), display_ip_zone);
        last_cidr = encodeURIComponent(zone);
    } else if (requestId.includes("ipv6")) {
        let zone = document.getElementById("ipv6_search_input").value;
        get_request(admin_api_map["get_ipv6_zones"] + encodeURIComponent(zone), display_ipv6_zone);
        last_ipv6 = encodeURIComponent(zone);
    } else {
        let zone = document.getElementById("zone_search_input").value;
        get_request(admin_api_map["get_zones"] + zone.toLowerCase(), display_zone);
        last_zone = zone;
    }
    return false;
}

function confirm_zone_update(results, id) {
    if (id.includes("IPZone")) {
        document.getElementById("ipZoneUpdateResult").innerHTML = results['message'];
    } else if (id.includes("IPv6Zone")) {
        document.getElementById("ipv6ZoneUpdateResult").innerHTML = results['message'];
    } else {
        document.getElementById("zoneUpdateResult").innerHTML = results['message'];
    }
}

function add_zone() {
    var requestId = this.id;
    var query = "";
    var url = "";
    document.getElementById('errorMessage').innerHTML = "";
    if (requestId.includes("IPZone")) {
        if (document.getElementById("ipZone_add_input").value.length === 0) {
            document.getElementById('errorMessage').innerHTML = "<b>Error: A zone must be provided</b>";
            return false;
        }
        url = admin_api_map["ip_zones"];
        query = "zone=" + document.getElementById("ipZone_add_input").value;
    } else if (requestId.includes("IPv6Zone")) {
        if (document.getElementById("ipv6Zone_add_input").value.length === 0) {
            document.getElementById('errorMessage').innerHTML = "<b>Error: A zone must be provided</b>";
            return false;
        }
        url = admin_api_map["ipv6_zones"];
        query = "zone=" + document.getElementById("ipv6Zone_add_input").value;
    } else {
        if (document.getElementById("zone_add_input").value.length === 0) {
            document.getElementById('errorMessage').innerHTML = "<b>Error: A zone must be provided</b>";
            return false;
        }
        url = admin_api_map["zones"];
        query = "zone=" + document.getElementById("zone_add_input").value;
    }

    var xhr = new XMLHttpRequest();
    xhr.addEventListener("error", errorHandler);
    xhr.onreadystatechange = function () {
        if (xhr.readyState === 4 && xhr.status === 201) {
            try {
                var myObj = JSON.parse(xhr.responseText);
            } catch (err) {
                document.getElementById('errorMessage').innerHTML = "<b>Error: Bad JSON! <pre>" + err.message + "</pre></b>";
                return;
            }
            confirm_zone_update(myObj, requestId);
        } else if (xhr.status === 500 || xhr.status === 400) {
            document.getElementById('errorMessage').innerHTML = xhr.responseText;
        }
    };

    xhr.open("POST", url);
    xhr.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
    xhr.send(query);
    return false;
}

function display_zone(results) {
    if (results.length === 0) {
        document.getElementById("zoneResult").innerHTML = "<b>Not found</b><br/>";
    }

    document.getElementById("zoneDetails").style.visibility = 'visible';

    var displayHTML = create_new_table()
    displayHTML += create_table_head(["Zone", "Creation Date", "Update Date", "Status", "Notes"]);
    displayHTML += create_table_body();
    displayHTML += create_table_row();
    displayHTML += create_table_entry(results['zone']);
    displayHTML += create_table_entry(results['created']);
    displayHTML += create_table_entry(results['updated']);
    displayHTML += create_table_entry(results['status']);

    if (results['notes']) {
        displayHTML += create_table_entry(results['notes'].toString());
    } else {
        displayHTML += create_table_entry("");
    }
    displayHTML += end_table_row();

    displayHTML += end_table() + "<br/>";

    last_zone_id = results['_id'];

    document.getElementById("zoneResult").innerHTML = displayHTML;
}

function display_ip_zone(results) {
    if (results.length === 0) {
        document.getElementById("ipZoneResult").innerHTML = "<b>Not found</b><br/>";
    }

    document.getElementById("ipZoneDetails").style.visibility = 'visible';

    var displayHTML = create_new_table();
    displayHTML += create_table_head(["CIDR", "Creation Date", "Update Date", "Status", "Notes"]);
    displayHTML += create_table_body();
    displayHTML += create_table_row();
    displayHTML += create_table_entry(results['zone']);
    displayHTML += create_table_entry(results['created']);
    displayHTML += create_table_entry(results['updated']);
    displayHTML += create_table_entry(results['status']);

    if (results['notes']) {
        displayHTML += create_table_entry(results['notes'].toString());
    } else {
        displayHTML += create_table_entry("");
    }

    displayHTML += end_table_row();

    displayHTML += end_table() + "<br/>";

    last_cidr_id = results['_id'];

    document.getElementById("ipZoneResult").innerHTML = displayHTML;
}

function display_ipv6_zone(results) {
    if (results.length === 0) {
        document.getElementById("ipv6ZoneResult").innerHTML = "<b>Not found</b><br/>";
    }

    document.getElementById("ipv6ZoneDetails").style.visibility = 'visible';

    var displayHTML = create_new_table();
    displayHTML += create_table_head(["IPv6 CIDR", "Creation Date", "Update Date", "Status", "Notes"]);
    displayHTML += create_table_body();
    displayHTML += create_table_row();
    displayHTML += create_table_entry(results['zone']);
    displayHTML += create_table_entry(results['created']);
    displayHTML += create_table_entry(results['updated']);
    displayHTML += create_table_entry(results['status']);

    if (results['notes']) {
        displayHTML += create_table_entry(results['notes'].toString());
    } else {
        displayHTML += create_table_entry("");
    }

    displayHTML += end_table_row();

    displayHTML += end_table() + "<br/>";

    last_ipv6_id = results['_id'];

    document.getElementById("ipv6ZoneResult").innerHTML = displayHTML;
}

function display_group_table(results) {
    if (results.length === 0) {
        document.getElementById("groupList").innerHTML = "<b>Not found</b><br/>";
    }

    var displayHTML = create_new_table();
    displayHTML += create_table_head(["Name", "Creation Date", "Updated", "Status", "Admins", "Members"]);
    displayHTML += create_table_body();

    var groupSel = document.getElementById("selectGroup");
    let initialLength = groupSel.length;

    for (var i = 0; i < results.length; i++) {
        displayHTML += create_table_row();
        displayHTML += create_table_entry(results[i]['name']);
        displayHTML += create_table_entry(results[i]['creation_date']);

        if (results[i].hasOwnProperty("updated")) {
            displayHTML += create_table_entry(results[i]['updated']);
        } else {
            displayHTML += create_table_entry(results[i]['creation_date']);
        }
        var admins = results[i]['admins'].toString().replace(/,/g, ", ");
        var members = results[i]['members'].toString().replace(/,/g, ", ");

        displayHTML += create_table_entry(results[i]['status']);
        displayHTML += create_table_entry(admins);
        displayHTML += create_table_entry(members);
        displayHTML += end_table_row()

        if (initialLength == 0) {
            var option = document.createElement("option");
            option.text = results[i]['name'];
            option.value = results[i]['name'];

            groupSel.add(option);
        }
    }

    displayHTML += end_table() + "<br/>";

    document.getElementById("groupList").innerHTML = displayHTML;
}

function display_user_table(results) {
    if (results.length === 0) {
        document.getElementById("userList").innerHTML = "<b>Not found</b><br/>";
    }

    var displayHTML = create_new_table();
    displayHTML += create_table_head(["UserID", "Creation Date", "Status"]);
    displayHTML += create_table_body();

    for (var i = 0; i < results.length; i++) {
        displayHTML += create_table_row();
        displayHTML += create_table_entry(results[i]['userid']);

        if (results[i].hasOwnProperty("updated")) {
            displayHTML += create_table_entry(results[i]['updated']);
        } else {
            displayHTML += create_table_entry(results[i]['creation_date']);
        }
        displayHTML += create_table_entry(results[i]['status']);
        displayHTML += end_table_row();
    }

    displayHTML += end_table() + "<br/>";

    document.getElementById("userList").innerHTML = displayHTML;
}

function compare(a, b) {
    if (a.job_name < b.job_name)
        return -1;
    if (a.job_name > b.job_name)
        return 1;
    return 0;
}


function display_jobs_table(results) {
    if (results.length === 0) {
        document.getElementById("jobStatus").innerHTML = "<b>Not found</b><br/>";
    }

    var displayHTML = create_new_table();
    displayHTML += create_table_head(["Job Name", "Update Date", "Status"]);
    displayHTML += create_table_body();

    results.sort(compare);
    for (var i = 0; i < results.length; i++) {
        if (results[i]['status'] != "RETIRED") {
            displayHTML += create_table_row();
            displayHTML += create_table_entry(results[i]['job_name']);
            displayHTML += create_table_entry(results[i]['updated']);

            if (results[i]['status'] === "ERROR") {
                displayHTML += create_table_entry(results[i]['status'], "", "errorResult");
            } else {
                displayHTML += create_table_entry(results[i]['status']);
            }
            displayHTML += end_table_row();
        }
    }

    displayHTML += end_table() + "<br/>";

    document.getElementById("jobStatus").innerHTML = displayHTML;
}

function get_request(url, callback) {
    var xhr = new XMLHttpRequest();
    xhr.addEventListener("error", errorHandler);
    xhr.onreadystatechange = function () {
        if (xhr.readyState === 4 && xhr.status === 200) {
            try {
                var myObj = JSON.parse(xhr.responseText);
            } catch (err) {
                document.getElementById('errorMessage').innerHTML = "<b>Error: Bad JSON! <pre>" + err.message + "</pre></b>";
                return;
            }
            callback(myObj);
        } else if (xhr.status === 404) {
            callback([]);
        } else if (xhr.status === 500) {
            document.getElementById('errorMessage').innerHTML = xhr.responseText;
        }
    };

    xhr.open("GET", url);
    xhr.send();
    return;
}
