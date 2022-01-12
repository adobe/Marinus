
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


/**
 * This file handles per-deployment extensions.
 * This file can be customized to add your own code to extend Marinus.
 */


/**
  * This will be concatenated to the main api_map used in the rest of the code.
  * The structure of api_map is {'name': 'url', 'name2': 'url2', ...}
  * Add the list of your custom APIs here.
  */
var custom_api_map = {
};

/**
 * This will be concatenated with the zgrab_http_headers map.
 * It will allow you to search for custom headers.
 */
var custom_http_headers_map = {
};

/**
 * This is a generic handler that is included in pages that support custom actions.
 * The first argument in the array informs the function which page is calling.
 * Based on the first argument (args[0]), you can then call your own functions
 * that you have added to this file.
 */
function custom_code_handler(...args) {
    if (args[0] === "/ip") {
        // Place your custom IP page function here.
    } else if (args[0] === "/domain") {
        // Place your custom Domain page function here.
    } else if (args[0] === "zone_ui_data_requests") {
        // Place your custom Zone page data function here.
    } else if (args[0] === "zone_ui_table_header") {
        // Place your custom Zone page UI table header function here.
    } else if (args[0] === "zone_ui_table_row") {
        // Place your custom Zone page UI table row function here.
    } else if (args[0] === "port_aws_check") {
        // Place your Port page custom AWS check code here
    }
}
