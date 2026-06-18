import js from "@eslint/js";
import globals from "globals";
import { defineConfig } from "eslint/config";

export default defineConfig([
  { files: ["**/*.{js,mjs,cjs}"], plugins: { js }, extends: ["js/recommended"], languageOptions: { globals: {...globals.browser, ...globals.node} } },
  {
    files: ["public/javascripts/**/*.js"],
    languageOptions: {
      globals: {
        // utilities.js — loaded on every page
        api_map: "writable",
        qs: "readonly",
        get_tls_log: "readonly",
        get_port_tls_log: "readonly",
        make_get_request: "readonly",
        dynamic_whois: "readonly",
        errorHandler: "readonly",
        clearErrorHandler: "readonly",
        create_h3: "readonly",
        create_new_div: "readonly",
        create_new_div_section: "readonly",
        create_new_list: "readonly",
        create_list_entry: "readonly",
        end_list: "readonly",
        end_div: "readonly",
        create_anchor: "readonly",
        create_new_table: "readonly",
        create_table_head: "readonly",
        create_table_body: "readonly",
        create_table_row: "readonly",
        create_table_entry: "readonly",
        end_table_row: "readonly",
        end_table: "readonly",
        create_check_mark: "readonly",
        create_button: "readonly",
        add_click_event_listeners: "readonly",
        LIMIT: "writable",
        PAGE: "writable",
        PAGING_FUNCTIONS: "writable",
        PAGING_URLS: "writable",
        PAGING_CLICK_WAIT: "writable",
        add_paging_html: "readonly",
        update_limit: "readonly",
        page_back: "readonly",
        page_forward: "readonly",
        sleep: "readonly",

        // constants.js — loaded on every page
        ScanDataSources: "readonly",
        ScanSupportedPorts: "readonly",
        CensysSupportedPorts: "readonly",
        TLSOrgs: "readonly",
        CompanyName: "readonly",
        DynamicWhoisEnabled: "readonly",
        CustomScriptSourcesEnabled: "readonly",
        CustomScriptSrc: "readonly",

        // custom_code.js
        custom_api_map: "readonly",
        custom_http_headers_map: "readonly",
        custom_code_handler: "readonly",

        // api.js / zone_ui.js — shared layout helpers
        create_div_title: "readonly",
        create_div_data: "readonly",

        // zone_ui.js
        display_response: "readonly",

        // zgrab_headers.js
        zgrab_http_headers: "writable",

        // geometry.js
        geo: "writable",

        // meta.js
        get_counts: "readonly",

        // Third-party libraries
        $: "readonly",
        d3: "readonly",
        URI: "readonly",
      },
    },
  },
  {
    // These files exist solely to expose globals; every declaration is intentionally unused within the file itself.
    files: [
      "public/javascripts/utilities.js",
      "public/javascripts/constants.js",
      "public/javascripts/custom_code.js",
      "public/javascripts/zgrab_headers.js"
    ],
    rules: {
      "no-unused-vars": "off",
    },
  },
]);
