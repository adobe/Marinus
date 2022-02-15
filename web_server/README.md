# Marinus

The Marinus front end is based on Node.js, Express, and Coral UI. Marinus has been tested with Node.js version 12. It connects to a MongoDB backend via a Mongoose driver. For production deployments, Marinus can interact with third-party services such as SSO providers, Splunk, and New Relic.

The code layout is as follows:
* */config/*
  -- Contains the basics for the Node.js configuration
* */config/keys/*
  -- This is the directory that contains the keys for TLS and SSO.
* */config/models/*
  -- This contains the models used for interacting with the MongoDB. All MongoDB queries are defined here.
* */public/*
  -- Contains the JavaScript, CSS, and resources for the HTML front end.
* */routes/*
  -- Contains the server-side APIs for Marinus. The APIs are the bridge between the HTML front end and the database model code backend. These APIs can also be called using the apiKey header.
* */views/*
  -- Contains the "EJS" HTML templates.
* */server.js*
  -- The main file used to start the server. (e.g. "server node.js")
* */start.sh and /stop.sh*
  -- Utility scripts for starting and stopping the server using forever.
  
## Philosophy:
The Marinus web server is a view into the data that the Marinus python scripts collect. The GUI is simple in nature and it is targeted more towards engineers. It enables a user to perform quick searches and view visual summaries of the network. The GUI also provides a selection of reports that are meant to inspire people about how the data can be used. Although, the primary goal of the Marinus web server is to provide rich APIs into the data for additional reporting and automation.
 
For instance, the Reports section of the GUI provides a few select reports that demonstrate how the different types of data in Marinus can be useful. Let's say that you see a report that is pulling the data that you want but it is not displaying in a way that is useful for your needs. All of the Marinus web pages pull data by leveraging the APIs that are defined in the Swagger documentation. Therefore, you could reuse the same APIs as the existing web page in order to create your own reports that display the data in the way that meets your needs.
 
## Marinus API
Marinus provides access to all of the data via APIs. All of the APIs are available under "/api/v1.0/...". In order to leverage the API, you need to provide an *apiKey* as a GET parameter ("apiKey") or a HTTP header ("x-api-key"). The latter is preferred since it prevents API keys from showing up in the access log. It is currently planned to deprecate the GET parameter option in the near future. Every user is issued a unique API key when their account is created. The key can be found within the user profile page.

The web UI also leverages the REST APIs to retrieve data. Therefore, the REST APIs will first check for a cookie-based session. If one is not found, the REST APIs will then try to find an apiKey in the request to use for authorization.

The Swagger documentation for the REST APIs can be found under "/docs" on the web site.

## Marinus authentication and authorization
Marinus has a "production" and "development" mode. When Marinus is in production mode, all user authentication is done using the Node passport.js library (http://www.passportjs.org/) configured for SAML authentication (passport-saml). The passport.js library is compatible with multiple SSO providers such as Facebook, Twitter, Github, and Google through modules known as "strategies". The Marinus implemntation uses a SAML "strategy" that works with services such as Okta and Active Directory Federation Services. The config/passport_conf.js file manages the configuration for the passport-saml strategy. If your SSO is not SAML based, then you can modify that file for your particular provider's strategy module.

A valid SSO account is not sufficient on its own to obtain access to Marinus in production mode. A Marinus user account must also be created that matches their SSO username. Marinus listens for SSO responses at "/okta" as deined in the source code at *routes/auth.js*.

When Marinus is running in development mode, it is possible to authenticate using the username "marinus" and the *localAdminPassword* specified in the config/env.js file. The *marinus* user is a full administrator account but it does not have an API key by default. Users added via the UI in development mode will be treated like service accounts. They will not be able to login to the UI but they will have usable API keys assigned to them. The apiKey values are stored as part of their profile in the *users* collection in the database. API key values are the same in both development and production modes.

Marinus user level authorization provides read-only access to most data. *Data admins* are able to modify the zones and CIDRs by annotating them with notes or marking false positives. Lastly, full *admins* have all the rights of data admins as well as the ability to create users, create new zones/CIDRs, and assign groups.

## Marinus configuration
Please note, that you don't want to run the web server unless you have already setup the database as defined within the python3_cron_scripts GettingStarted.md. The web server is designed to show the data that is collected by the scripts so it is best to run a few of the scripts first.

To start, you must first ensure that all of the necessary packages are installed. The packages are defined within the packages.json file in the root directory of the web server. From within the root directory of the web server, type:

`npm install`

This will install of the necessary packages that Node.js will need. There are also *start.sh* and *stop.sh* files within the root directory of the web server. The *start.sh* file assumes that a "../logs/" directory exists as a place to store the logs. Be sure to create this directory. In addition, these scripts are dependent on the *forever* command in order to allow the server to run continuously. The forever command can be installed using:

`[sudo] npm install forever -g`

Marinus is able to run in either a development mode or a production mode. In development mode, Marinus uses a single account for authentication and all logging is local. In production mode, Marinus attempts to use SSO for authentication and attempts to log to Splunk and NewRelic (see Marinus Logging). It is possible to disable these features in *config/config.js* and in *config/env.js* if they are not used within your organization. API keys are the same in both development and production modes.

Marinus determines whether it is in production or development mode by checking the environment variable: *NODE_ENV* . If you can't set the environment variable, then you can adjust the default in the server.js file. It is defined in the following line: `var env = process.env.NODE_ENV || 'production';`

The web server can not run immediately after a git check out. You should first initialize the database using the guidance in the GettingStarted.md file located in the python3_cron_scripts directory. Once there is data in the database, there are several keys and credentials which must be collected for the Node.js configuration. These include:

  * The TLS certificate and key to be placed in config/keys/server.key and config/keys/server.crt
  * The SSO key in config/keys/sso.cert (if used)
  * If the MongoDB server uses TLS, then you should place its CA file in the config/keys/ directory.
  * You will need the MongoDB authentication information for the config/env.js file
  * If the server is located in "./node-src/", then log files will be placed in "./logs/" and that directory needs to be created.
  
The available Marinus configuration parameters within config/env.js are as follows:
  * **version**: The version of Marinus. Modification is not necessary.
  * **build**: The current build of Marinus. Modification is not necessary.
  * **state**: A variable that Marinus uses to know which state was loaded. Modification is not necessary.
  * **rootPath**: This is a variable for Express. Modification is not necessary.
  * **database**: Change this to reflect the location of your MongoDB database. Please see the notes below.
  * **port**: The port that the web server will listen on. By default, this variable is set to 3005 but can be overriden by a *PORT* environment variable.
  * **ip**: The IP address that the web server will listen on. If you are going to use an NGINX front end, then you can leave this as localhost.
  * **cookieSecret**: This value is used by the Express Session npm package to sign the SessionID cookie. Set it to whatever secret value that meets your compliance needs.
  * **localAdminPassword**: If you are not using SSO for authentication, then you can log into the web server with the username *marinus* and this password. Set it to whatever highly secure value meets your compliance needs.
  * **pretty**: A deprecated setting for Express 3.x environments. This can be ignored.
  * **sso_url**: If SSO is used, this URL value is used as the "entryPoint" value in Passport's SamlStrategy.
  * **swagger**: This section is for Swagger configuration. Swagger needs to know the hostname in order to operate properly.
  * **internalDomain**: The Marinus web server can produce reports showing the references to your internal domains that it identified within public sources such as certificate transparency logs. This value informs the code of your second or third-level domain name that is used within your internal network. For instance, let's your internal network is internal.example.org and it has hosts such as hr.internal.example.org, finance.internal.example.org, etc. You would set this value to "internal.example.org" so that Marinus can inform you of any identified references to your private network within the public data that it has collected.
  * **api_key_length**: The web server will automatically create a new API key for each SSO user that is added through the web interface. This specifies the size of the API key when it is hex encoded. This means that if you specify 32 in this field, then you will get a 16 byte secret that is hex encoded to produce a string that is 32 bytes long.
  * **splunk_url,splunk_token**: Specify these values if you would like Marinus to log its web requests to Splunk.
  * **new_relic_enabled**: Set this to true if you would like Marinus to send performance data to NewRelic. Also be sure to edit the newrelic.js file to include your key.
  * **mongodbSSLCA**: If your Mongo database uses TLS, then this value can be set to the path of your CA file for the connection. For example: `'./config/keys/mongoCA.pem'`
  
If your Mongo database supports replica sets, then they can be specified as follows in the env.js file as follows:
   mongodb://DEV_DATABASE_USERNAME:DEV_DATABASE_PASSWORD@replica-1.example.org:27021,replica-2.example.org:27021/DOMAINS?replicaSet=REPLICA_SET_NAME

One important note is that the api_key_length within config/env.js sets the strength of the API key. The API key is generated by creating api_key_length/2 random bytes and then hex encoding them. Therefore, the key strength will be api_key_length/2. In other words, a 32 byte length would have the security of 128 bit key ((32/2) * 8 bits).

Marinus also has options for modifications to how the HTML is rendered. The first file is located in *public/javascripts/constants.js* . This has the following settings:

* **ScanDataSources**: This setting defines where the web server should look for zgrab scanning information. If you are using data from Censys, then you would place the string `censys` in this array. If you are scanning yourself using the provided zgrab scripts, then you would place `zgrab` in this array. If you are using both, then specify both.

* **ScanSupportedPorts,CensysSupportedPorts**: These define the list of ports that the scanners are currently auditing. This does not need to be changed.

* **TLSOrgs**: When you configured the Marinus database, you added the organization values for your TLS certificates. You can place those same values here. This will eventually be replaced with an API call to fetch the values from the database. This data is currently only used in the administrative Data Statistics page.

* **CompanyName**: This is not currently used and was put in for a future update.

* **DynamicWhoisEnabled**: This defines whether certain web pages should include a Dynamic Whois option at the bottom. If enabled, the option on the page would tell the Marinus server to attempt a real-time Whois lookup. This would require port 43 to be allowed outbound in your environment from the Node web server. By default, this is disabled.

* **CustomScriptSourcesEnabled**: Marinus allows for optional extensions that are not a part of the open source project. Therefore, if you have an internal service whose data you want included in your deployment, then you would set this value to true. The following settings define where you have uploaded the JavaScript for your custom integrations.

* **CustomScriptSrc**: This is the file where you will place your custom javascript to include in the web pages. Marinus expects this file to have certain functions available so it is best not to change this value and to use the template provided by Marinus. Extending Marinus with your own custom code is an optional step. Please see the next section for more information.

## Customized Marinus Extensions
As mentioned above, the *public/javascripts/constants.js* file refers to the option of extending Marinus with customized data from your own services. Marinus will check the file referenced in *CustomScriptSrc* for the following two values:

* **custom_api_map**: These values get appended to the standard api_map list. If you have extended Marinus with your own REST APIs, then you would add their names and URLs to this dictionary. An example:

`var custom_api_map = {
    'custom_api_1': '/api/v1.0/custom/api_1',
    'custom_api_2': '/api/v1.0/custom/api_2'
};`

New APIs would also need to be added to the config/routes.js file in order to be loaded by the web server.

* **custom_http_headers_map**: This parameter is used in the HTTP Response Headers search page. If your public web services issue custom HTTP headers, then defining them here will allow the headers to show up in the search options of the HTTP Response Headers search page. The "name" value in the dictionary entry is the name of the HTTP header. The "value" would be set to "unknown". This format is based on how zgrab and Censys group headers in their JSON responses. According to their format, headers which are not a part of the HTTP standard are grouped together as "unknown". An example entry for your company's custom token and server headers might be:

`var custom_http_headers_map = {
    "x_company_custom_token_header": "unknown",
    "x_company_custom_server_header": "unknown",
};`

* **custom_code_handler**: This is the function that is called by every page that supports custom extensions. The function accepts a dynamic array of arguments for maximum flexibility. The first argument is a unique value that allows the function to know who is calling it. The first argument is then used to decide which action to take. For instance, the "Domain" page of Marinus calls the custom code handler function as follows:

`custom_code_handler('/domain', 'domain', value);`

The custom_code_handler function has the following code for handling that call:

`   ...
    } else if (args[0] === "/domain") {
        // Place Domain page specific custom code here
    } else if ...`

If you wanted to extend Marinus' functionality on the Domain page, then you could put whatever code you wanted in that section. In general, it is assumed that this file will be completely customized by anyone who uses Marinus. By separating out the customization code into its own file, it makes it easier to do merges when there are updates to Marinus.

## Custom web pages
It is also possible to add custom web pages with minimal impact to core Marinus code. Within the */views/partials/custom/* directory, there is a *custom_host_header.ejs* file and a *custom_reports_header.ejs* file. You can place references to your custom pages within these two files and they will will show up in the respective pull down menus of the navigation page. You would also need to specify the new pages in the *routes/core.js* file in order for Node.js to recognize them.

## Marinus security
Marinus has some built-in security such as leveraging Content-Security-Policies and using database models. There are some security choices that are left up to admin with regards to the use of TLS, the length of the API keys, and authentication choices. Please see the CONTRIBUTING.md file in the root github directory for details on how to report security issues.

Marinus stores cryptographic keys in */config/keys*. By default, Marinus is designed to run with HTTPS. The TLS keys for HTTPS should be placed in */config/keys/server.key* and */config/keys/server.crt*. If you are using MongoDB with TLS, the CA certificate for the MongoDB server can be placed anywhere so long as its location is specified in the *mongodbSSLCA* parameter of the *config/env.js* file. If SSO will be used, then the key associated with the SSO provider can be placed in */config/keys/sso.crt*.

## Marinus logging
Marinus has code to log to both Splunk and NewRelic. These are optional depending on whether the tools are relevant to your environment. For NewRelic support, enable it within the config/env.js file and enter your NewRelic configuration in the newrelic.js file. For Splunk support, the configuration parameters are specified in config/env.js. The code that configures the Splunk format and other properties is within config/config.js. If the web server is in *./node-src*, then the log files will be placed in *./logs* by default. This is specified in the *start.sh* file and the directory must exist in order for Marinus to run.

## NGINX
For a production deployment of Node, it is common to have an NGINX proxy relay requests to the Node.js server. Therefore, a simple nginx configuration is provided in the nginx_proxy folder of this git project. If you do not require an nginx proxy for your environment or you are doing local testing, then this step can be skipped.

## Testing
The Marinus web UI is primarily tested in the Chrome browser.
