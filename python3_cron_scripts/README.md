# Marinus Python 3 Cron Scripts

## General overview
Marinus collects the majority of its data from common commercial and open source remote repositories such as Censys, Rapid7, Common Crawl, Certificate Transparency Logs, commercial integrations, and Google DNS over HTTPS. Marinus also supports pulling data from commercial infrastructure applications such as Infoblox, Azure DNS, AWS Route53, and UltraDNS. The scripts in this directory are responsible for obtaining the data from those sources and are the first step in getting Marinus up and running. The majority of the scripts are optional and you can choose which scripts are relevant based on the type of environment you have in your organization.  

All scripts need to run within some form of an environment. The current Marinus infrastructure at Adobe is quite robust and can serve as an example of running Marinus within a large organization. Smaller organizations and/or smaller deployments will not need this level of infrastructure in order to process the data. Experimentation and a little tuning will help you to determine the best way to deploy the scripts within your organization.

Let's assume that you are working for a complex organization with thousands of records. At Adobe, the processing is split into two groups. There is a remote environment for the scripts that require powerful machines and from which we can conduct remote scanning. There is an also a group of instances inside the internal network which runs the majority of scripts which don't require a lot of resources. A Mongo DB instance sits within both groups with the internal database acting as the single source of truth. The deployment is broken down as follows:

### External cloud environment
* One server with a large CPU and a 1.5TB drive for handling Censys data.
* Two servers for running the zgrab scripts. They are separated on different machines to split up the network traffic.
* One remote MongoDB server to cache the data until it can be pulled down by the primary database. This is fairly light weight and can exist on the Censys server.

### Internal environment
* A MongoDB that is the single source of truth
* One server for short running scripts (3 days or less)
* Five servers for the sonar scripts with 300GB partitions
* One server for the Certificate Transparency jobs with a 300GB partition
* One server for the common crawl graph job.
* One server for hosting the web site

The majority of the scripts are CPU-bound problems. Therefore, your performance will be gated by your CPU rather than RAM or disk speed. With the exception of the Certificate and Zgrab scripts, most of the scripts do not support multiple threads at this time so the jobs will not be spread across cores.

The Sonar, Censys, and Certificate transparency machines must have GBs of free disk space in order to download and then unzip the relevant data. In the case of the Censys data, the last measurement was around 250GB as an lz4 compressed file and a little over 1 TB when unpacked which means you need around 1.5 TB in order to download the compressed file and have space to create the decompressed with a margin of safety. This should be set up as a separate mounted partition from the core OS. By using a separate partition, you can ensure that the OS can continue run if the separate partition ever becomes full. The machines processing Sonar data require around 300GB free. If you use the older Common Crawl WARC files script, then it is 67.79TB of compressd data that is spread out into smaller 1.3 GB of compressed files. The Common Crawl graph script is much faster and needs less than 50GB of space.

## Mongo databases
The scripts assume that there are two MongoDB instances:
 
 * A primary instance that is hosted in an internal network. It is the authorative store for all data.
 * A remote database that lives in a remote cloud environment.
 
The remote database allows for scripts to be executed in a separate remote network. A few of the collections from the primary instance are mirrored to the remote database so that scripts have the relevant data for their tasks. The updated data is then copied back to the primary database when processing completes.

If you are able to run all of your scripts within a single environment, then the remote database is not necessary. Specifying the same connnection information for both databases within the connector.config file will force the scripts to use a single database. You will also not need to run the send_remote_server.py or download_from_remote_database.py scripts.

For better performance, you can add indexes on the collections. The following is a list of example MongoDB commands for creating indexes in order to improve the performance of Marinus. You only need to run the commands for collections that you use. For instance, if you do not use Infoblox, then you can skip all of the iblox_* commands:

db.getCollection('all_dns').createIndex({'fqdn': 1})
db.getCollection('all_dns').createIndex({'type': 1})
db.getCollection('all_dns').createIndex({'zone': 1})
db.getCollection('all_dns').createIndex({'value': 'hashed'})
db.getCollection('all_ips').createIndex({'ip': 1})
db.getCollection('censys').createIndex({'ip': 1})
db.getCollection('cert_graphs').createIndex({'zone': 1})
db.getCollection('cidr_graphs').createIndex({'zone': 1})
db.getCollection('ct_certs').createIndex({'fingerprint_sha256': 1})
db.getCollection('ct_certs').createIndex({'isExpired': 1})
db.getCollection('graphs_data').createIndex({'zone': 1})
db.getCollection('graphs_docs').createIndex({'zone': 1})
db.getCollection('graphs_links').createIndex({'zone': 1})
db.getCollection('iblox_a_records').createIndex({'_ref': 1})
db.getCollection('iblox_aaaa_records').createIndex({'_ref': 1})
db.getCollection('iblox_a_records').createIndex({'_ref': 1})
db.getCollection('iblox_cname_records').createIndex({'_ref': 1})
db.getCollection('iblox_extattr_records').createIndex({'_ref': 1})
db.getCollection('iblox_host_records').createIndex({'_ref': 1})
db.getCollection('iblox_mx_records').createIndex({'_ref': 1})
db.getCollection('iblox_txt_records').createIndex({'_ref': 1})
db.getCollection('ip_zones').createIndex({'zone': 1})
db.getCollection('ipv6_zones').createIndex({'zone': 1})
db.getCollection('jobs').createIndex({'job_name': 1})
db.getCollection('sonar_rdns').createIndex({'ip': 1})
db.getCollection('tpd_graphs').createIndex({'zone': 1})
db.getCollection('tpds').createIndex({'tld': 1})
db.getCollection('users').createIndex({'userid': 1})
db.getCollection('users').createIndex({'apiKey': 1})
db.getCollection('virustotal').createIndex({'zone': 1})
db.getCollection('whois').createIndex({'zone': 1})
db.getCollection('zgrab_443_data').createIndex({'domain': 1})
db.getCollection('zgrab_443_data').createIndex({'ip': 1})
db.getCollection('zgrab_80_data').createIndex({'domain': 1})
db.getCollection('zgrab_80_data').createIndex({'ip': 1})
db.getCollection('zgrab_port_data').createIndex({'ip': 1})
db.getCollection('zones').createIndex({'zone': 1})
db.getCollection('zones').createIndex({'status': 1})


## Set up
The scripts and the associated libs directory can be placed anywhere on an instance so long as it meets the following requirements:

* Python 3.x is installed with the libraries referenced in the requirements.txt file. The scripts assume that python is installed in /usr/bin/python3 but you can modify this at the top of the scripts.
* A connector.config file exists with the database connection information. The connector.config files also contain the credentials for any third-party services, such as VirusTotal.
* A configured mongoCA.pem file may be necessary if your database leverages TLS.

Once the requirements have been installed and the connector.config has the relevant database information, the setup.py script can be run to configure Marinus. Please see the GettingStarted.md file for further information on what is needed to configure Marinus.

## Running Time
The running time for the scripts will vary based on the number of root domains that are tracked and the CPU power of the server. Also, many of the scripts have a time.sleep() call in order to prevent the scripts from over taxing their dependencies. For instance, some third-party providers have limits on the number of requests that are allowed per day. If you have a small enough environment, then you may want to remove those sleep statements to increase the speed of the scripts. Please consult the respective third-party documentation on their rate-limiting policies. It is assumed that most scripts are run once a week.

## Crontab.cron
This is an example file that contains information on the order in which the scripts should be run. All of the scripts print out a starting time and an ending time so that you can see how long they will take to run in your specific environment. Once you know how long they take to run in your environment, you can adjust the crontab file accordingly. If you are spreading the scripts across multiple machines, it is possible for many of the scripts to run concurrently. You will need to run the scripts that collect zones (aka root domains) first. The scripts that peform the second pass on the cname records and those that create the graphs should be run at the end of the process. The rest of the scripts can be run anywhere in between. As your Marinus deployment reaches a steady state where scripts are regularly run, the order of the scripts will matter less.

## Sonar searches
The sonar scripts (get_data_by_cidr_unified, get_sonar_data_unified) each run daily. If the scripts detect that they are already running, then they will exit. Within Adobe's environment, it takes five machines to run these scripts because each script can be run in one of two modes (searching Sonar RDNS or searching Sonar DNS). The forward DNS runs are split across two machines since there are different files involved.

## Censys searches and Zgrab scripts
The get_censys_files script will download and unpack the Censys file. The search_censys_files script will search the downloaded file for the relevant zone relevant entries. It could technically be one script but there were certain advantages to keeping them separate. This script requires a commercial subscription to Censys.

The Censys project utilizes tools from the ZMap Project to collect data. The Marinus zgrab scripts allow you to collect data similar to Censys that can be used in conjunction or as an alternative to their services. The Marinus zgrab scripts can be used to collect data on ports 22, 25, 443, and 465. The zgrab_port_ip scripts will capture the handshake for these ports. The zgrab_http_domain and zgrab_http_ip scripts will record HTTP specific information from servers, such as HTTP headers, that can be used to more deeply measure and monitor web servers. These are currently based on the original zgrab scripts. Research is being done on how to port them to the new zgrab 2.0 project.

## Certificate transparency scripts
There are three options for downloading certificate transparency scripts within this directory. The first is get_original_ct_logs.py which is designed to talk directory to a single designated CT Log server. The first run of this script will be slow because it starts at the very first certificate in the log and crawls forward. Subsequent runs of the script are faster because it can start from the last matched index of the previous run. In terms of which logs to query, it is best to start with logs associated with the CAs that are used by your organization. Some Google CT log servers are frequently used as secondary logs. Certificates will be matched to your organization through comparisons against your configured zones and the SSL_Orgs specified in your config. A list of active logs are listed on https://crt.sh/monitored-logs. The logs that Marinus supports are defined in the libs3/X509Parser.py library.

The second option is a script for querying the crt.sh service called, "get_crt_sh.py". The crt.sh service is a unified database that represents most of the CT Log servers. This new script can both download identified certificates and extract any new domain names within the certificate. This is currently the only CT script to directly add new DNS names to the database. The script extract_ssl_names will identify DNS names from the certificates saved by the other scripts.

There is also a Python 3 script in this folder for querying the Facebook Graph API for relevant certificates if you have a Facebook Graph account. It is similar to the crt.sh service in that is a centralized database of multiple CT Logs.

## Common Crawl scripts
There are two scripts for parsing data from the Common Crawl project. One script is for processing WARC files from the Common Crawl database that is present in the Python 2 directory. Due to the large amount of resources necessary to parse the WARC files and its redundancy with other methods, maintanence on the script has not been maintained. It has been included as a reference for people who may want to dig deeper into that data set. However, it likely needs to be updated for any changes since it was last used over a year ago.

The second script is in the Python 3 directory and it parses the Common Crawl graph data. This requires far fewer resources and this script is currently acively maintained. The Common Crawl team only publish their graph data once a quarter. Therefore, the script needs to be manually updated with a new path and run once a new dataset becomes available.

## Infoblox, Azure, AWS Route53, and UltraDNS scripts
These scripts are useful for people that internally leverage these commercial tools as part of their DNS infrastructure. Pulling data from your internal DNS infrastructure will allow you to compare and contrast with what the Internet sees. This comparison could allow you to find shadow IT, dead DNS records, or forgotten systems. The internal information can also useful when you identify an issue and you are trying to track down where in the organization a host lives.

The Infoblox scripts are split into separate searches and have several sleep commands. The sleep commands are due to limitations noticed when leveraging their API at speed. The extattr scripts are only necessary if your organization uses the extattrs property to record additional information. Within Marinus, the UI will search these properties looking for fields that contain the word, "owner."

## get_passivetotal_data.py
PassiveTotal's commercial services include an API to search their database of whois records. If you have a PassiveTotal account, you can use this to monitor for when new domains are registered.

## get_virustotal_data.py
Virustotal's APIs provide information on the domains that show up in their malware analysis. These APIs are available to both free and paid customers. This script will check the VirusTotal APIs to see whether your domains are appearing in any malware campaigns.

## Extract_vt, extract_ssl, marinus_dns, and sonar_round_two
Domains which are identified in VirusTotal searches, TLS certificate CN fields, and sonar files are immediately recorded without further analysis. However, it may be the case that if you do a DNS lookup on the domains from these sources, then it will be a CNAME reference to another tracked domain name. These scripts go through and perform recursive DNS lookups on data from these sources in order to find additional references. The scripts use the Google HTTPS over DNS service because Marinus wants to ensure that the results are not biased by internal DNS servers.

## Graph creation scripts
These scripts will take the data is available and create d3.js data models that will be used by the UI to provide graph summaries of the networks, certificates, and third-party services. These scripts should be run at the end of the process when the most data is available.

## remove_expired_entries and remove_fixed_dead_dns_records
Marinus is not intended to be a historical record of your database. The remove_expired_entries script will remove any entries that haven't been updated within two months. Prior to expiring the records, Marinus will use Google HTTPS-over-DNS to validate whether the record still exists. If the record stills exists but is no longer monitored by the third-party, then Marinus will save the record under its name. This script can be run daily. Marinus also tracks "dead DNS" records which are records that point to non-existent resources. This script will remove a host from the dead DNS list when it is corrected.

## get_splunk_data.py
This script is unique in that it is just a template for fetching data from Splunk. For organizations that use Splunk, Splunk can be a large source of internal information that could potentially be correlated with Marinus data. However, it is not possible to write a general purpose Splunk script since each organization would have its own logging format and indexes. Therefore, this script is a template that shows how to use Splunk libraries in Marinus to fetch data. It is up to the user to fill in the rest of the code for handling the data and storing it in the Splunk collection and/or via the DNSManager class. 

## upload_collection_to_splunk.py
Some organizations may want to be able to push their Marinus data into Splunk. This could allow an organization to cross-reference the data with other Splunk sources. It may also be easier for an organization to create customized dashboards of the data using Splunk dashboards. This script will upload HTTP Headers recorded from the web sites analyzed by Zgrab. However, it could easily be altered to upload whatever data that is needed by the organization. The data is currently uploaded in a JSON ("_json") format.

## libs3
The libs3 directory contains Python 3 classes for interacting with the databases and third-party services. The MongoConnector library is necessary for any script that talks to the main database (which is most of them). Many of the other libraries are necessary for specific connections as specified by their name.

## MongoCA.pem
This file is necessary if your Mongo Database uses TLS based on its own certificate authority. If you use a MongoDB with TLS (and you should :-) ), then you will need to replace this file your own MongoCA.pem file that contains the public CA certificate for your database.

## MongoDB jobs table
Most of the scripts record their status in a *jobs* collection within MongoDB. The JobsManager can create the necessary entries in the collection. If it is useful, the setup.py script can also pre-populate the jobs collection with all of the known jobs. 

## Requirements.txt
This file contains the Python libraries used by the various scripts. Run 'pip install -r requirements.txt' in order to install of the required dependencies.

## Logging
All of the Python scripts will use print to output their start and stop times. In addition, the scripts take advantage of Python logging. The format of the output is defined in the libs3/LoggingUtil.py library. You can manually edit a given Python script to override the default log level or provide a config file location in the LoggingUtil.create_log() call. If a manual override is not done, then the LoggingUtil class will look for a 'logging.conf' file in the parent folder. The conf files should follow the Python logging YAML format. If a conf file is not found, then it will use the default settings specified within the class.
