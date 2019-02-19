# Getting Started

## Minimum requirements
To get started with Marinus, you must first set up a MongoDB database to store all of your information. Marinus is currently tested with the 3.x versions. A Python script can create the necessary collections and pre-populate some of the data. The location and authentication for the database must be specified in the connector.config file. Some Marinus scripts do refer to a remote Mongo database. This is for complex set ups where multiple databases are necessary. If you do not plan to use multiple mongo databases, then you can specify the same connection information in both sections.

NOTE: To use these scripts, you have should have locale set to en_US.UTF-8 within your shell.

## Baseline information
Marinus will require some initial hints as to what will be tracked. The information that is needed to start the process include:

DNS-Admin emails: Marinus will search through whois records by examining the contact information for the registered domain. Mairnus compares the email addresses of the whois records with the DNS_Admins listed within the configuration. This data is used by the get_passivetotal_data.py script and the commercial PassiveTotal service. If you already know the root domains that will be tracked, then this is not required. You can manually add domains via the setup.py script or the Node JS UI.

Whois Organizations: Another method to search Whois records with PassiveTotal is the organization associated with the Whois registration. Searching by organization value can be riskier if your company's name is similar to other businesses. This value is only necessary if you plan to use the commercial PassiveTotal services.

TLS Organizations: Some TLS certificate searches are done based on the Organization field defined within the distinguished name of the certificate. The Censys scripts can check the IP based records to see if the TLS certificate associated with the IP belongs to one these organizations. It is way to identify IPs that may be associated with the organization in addition to CIDR checks. These values will also be used in the certificate transparency log searches to identify relevant certificates.

Root domains: The root domains (example.org, example.net, example.org.uk, etc.) that will be tracked can be manually entered via the setup script as described below and web UI admin interface. If the get_passivetotal_data.py script is not used, then it is necessary to manually entering the root domains. The web UI and setup script should not be used to enter fully qualified domain names (e.g. www.example.org). Marinus will discover the FQDNs on its own.

CIDRs: For searches based on IPs (such as Censys) or reverse DNS lookups, Marinus will need any CIDRs that are owned by the organization. These should only be static IP ranges that are directly allocated to the company and should not be temporary IPs issued by cloud services. The IP addresses can be entered via the web UI.

## Dependencies
Marinus has been tested with Node version 8, Python 3.6, and MongoDB 3.x versions. It was tested on Ubuntu Linux hosts but it should be portable to other environments. The necessary Python libraries that are required are listed in the requirements.txt file. The necessary NPM libraries are specified in the packages.json file.

## Crypotographic keys
The web server will require a TLS certificate and key in order to support HTTPS connections. These keys should be placed in web_server/config/keys/server.key and web_server/config/keys/server.crt.

If you plan to use the nginx server as a front end, it will also need TLS certificates. In this deployment, the nginx server would need certificates trusted by the browser and the Node.js could use a private CA. 

If SSO will be used, then the key associated with the SSO provider can be placed in web_server/config/keys/sso.crt

If TLS is going to be used for the MongoDB, then the connector.config "mongo.ca_cert:" value will need to point to the public CA certificate that is authoritative for the MongoDB.

## NGINX
For a production deployment of Node, it is common to have an NGINX proxy relay requests to the NodeJS server. Therefore, a simple nginx configuration is provided. If you do not require an nginx proxy for your environment or you are doing local testing, then this can be skipped.

## Directory structure
The web server and Python scripts do not need to live on the same host. For performance reasons, it is best if they are on separate hosts since the Python scripts frequently use 100% of a CPU core. The Python scripts can be spread across as many machines as is necessary for the environment. The web server is fairly lightweight but usage will vary.

## Database installation
To set up the database, you can do a simple, "apt-get install mongodb." The default installation of mongodb requires no passwords and accepts connections over plaintext. Marinus will work with the default installation of MongoDB.

If you plan to enable authentication (https://docs.mongodb.com/manual/tutorial/enable-authentication/), then you will need to create the database (https://docs.mongodb.com/manual/core/databases-and-collections/) so that you can assign permissions to the database. Marinus currently only supports the option of using username and password authentication. If you are not assigning roles and permissions to the database, then the Marinus setup.py script can create the database on its own.

If your database supports TLS connections, then Marinus supports specifying a CA certificate for the TLS connection. For NodeJS, you can specify the location of the CA certificate in web_server/config/env.js file in the "mongodbSSLCA" parameter. For the Python code, you can specify the location of the CA cert in the "ca_cert" parameter of the "MongoDB" and "RemoteMongoDB" sections.

Replica sets can be specified as follows in the env.js file as follows:
   mongodb://DEV_DATABASE_USERNAME:DEV_DATABASE_PASSWORD@replica-1.example.org:27021,replica-2.example.org:27021/DOMAINS?replicaSet=REPLICA_SET_NAME

Connector.config:
   mongo.host: replica-1.example.org:27021,replica-2.example.org:27021

The Marinus Python scripts can support a local and a remote MongoDB where the data is copied from the remote database and into the local database. The use of two databases was the result of a limitation where Marinus was originally deployed during development. If your deployment will only a single database, then you can specify the same values for both the local and remote sections of the connector.config file.

The configuration of the collections of the database is defined in the next section.

## Python script installations

For each server where you plan to run a Python script, copy the Python 3 folder to the machine and perform the following steps:
 
   apt-get install python3-pip
   pip3 install -r requirements.txt

Due to speed and disk space restraints, it is likely that you will need to spread the work across multiple machines. At a mininum you would need to copy the script that you want to run (e.g. get_sonar_data_unified.py), the connector.config file, the MongoDB CA certificate (if used), and the libs3 directory onto each machine.

(Mandatory) Once you have a Python machine set up, there is a one-time task to configure the database with the information for your organization. Setup connector.config with the MongoDB connection information for your host. The very first Python3 command that you will need to run is:

./setup.py --create_collections

This will initialize the database and a few collections. You can verify this by connecting to the Mongodb. If you are not experienced with MongoDB command lines, then you can use Robo3T as a GUI based tool: https://robomongo.org/

(Required) The vast majority of Marinus logic is based around your organization's root domains (e.g. "example.org"). These are referred to as zones. To add your first few zones to the database you can run:

./setup.py --add_zone example.org

(Optional) If your organization has IPv4 or IPv6 address spaces reserved through organizations such as ARIN, you can inform Marinus about the CIDRs that you own. The data is used with the Censys and Rapid 7 Sonar/Open Data scripts to identify hosts via reverse DNS. This functionality should not be used to add temporarily leased IP addresses or internal IP ranges. The use of internal networks below is just to avoid using someone's real production network as an example. To add a CIDR to Marinus, use one of the following comands:

./setup.py add_IPv4_network "10.0.0.0/8"
./setup.py add_IPv6_network "fd00::/8"

(Optional) In addition, Marinus does searches based on information from Whois records. One search of the whois records is performed by searching whois databases for the domain's email contacts. To add the DNS contact information to Marinus, run the following command:

./setup.py  --add_dns_admin "admin@example.org"

(Optional) Similarly, Marinus can search the database of WHOIS information based on the organization that registered the domain. This is riskier since many organizations have similar names. Therefore, be sure to double check the results that you obtain. This information is also used by the mark_expired script to determine if a domain has been transferred to a third-party. To add an organization for whois searches, run the following command:

./setup.py --add_whois_org "Acme, Inc."

(Optional) Many WHOIS records no longer show the contact information for a domain name which makes it difficult to determine ownership. One indirect way to confirm ownership of the domain is to examine the registered name servers within the WHOIS record. The mark_expired script can try to match the name server values to your organization to confirm that you still control the domain even if the ownership information has been redacted within the WHOIS record. NOTE: All name server values are converted to lowercase prior to comparison. Therefore, it is only necessary to provide lowercase versions of the DNS server names. To add name servers that relate to your WHOIS records, run the following command:

./setup.py --add_whois_name_server "dns1.example.org"

(Optional) When Marinus is searching either the certificate transparency logs or Censys data for relevant IP records, Marinus can check whether the TLS certificate is associated with the organization by checking the "O=" value in the distinguished name. Setting these values is strongly encouraged if you plan to use the certificate transparency scripts. To inform Marinus regarding your TLS certificate orgs, use the following command:

./setup.py --add_tls_org "Acme, Inc."

(Optional) If you plan to use SSO with the Marinus UI, you can add users with the setup script with the folloiwng command. A password is not specified since the SSO provider would handle authentication:

./setup.py --add_user --username user1

(Optional) Users that can modify existing zones through the Marinus UI are considered data_admins. Users that can add zones and additional users are part of the "admin" group. You can make a user a member of one of these two groups using the following command:

./setup.py --add_user_to_group --username user1 --group admin

(Optional) Groups can have their own admins. This was put in place to support more complicated groups in the future. For now, it does nothing. Therefore, setup.py supports listing admins for groups but the Marinus UI does not currently use the data.

./setup.py --add_group_admin --username user1 --group admin

## Running the scripts
Once the database is configured with your intiial information, then you can proceed to collecting records on the data using the Python scripts. Please see the crontab.cron file for information on the order in which to run the scripts. Each Python script also includes a few notes at the top of the file for further information.

The scripts can be run at whatever frequency fits your organization. Within Adobe's environment, the scripts are typically run once a week. For scripts that take longer than a week to run, they are set to restart after each run. Many of the longer running scripts will check to see if they are already running before starting. This allows you to start them once a day in crontab and ensure that they will only run after the last process has completed.

After you have successfully run a few scripts and have some initial data populated in the collections, you can then start up the web server in order to view the data. Please see the README file in the web_server directory for more information.

