# Marinus
Marinus is a project to track an organization's Internet-facing footprint from the perspective of a third-party. Essentially, what can someone piece together about an organization's network based on publicly available information? That data can then be compared with data from internal sources in order to answer the follow-up question, "What does the Internet know about our organization's network that we don't?" The information that Marinus collects can be used to create network maps, identify shadow IT or legacy infrastructure, and track TLS best practices across your entire company. When a vulnerability arises with a piece of third-party technology or third-party service, engineers can search the Marinus data for usage of that third-party within the organization. Engineers can also feed the lists of collected hosts into their existing security scanning automation to achieve more complete coverage.

For clarity, Marinus is not designed or intended to track internal, private networks. Marinus can leverage a few internal DNS resources to supplement its findings. However, this is to assist in either identifying internal owners or for comparisons against the external findings. The internal references are not considered authoritative since they often have legacy information that hasn't been cleaned up or they are potentially biased is some manner. If Marinus has a reference to internal resource, then it is most likely because Marinus found that information in a public record.

Since Marinus collects data from third-parties, it does not provide a snapshot of the network in real-time. Instead, Marinus periodically retrieves updated information from the third-party sources. Marinus is also not intended to act as a historical record of the network over time.

Marinus is able to collect a wide-variety of information from third-party sources. Once the root domains (e.g. example.org) are entered into the system, Marinus starts by collecting DNS information. DNS is the underpinning of the Internet and is often used for security controls like SPF and DKIM. Sources like Censys or the Marinux zgrab scripts will provide the handshake information from connections to services such as SSH, SMTP, HTTP, and HTTPS. In addition, Marinus can also check certificate transparency logs for additional TLS information. Finally, Marinus can search services such as VirusTotal for any references to the root domains in malware records. These combine to create a database of information that can be dynamically searched in order to ensure security best practices, respond quickly to incidents, and improve security automation and processes within the organization. Having an automatically-updated, company-wide database of an organization's external footprint can save a centralized security team numerous phone calls and emails. In addition, it can provide a view of the network without the need to scan it yourself.

## What is included in this project?
Marinus is comprised of a collection of Python scripts which collect the information from the third-party resources and store it in the database. The data can be accessed through a web UI or via REST APIs provided by a Node.js web server. A nginx server acts as a proxy into the Node.js web services.

This repository stores four folders relevant to Marinus:
  * *web_server*: The Node.js web server which provides the GUI and the REST APIs.
  * *cron_scripts*: A small collection of Python 2.x scripts which still require legacy libraries.
  * *python3_cron_scripts*: The Python 3.x scripts which retrieve and parse the majority of data.
  * *nginx_proxy*: The nginx configuration for the optional reverse proxy in front of the Node.js server.

## The cron scripts
The Python 2.x and Python 3.x scripts are responsible for talking to various third-party services and extracting out the relavent data. They can be automated to run on a regular basis using the Unix cron daemon or a similar scheduler. The python3_cron_scripts folder contains the Marinus setup script and the majority of the scripts for collecting Marinus information. The cron_scripts folder contains a small number of Python 2.x scripts that are still dependent on Python 2.x libraries.

The cron scripts are not usable when they are first checked out of git. The *connector.config* file must be filled in with the relevent credentials. Most importantly, the scripts will need a MongoDB 4.x instance to store the collected data. Running the scripts is the first step in getting Marinus operational since nothing else can be done without data.

It is not necessary to run all of the Python scripts in order for Marinus to be usable. The majority of the scripts are optional and you can choose which scripts are relevant based on the type of environment you have in your organization.

Please see the README.md and GettingStarted.md files in the python3_cron_scripts folder for more details.

## The web server
The Node.js web provides the browser interface for manual searches, statistics, and some example reports for how Marinus data can be useful. The web server also provides REST APIs for automated queries. Marinus uses Swagger for API documentation and testing. In production mode, the web server is able to use your single-sign-on provider for authentication using passport.js security strategies. Advanced users are able to extend the web interface through their own custom code.

The web server cannot run immediately after a git check out. There are several keys and credentials which must first be entered in the env.js file. Please see the README.md file in the web_server folder for details on configuring the web server.

## The nginx proxy
It is a common practice to place an nginx reverse proxy in front of a Node.js deployment. This directory provides a minimual nginx configuration for organizations that want to take this approach. The use of the nginx proxy is optional.

## Project updates
The Marinus project does not follow a waterfall release model. New features and scripts are added as they become available. Users should track the CHANGELOG to see what has been improved since their last clone.

## Marinus development
Marinus is an open-source project and code contributions are welcome. Please create a GitHub issue before starting to author code so that we can come to an agreement on the best approach before coding. Information on how to contribute are in the CONTRIBUTING.md, PULL_REQUEST_TEMPLATE, and ISSUE_TEMPLATE.
 
## Author
The original Marinus project was started by Peleus Uhley. Contributors include Mayank Goyal and Bhumika Singhal.
