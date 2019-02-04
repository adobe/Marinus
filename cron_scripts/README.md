# Marinus Python 2 Cron Scripts

## General overview
The original version of Marinus was written using Python 2.x. With the upcoming EOL for Python 2, the majority of the code has been rewritten for Python 3.6. These deprecated files are being kept as a reference in case work resumes on them in the future. All currently maintained code is in the python3_cron_scripts folder.

## Certificate Transparency
The certificate transparency scripts have been migrated to Python 3 directory. Please see the CHANGELOG in the root directory.

## Common_Crawl directory
Common Crawl provides two types of data. The first type of data is graph data. The script for graph data has been moved to the Python 3 directory. The second type of data that Common Crawl provides is WARC data files which include the response from the server. This script is deprecated since the data was considered less useful at the time given the resources required to run it. However, the script for that work is still kept in this directory as a historical reference in case the efforts are resumed in the future.

## libs2
The libs2 directory contains classes for interacting with the databases and third-party services. The MongoConnector library is necessary for interactions with the primary database. The other libraries are necessary for specific connections as specified by their name.

## MongoCA.pem
The connection to the remote MongoDB instance is conducted over SSL. The MongoCA.pem file is the public certificate for the certificate authority used to establish the SSL connection.

## Requirements.txt
This file contains the Python libraries used by the various scripts.
