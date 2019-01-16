# Marinus Python 2 Cron Scripts

## General overview
The original version of Marinus was written using Python 2.x. With the upcoming EOL for Python 2, the majority of the code has been rewritten for Python 3.6. This directory currently contains the scripts that have yet to be converted. It also contains a few older scripts for work that have been deprecated. The deprecated files are being kept as a reference in case work resumes on them in the future.

## Certificate transparency scripts
The CT scripts go through their respective CT server (download_aviator, download_digicert, etc.) downloading certificates associated with the tracked SSL_Orgs configured by setup.py. Once all of the downloads are complete, the hash_based_upload script will ensure that the new, unique certificates found in the searches are uploaded. These scripts are actively maintained. They have not been ported to Python 3.x due to their dependency on Python 2.x certificate transparency github project. In addition, the example CT scripts from the CT github project are not efficient for this purpose since they don't retain a memory of where they left off and will rescan the entire log. There are future plans to address these issues.

The CT scripts use SSL_Orgs instead of zones due to the large number of comparisons that would need to be performed. That said, you can set a primary_domain variable within the scripts to check for certificates associated with a specific zone. It is recommended that you set this parameter within the scripts.

The selection of the Aviator and DigiCert CT logs are arbitrary examples. You may get better results by converting these scripts to use the CT logs that are managed by your certificate provider. To use a different CT Log, make your own copy of the Python script. You can then modify the new file by changing the HTTPS url in the scanner.scan_log call to reflect the URL of your certificate provider. You will also want to change the output folder to reflect a unique directory for your provider. Finally, you will want to add that path to the hash_based_upload script so that the results are uploaded.

The scripts in this directory all assume that they are in the path of "/mnt/workspace". You may need to adjust those properties for your environment. The scripts also assume that you have the Google Certificate Transparency code (https://github.com/google/certificate-transparency/) installed in /mnt/workspace/certificate-transparency/.

It is planned to convert these scripts to accept dynamic parameters when they are converted to Python 3.

## Common_Crawl directory
Common Crawl provides two types of data. The first type of data is graph data. The script for graph data has been moved to the Python 3 directory. The second type of data that Common Crawl provides is WARC data files which include the response from the server. This script is deprecated since the data was considered less useful at the time given the resources required to run it. However, the script for that work is still kept in this directory as a historical reference in case the efforts are resumed in the future. 

## libs2 
The libs2 directory contains classes for interacting with the databases and third-party services. The MongoConnector library is necessary for interactions with the primary database. The other libraries are necessary for specific connections as specified by their name. 

## MongoCA.pem
The connection to the remote MongoDB instance is conducted over SSL. The MongoCA.pem file is the public certificate for the certificate authority used to establish the SSL connection.

## Requirements.txt
This file contains the Python libraries used by the various scripts.
