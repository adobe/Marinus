# CHANGELOG

## February 7, 2019
* Modified the get_original_ct_logs, get_crt_sh, and download_facebook_certs scripts to start recording the zones associated with the certificate. This will make it easier to search the ct_certs collection for root domains.


## February 6, 2019
* The get_owasp_amass script adds support to import DNS data from the OWASP Amass tool. Amass is similar to Marinus and supports a few more data sources than Marinus. Rather than duplicating existing Amass functionality, Marinus now supports running and importing the results from Amass searches. The OWASP Amass GitHub page provides information on how to install the tool: https://github.com/OWASP/Amass/
* In order to decrease the chances of script failures due to database connection issues, support was added to handle pymongo AutoReconnect exceptions for the find queries in a few selected libraries. As Marinus progresses, this will expand to a more complete implementation.


## February 5, 2019
* PTR records are now added to the all_dns collection when RDNS records are identified in Sonar.
* A few bug fixes and touch ups.


## February 4, 2019
* The Python 2 versions of hash_based_upload and download_* were removed.
* A Python 3 X509 certificate parser was added to separate the certificate parsing from the hash_based_upload script.
* The get_original_ct_logs Python 3 script was added as a replacement for the Python 2 download_* and hash_based_upload scripts. It is more performant over time than the Python 2 scripts because it only queries new certs since the last run. The script does not require the Google Certificate Transparency project, it works with any Version 1 CT Log, and performs more thorough searching of zones. Saving of certificates to disk is now optional.
* A get_crt_sh script was created to allow for querying the crt.sh service for additional certificates. Saving certificates to disk is optional.
* A Python 3 Jobs Manager library was created to standardize job tracking.
