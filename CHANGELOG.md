# CHANGELOG

## February 6, 2019
* Added support to import data from the OWASP Amass tool. Amass is similar to Marinus and supports a few more sources than what Marinus currently supports. Rather than reproduce the Amass functionality, Marinus supports importing the results from the Amass tool. For more information, see: https://github.com/OWASP/Amass/
* In order to decrease the chance of script failures due to database connection issues, support was added to handle pymongo AutoReconnect exceptions for the find queries in a few selected libraries. As Marinus progresses, this will expand to a more complete implementation.


## February 5, 2019
* PTR records are now added to the all_dns collection when RDNS records are identified in Sonar.
* A few bug fixes and touch ups.


## February 4, 2019
* The Python 2 versions of hash_based_upload and download_* were removed.
* A Python 3 X509 certificate parser was added to separate the certificate parsing from the hash_based_upload script.
* The get_original_ct_logs Python 3 script was added as a replacement for the Python 2 download_* and hash_based_upload scripts. It is more performant over time than the Python 2 scripts because it only queries new certs since the last run. The script does not require the Google Certificate Transparency project, it works with any Version 1 CT Log, and performs more thorough searching of zones. Saving of certificates to disk is now optional.
* A script was created to allow for querying the crt.sh service for additional certificates. Saving certificates to disk is optional.
* A Python 3 Jobs Manager library was created to standardize job tracking. Migration of existing scripts to the new library will happen over time.
