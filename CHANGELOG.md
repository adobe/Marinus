# CHANGELOG

## February 5, 2019 
* PTR records are now added to the all_dns collection when RDNS records are identified in Sonar. 
* A few bug fixes and touch ups.

## February 4, 2019 (Certificate Transparency Upgrades & JobsManager)
* A Python 3 JobsManager class was created in order to remove redundancy in the code.
* The Python 2 versions of hash_based_upload and download_* were removed.
* A Python 3 X509 certificate parsing library was created which improves on the parsing that was previously done by hash_based_upload.py.
* The get_original_ct_logs Python 3 script was added as a replacement for the Python 2 download_{log} scripts. It is more performant over time than the Python 2 scripts because it only queries for new certificates that were added since the last run. The script removes the previous requirement for the Google Certificate Transparency project, it works with any Version 1 CT Log, and performs more thorough searching of zones than the previous scripts. Saving certificates to disk is now an optional choice.
* The new get_crt_sh script was created to query the crt.sh service for certificates across all Certificate Transparency logs.
