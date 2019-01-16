# NGINX configuration
It is a common practice by many in the web community to place an nginx reverse proxy in front of a Node.js server. This directory contains the relevant configuration files for a front-end nginx server. This is a minimal configuration and it has not been optimized for serving static content.

## Getting started
You must edit the conf.d/default.conf file to contain the references to your domains and certificates. The macro YOUR_PUBLIC_DOMAIN_NAME should be replaced with the domain that Marinus users will use to visit the site. This field should match the common name in your nginx TLS certificates. The nginx TLS certificates will be the ones that are trusted by the web browser. It is assumed by the configuration file that the public certificate is located in /etc/ssl/certs/server.crt and that the private key is located in /etc/ssl/keys/server.key.

The macro YOUR_LOCAL_DOMAIN_NAME should be an internal reference to the local Node.js server. The value should match the domain used by the certificates from the NodeJS TLS configuration. Assuming that the Node.js server is using certificates from an internal CA, the public CA certificates for the local Node.js server can be placed in /etc/ssl/certs/combined_private_ca.pem.

## More information
For more information on using nginx with NodeJS and why you might need it for your deployment, please see: https://www.nginx.com/blog/5-performance-tips-for-node-js-applications/
