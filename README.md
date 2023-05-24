# olca-license

A licensing framework for openLCA based on the SSL/TLS communication protocol and symmetric encryption.

## Create the Certificate Authority (CA)

 - Create the Root CA - that has to later be stored offline - with `create_root_ca.sh`.
 - Create the server CA (Nexus) subordinated from the Root CA `create_nexus_ca.sh`.

## Check the information an issued certificate

```bash
openssl x509 -text -in issued-cert.crt -noout
```
