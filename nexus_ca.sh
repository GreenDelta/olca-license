#!/bin/sh

CURRENT=$(pwd)

# Create the Nexus CA subordinated from the root CA.

printf "\nCreating the Nexus CA directory structure..."
rm -rf nexus-ca
mkdir nexus-ca
cp config/nexus-ca.conf nexus-ca/nexus-ca.conf
cd nexus-ca || exit 0
mkdir certs db private
chmod 700 private
touch db/index
openssl rand -hex 16 > db/serial
echo 1001 > db/crlnumber

# certs: certificate storage
# db: certificate database and CRL serial numbers
# private: store the private keys

printf "\nCreating the Nexus CA private key and CSR..."
openssl req -new -nodes -config nexus-ca.conf -out nexus-ca.csr \
 -keyout private/nexus-ca.key

printf "\nCreating the Nexus CA certificate..."
cd "$CURRENT"/root-ca || exit 0
openssl ca -batch -config root-ca.conf -in "$CURRENT"/nexus-ca/nexus-ca.csr \
 -out "$CURRENT"/nexus-ca/nexus-ca.crt -extensions sub_ca_ext
