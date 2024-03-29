#!/bin/sh

# Create a Root CA

printf "\nCreating the Root CA directory structure..."
rm -rf root-ca
mkdir root-ca
cp config/root-ca.conf root-ca/root-ca.conf
pwd
cd root-ca || exit 0
pwd
mkdir certs db private
chmod 700 private
touch db/index
openssl rand -hex 16 >db/serial
echo 1001 >db/crlnumber

# certs: certificate storage
# db: certificate database and CRL serial numbers
# private: store the private keys

printf "\nCreate the private key and the CSR...\n"
openssl req -new -nodes -config root-ca.conf -out root-ca.csr \
  -keyout private/root-ca.key

printf "\nCreate the self-signed certificate...\n"
openssl ca -batch -selfsign -config root-ca.conf -in root-ca.csr -out root-ca.crt \
  -extensions ca_ext
