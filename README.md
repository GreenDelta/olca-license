# olca-license

A licensing framework for openLCA that can certify, sign and encrypt data library.

## Create the Certificate Authority (CA)

- Create the Root CA - that has to later be stored offline - with `root_ca.sh`.
- Create the server CA (Nexus) subordinated from the Root CA with
  `nexus_ca.sh` and store the `nexus-ca` folder into the server
  `/etc/ssl/certs/` directory.

## Certify a data library

Once the certificate authority is created and stored in the server, one can
start certifying data libraries.

First, create a `Licensor` instance with the CA `File` folder as an input:

```java
var ca = new File("path/to/the/certificate/authority");
var licensor = Licensor.getInstance(ca);
```

Then, certify the library by inputting the `ZipInputStream` of the compressed
raw library, the destination `ZipOutputStream`, the password provided by the
user of the library and the `CertificateInfo` object holding the start and
expiration date and the subject and issuer information:

```java
try (var output = new ZipOutputStream(new FileOutputStream(library))) {
    licensor.license(input, output, PASSWORD_LIB, info);
}
```

## Check the information of an issued certificate

An X.509 certificate can be stored with respect with the industry standard as a
key encoded in `Base64`:

```bash
-----BEGIN CERTIFICATE-----
<certificate key>
-----END CERTIFICATE-----
```

This certificate can be converted in a more readable format by using the
following command:

```bash
openssl x509 -text -in issued-cert.crt -noout
```
