use:

openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes

to generate a new key and certificate.

use:

openssl req -new -nodes -newkey rsa:2048 -keyout key.pem -out mycsr.csr -days 365

to generate new key and certificate signing request.

use:

openssl req -new -x509 -extensions v3_ca -key key.pem -out cert.pem -days 3650

to generate self signed certificate from private key.