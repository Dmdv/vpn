#!/bin/bash

# Create directories
mkdir -p certs
cd certs

# Generate CA private key and certificate
openssl genpkey -algorithm RSA -out ca.key -pkeyopt rsa_keygen_bits:4096
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 -out ca.crt \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=VPN Root CA"

# Generate server private key
openssl genpkey -algorithm RSA -out server.key -pkeyopt rsa_keygen_bits:2048

# Generate server CSR
openssl req -new -key server.key -out server.csr \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=vpn.example.com"

# Generate server certificate
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out server.crt -days 365 -sha256 -extensions v3_req \
    -extfile <(echo -e "[v3_req]\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth")

# Set permissions
chmod 600 *.key
chmod 644 *.crt *.csr

echo "Certificates generated successfully in ./certs directory:"
ls -l

# Cleanup
rm server.csr ca.srl 