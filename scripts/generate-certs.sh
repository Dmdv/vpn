#!/bin/bash

set -e  # Exit on error

# Default values
CERT_DIR="certs"
BACKUP_DIR="certs/backup"
CA_BITS=4096
SERVER_BITS=2048
CLIENT_BITS=2048
DAYS_CA=3650
DAYS_CERT=365
SERVER_CN="vpn.example.com"
CLIENT_CN="client"

# Create directories
mkdir -p "$CERT_DIR"
mkdir -p "$BACKUP_DIR"

# Backup existing certificates
if [ -f "$CERT_DIR/server.crt" ]; then
    echo "Backing up existing certificates..."
    timestamp=$(date +%Y%m%d_%H%M%S)
    mkdir -p "$BACKUP_DIR/$timestamp"
    cp "$CERT_DIR"/*.{key,crt} "$BACKUP_DIR/$timestamp/" 2>/dev/null || true
fi

cd "$CERT_DIR"

echo "Generating certificates..."

# Generate CA private key and certificate
echo "Generating CA key and certificate..."
openssl genpkey -algorithm RSA -out ca.key -pkeyopt rsa_keygen_bits:$CA_BITS
openssl req -x509 -new -nodes -key ca.key -sha256 -days $DAYS_CA -out ca.crt \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=VPN Root CA"

# Generate server private key
echo "Generating server key..."
openssl genpkey -algorithm RSA -out server.key -pkeyopt rsa_keygen_bits:$SERVER_BITS

# Generate server CSR
echo "Generating server CSR..."
openssl req -new -key server.key -out server.csr \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=$SERVER_CN"

# Generate server certificate
echo "Generating server certificate..."
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out server.crt -days $DAYS_CERT -sha256 -extensions v3_req \
    -extfile <(echo -e "[v3_req]\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth")

# Generate client key and certificate
echo "Generating client key and certificate..."
openssl genpkey -algorithm RSA -out client.key -pkeyopt rsa_keygen_bits:$CLIENT_BITS
openssl req -new -key client.key -out client.csr \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=$CLIENT_CN"
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out client.crt -days $DAYS_CERT -sha256 -extensions v3_req \
    -extfile <(echo -e "[v3_req]\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=clientAuth")

# Generate Diffie-Hellman parameters for perfect forward secrecy
echo "Generating DH parameters (this may take a while)..."
openssl dhparam -out dhparams.pem 2048

# Set permissions
echo "Setting proper permissions..."
chmod 600 *.key dhparams.pem
chmod 644 *.crt *.csr

echo "Certificates generated successfully in ./$CERT_DIR directory:"
ls -l

# Cleanup
rm *.csr *.srl

echo "
Generated files:
- ca.key: Certificate Authority private key
- ca.crt: Certificate Authority certificate
- server.key: Server private key
- server.crt: Server certificate
- client.key: Client private key
- client.crt: Client certificate
- dhparams.pem: Diffie-Hellman parameters

Keep all .key files secure and never share them!" 