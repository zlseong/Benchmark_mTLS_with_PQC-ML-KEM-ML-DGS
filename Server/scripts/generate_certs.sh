#!/bin/bash
# MQTT Broker Certificate Generation Script
# Generates CA, server, and example client certificates for all supported algorithms

set -e

# Configuration
SERVER_IP="${1:-localhost}"
CERT_DIR="${2:-./certs}"
OPENSSL="${OPENSSL:-/usr/local/ssl/bin/openssl}"
VALIDITY_DAYS=365
CA_VALIDITY_DAYS=3650

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== MQTT Broker Certificate Generation ===${NC}"
echo "Server IP: $SERVER_IP"
echo "Certificate Directory: $CERT_DIR"
echo "OpenSSL: $OPENSSL"
echo

# Create certificate directory
mkdir -p "$CERT_DIR"
cd "$CERT_DIR"

# Verify OpenSSL version
OPENSSL_VERSION=$($OPENSSL version | awk '{print $2}')
echo -e "${YELLOW}OpenSSL Version: $OPENSSL_VERSION${NC}"
if [[ ! "$OPENSSL_VERSION" =~ ^3\.[56]\. ]]; then
    echo -e "${RED}Warning: OpenSSL 3.5+ required for ML-KEM/ML-DSA support${NC}"
fi

# =============================================================================
# Generate SAN Configuration
# =============================================================================
echo -e "\n${GREEN}[1/5] Creating SAN configuration...${NC}"
cat > san.cnf << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req

[req_distinguished_name]

[v3_req]
subjectAltName = @alt_names

[alt_names]
IP.1 = ${SERVER_IP}
DNS.1 = localhost
IP.2 = 127.0.0.1
EOF

# =============================================================================
# 1. ECDSA P-256 Certificates
# =============================================================================
echo -e "\n${GREEN}[2/5] Generating ECDSA P-256 certificates...${NC}"

# CA
$OPENSSL ecparam -genkey -name prime256v1 -out ca_key.pem
$OPENSSL req -new -x509 -key ca_key.pem -out ca_cert.pem -days $CA_VALIDITY_DAYS \
    -subj "/C=US/O=Example/CN=TestCA-ECDSA"

# Server
$OPENSSL ecparam -genkey -name prime256v1 -out server_key.pem
$OPENSSL req -new -key server_key.pem -out server.csr \
    -subj "/C=US/O=Example/CN=${SERVER_IP}"
$OPENSSL x509 -req -in server.csr -CA ca_cert.pem -CAkey ca_key.pem \
    -CAcreateserial -out server_cert.pem -days $VALIDITY_DAYS \
    -extfile san.cnf -extensions v3_req

# Example Client
$OPENSSL ecparam -genkey -name prime256v1 -out example_client_key.pem
$OPENSSL req -new -key example_client_key.pem -out example_client.csr \
    -subj "/C=US/O=Example/CN=ExampleClient"
$OPENSSL x509 -req -in example_client.csr -CA ca_cert.pem -CAkey ca_key.pem \
    -CAcreateserial -out example_client_cert.pem -days $VALIDITY_DAYS

echo -e "${GREEN}✓ ECDSA P-256 certificates generated${NC}"

# =============================================================================
# 2. ML-DSA-44 Certificates
# =============================================================================
echo -e "\n${GREEN}[3/5] Generating ML-DSA-44 certificates...${NC}"

# CA
$OPENSSL genpkey -algorithm ML-DSA-44 -out ca_key_mldsa44.pem
$OPENSSL req -new -x509 -key ca_key_mldsa44.pem -out ca_cert_mldsa44.pem -days $CA_VALIDITY_DAYS \
    -subj "/C=US/O=Example/CN=TestCA-MLDSA44"

# Server
$OPENSSL genpkey -algorithm ML-DSA-44 -out server_key_mldsa44.pem
$OPENSSL req -new -key server_key_mldsa44.pem -out server_mldsa44.csr \
    -subj "/C=US/O=Example/CN=${SERVER_IP}"
$OPENSSL x509 -req -in server_mldsa44.csr -CA ca_cert_mldsa44.pem -CAkey ca_key_mldsa44.pem \
    -CAcreateserial -out server_cert_mldsa44.pem -days $VALIDITY_DAYS \
    -extfile san.cnf -extensions v3_req

# Example Client
$OPENSSL genpkey -algorithm ML-DSA-44 -out example_client_key_mldsa44.pem
$OPENSSL req -new -key example_client_key_mldsa44.pem -out example_client_mldsa44.csr \
    -subj "/C=US/O=Example/CN=ExampleClient-MLDSA44"
$OPENSSL x509 -req -in example_client_mldsa44.csr -CA ca_cert_mldsa44.pem -CAkey ca_key_mldsa44.pem \
    -CAcreateserial -out example_client_cert_mldsa44.pem -days $VALIDITY_DAYS

echo -e "${GREEN}✓ ML-DSA-44 certificates generated${NC}"

# =============================================================================
# 3. ML-DSA-65 Certificates
# =============================================================================
echo -e "\n${GREEN}[4/5] Generating ML-DSA-65 certificates...${NC}"

# CA
$OPENSSL genpkey -algorithm ML-DSA-65 -out ca_key_mldsa65.pem
$OPENSSL req -new -x509 -key ca_key_mldsa65.pem -out ca_cert_mldsa65.pem -days $CA_VALIDITY_DAYS \
    -subj "/C=US/O=Example/CN=TestCA-MLDSA65"

# Server
$OPENSSL genpkey -algorithm ML-DSA-65 -out server_key_mldsa65.pem
$OPENSSL req -new -key server_key_mldsa65.pem -out server_mldsa65.csr \
    -subj "/C=US/O=Example/CN=${SERVER_IP}"
$OPENSSL x509 -req -in server_mldsa65.csr -CA ca_cert_mldsa65.pem -CAkey ca_key_mldsa65.pem \
    -CAcreateserial -out server_cert_mldsa65.pem -days $VALIDITY_DAYS \
    -extfile san.cnf -extensions v3_req

# Example Client
$OPENSSL genpkey -algorithm ML-DSA-65 -out example_client_key_mldsa65.pem
$OPENSSL req -new -key example_client_key_mldsa65.pem -out example_client_mldsa65.csr \
    -subj "/C=US/O=Example/CN=ExampleClient-MLDSA65"
$OPENSSL x509 -req -in example_client_mldsa65.csr -CA ca_cert_mldsa65.pem -CAkey ca_key_mldsa65.pem \
    -CAcreateserial -out example_client_cert_mldsa65.pem -days $VALIDITY_DAYS

echo -e "${GREEN}✓ ML-DSA-65 certificates generated${NC}"

# =============================================================================
# 4. ML-DSA-87 Certificates
# =============================================================================
echo -e "\n${GREEN}[5/5] Generating ML-DSA-87 certificates...${NC}"

# CA
$OPENSSL genpkey -algorithm ML-DSA-87 -out ca_key_mldsa87.pem
$OPENSSL req -new -x509 -key ca_key_mldsa87.pem -out ca_cert_mldsa87.pem -days $CA_VALIDITY_DAYS \
    -subj "/C=US/O=Example/CN=TestCA-MLDSA87"

# Server
$OPENSSL genpkey -algorithm ML-DSA-87 -out server_key_mldsa87.pem
$OPENSSL req -new -key server_key_mldsa87.pem -out server_mldsa87.csr \
    -subj "/C=US/O=Example/CN=${SERVER_IP}"
$OPENSSL x509 -req -in server_mldsa87.csr -CA ca_cert_mldsa87.pem -CAkey ca_key_mldsa87.pem \
    -CAcreateserial -out server_cert_mldsa87.pem -days $VALIDITY_DAYS \
    -extfile san.cnf -extensions v3_req

# Example Client
$OPENSSL genpkey -algorithm ML-DSA-87 -out example_client_key_mldsa87.pem
$OPENSSL req -new -key example_client_key_mldsa87.pem -out example_client_mldsa87.csr \
    -subj "/C=US/O=Example/CN=ExampleClient-MLDSA87"
$OPENSSL x509 -req -in example_client_mldsa87.csr -CA ca_cert_mldsa87.pem -CAkey ca_key_mldsa87.pem \
    -CAcreateserial -out example_client_cert_mldsa87.pem -days $VALIDITY_DAYS

echo -e "${GREEN}✓ ML-DSA-87 certificates generated${NC}"

# =============================================================================
# Cleanup
# =============================================================================
echo -e "\n${YELLOW}Cleaning up temporary files...${NC}"
rm -f *.csr *.srl

# =============================================================================
# Summary
# =============================================================================
echo -e "\n${GREEN}=== Certificate Generation Complete ===${NC}"
echo -e "\nGenerated files in $CERT_DIR:"
echo -e "${YELLOW}CA Certificates:${NC}"
ls -lh ca_cert*.pem
echo -e "\n${YELLOW}Server Certificates:${NC}"
ls -lh server_cert*.pem
echo -e "\n${YELLOW}Example Client Certificates:${NC}"
ls -lh example_client_cert*.pem

echo -e "\n${GREEN}Certificate sizes:${NC}"
echo "ECDSA P-256:  $(stat -f%z ca_cert.pem 2>/dev/null || stat -c%s ca_cert.pem) bytes"
echo "ML-DSA-44:    $(stat -f%z ca_cert_mldsa44.pem 2>/dev/null || stat -c%s ca_cert_mldsa44.pem) bytes"
echo "ML-DSA-65:    $(stat -f%z ca_cert_mldsa65.pem 2>/dev/null || stat -c%s ca_cert_mldsa65.pem) bytes"
echo "ML-DSA-87:    $(stat -f%z ca_cert_mldsa87.pem 2>/dev/null || stat -c%s ca_cert_mldsa87.pem) bytes"

echo -e "\n${YELLOW}⚠️  SECURITY NOTICE:${NC}"
echo "- Keep *_key.pem files secure (never share or commit)"
echo "- Example client certificates are for testing only"
echo "- In production, clients should generate their own keys"
echo "- Update mosquitto.conf with correct certificate paths"

echo -e "\n${GREEN}Next steps:${NC}"
echo "1. Update mosquitto.conf with certificate paths"
echo "2. sudo systemctl restart mosquitto"
echo "3. Generate production client certificates using CSR workflow"

