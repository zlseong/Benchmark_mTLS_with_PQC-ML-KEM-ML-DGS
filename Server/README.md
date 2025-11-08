# MQTT Broker with Post-Quantum Cryptography (PQC)

Multi-port MQTT broker configuration supporting both classical and post-quantum cryptographic algorithms for TLS 1.3 benchmarking.

## Overview

This MQTT broker is configured to support multiple TLS configurations on separate ports, enabling comprehensive benchmarking of different cryptographic algorithms:

- **Port 8883**: ECDSA P-256 (Classical)
- **Port 8884**: ML-DSA-44 (PQC - Level 2)
- **Port 8885**: ML-DSA-65 (PQC - Level 3)
- **Port 8886**: ML-DSA-87 (PQC - Level 5)

## Features

- ✅ **Multi-Algorithm Support**: Classical ECDSA and post-quantum ML-DSA signatures
- ✅ **Hybrid Key Exchange**: ML-KEM-768, ML-KEM-1024 with classical ECDH
- ✅ **Pure PQC Key Exchange**: MLKEM512, MLKEM768, MLKEM1024
- ✅ **Mutual TLS**: Client certificate authentication required
- ✅ **OpenSSL 3.6.0**: Native PQC support without external providers
- ✅ **TLS 1.3 Only**: Modern protocol with enhanced security

## Supported Algorithms

### Signature Algorithms (Certificate)
- **ECDSA-P256**: Fast, small certificates (~700 bytes)
- **ML-DSA-44**: PQC, Security Level 2 (~5 KB)
- **ML-DSA-65**: PQC, Security Level 3 (~7.5 KB)
- **ML-DSA-87**: PQC, Security Level 5 (~11 KB)

### Key Exchange Mechanisms (TLS Handshake)
- **Pure ML-KEM**: MLKEM512, MLKEM768, MLKEM1024
- **Hybrid**: X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024
- **Classical**: X25519, prime256v1

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    MQTT Broker (Mosquitto)                   │
│                      OpenSSL 3.6.0                          │
├─────────────────────────────────────────────────────────────┤
│  Port 8883  │  Port 8884  │  Port 8885  │  Port 8886       │
│  ECDSA-P256 │  ML-DSA-44  │  ML-DSA-65  │  ML-DSA-87       │
├─────────────────────────────────────────────────────────────┤
│              TLS 1.3 + Mutual Authentication                │
│  Key Exchange: ML-KEM-512/768/1024 + Hybrid                │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
                    ┌───────────────┐
                    │    Clients    │
                    │  (Benchmark)  │
                    └───────────────┘
```

## Prerequisites

- Ubuntu 22.04 or later (WSL2 supported)
- OpenSSL 3.6.0 or later
- Mosquitto 2.0.18 or later
- Root/sudo access

## Installation

### 1. Install OpenSSL 3.6.0

```bash
# Download OpenSSL 3.6.0
cd /tmp
wget https://github.com/openssl/openssl/releases/download/openssl-3.6.0/openssl-3.6.0.tar.gz
tar -xzf openssl-3.6.0.tar.gz
cd openssl-3.6.0

# Build and install
./Configure --prefix=/usr/local/ssl shared
make -j$(nproc)
sudo make install

# Register library path
echo '/usr/local/ssl/lib64' | sudo tee /etc/ld.so.conf.d/openssl-3.6.0.conf
sudo ldconfig

# Verify installation
/usr/local/ssl/bin/openssl version
# Expected: OpenSSL 3.6.0 1 Oct 2025
```

### 2. Build Mosquitto with OpenSSL 3.6.0

```bash
cd /tmp
git clone https://github.com/eclipse/mosquitto.git
cd mosquitto
mkdir build && cd build

cmake .. \
  -DCMAKE_INSTALL_PREFIX=/opt/mosquitto \
  -DWITH_TLS=ON \
  -DOPENSSL_ROOT_DIR=/usr/local/ssl \
  -DOPENSSL_INCLUDE_DIR=/usr/local/ssl/include \
  -DDOCUMENTATION=OFF

make -j$(nproc)
sudo make install

# Create symlink
sudo ln -sf /opt/mosquitto/sbin/mosquitto /usr/sbin/mosquitto
```

### 3. Generate Certificates

See `scripts/generate_certs.sh` for certificate generation.

```bash
cd scripts
./generate_certs.sh <SERVER_IP>
```

### 4. Configure Mosquitto

```bash
# Copy configuration
sudo cp mosquitto.conf.example /etc/mosquitto/mosquitto.conf

# Edit paths in mosquitto.conf
sudo nano /etc/mosquitto/mosquitto.conf

# Update certificate paths:
# certfile /path/to/certs/server_cert.pem
# keyfile /path/to/certs/server_key.pem
# cafile /path/to/certs/ca_cert.pem
```

### 5. Configure ML-KEM Support

```bash
# Copy OpenSSL configuration
sudo cp openssl-kem.cnf.example /usr/local/ssl/openssl-kem.cnf

# Configure Mosquitto to use it
sudo mkdir -p /etc/systemd/system/mosquitto.service.d
sudo tee /etc/systemd/system/mosquitto.service.d/openssl.conf > /dev/null << 'EOF'
[Service]
Environment="OPENSSL_CONF=/usr/local/ssl/openssl-kem.cnf"
EOF

# Reload and restart
sudo systemctl daemon-reload
sudo systemctl restart mosquitto
```

### 6. Configure Firewall (Optional)

```bash
# For Windows WSL:
# Run in PowerShell as Administrator:

# Allow MQTT ports
New-NetFirewallRule -DisplayName "MQTT 8883" -Direction Inbound -LocalPort 8883 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "MQTT 8884" -Direction Inbound -LocalPort 8884 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "MQTT 8885" -Direction Inbound -LocalPort 8885 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "MQTT 8886" -Direction Inbound -LocalPort 8886 -Protocol TCP -Action Allow

# Port forwarding (WSL to Windows)
netsh interface portproxy add v4tov4 listenport=8883 listenaddress=0.0.0.0 connectport=8883 connectaddress=<WSL_IP>
netsh interface portproxy add v4tov4 listenport=8884 listenaddress=0.0.0.0 connectport=8884 connectaddress=<WSL_IP>
netsh interface portproxy add v4tov4 listenport=8885 listenaddress=0.0.0.0 connectport=8885 connectaddress=<WSL_IP>
netsh interface portproxy add v4tov4 listenport=8886 listenaddress=0.0.0.0 connectport=8886 connectaddress=<WSL_IP>
```

## Usage

### Start Broker

```bash
sudo systemctl start mosquitto
sudo systemctl status mosquitto
```

### Verify Ports

```bash
sudo ss -tlnp | grep mosquitto
# Expected:
# LISTEN 0.0.0.0:8883
# LISTEN 0.0.0.0:8884
# LISTEN 0.0.0.0:8885
# LISTEN 0.0.0.0:8886
```

### Test Connection

```bash
# Test ECDSA P-256 (Port 8883)
/usr/local/ssl/bin/openssl s_client -connect localhost:8883 \
  -cert /path/to/client_cert.pem \
  -key /path/to/client_key.pem \
  -CAfile /path/to/ca_cert.pem \
  -tls1_3

# Test ML-DSA-65 (Port 8885)
/usr/local/ssl/bin/openssl s_client -connect localhost:8885 \
  -cert /path/to/client_cert_mldsa65.pem \
  -key /path/to/client_key_mldsa65.pem \
  -CAfile /path/to/ca_cert_mldsa65.pem \
  -tls1_3
```

### Test Key Exchange Algorithms

```bash
# Test pure ML-KEM-768
/usr/local/ssl/bin/openssl s_client -connect localhost:8885 \
  -groups MLKEM768 \
  -cert /path/to/client_cert_mldsa65.pem \
  -key /path/to/client_key_mldsa65.pem \
  -CAfile /path/to/ca_cert_mldsa65.pem \
  -tls1_3 2>&1 | grep "Negotiated"

# Test hybrid X25519MLKEM768
/usr/local/ssl/bin/openssl s_client -connect localhost:8885 \
  -groups X25519MLKEM768 \
  -cert /path/to/client_cert_mldsa65.pem \
  -key /path/to/client_key_mldsa65.pem \
  -CAfile /path/to/ca_cert_mldsa65.pem \
  -tls1_3 2>&1 | grep "Negotiated"
```

## Benchmarking

This broker configuration is designed for TLS 1.3 handshake benchmarking with various cryptographic algorithms.

### Measured Metrics

- Handshake time (ms)
- Certificate chain size (bytes)
- Network traffic (bytes)
- Success rate (%)
- KEM operations time
- Signature verification time

### Benchmark Scenarios

1. **Signature Algorithm Comparison**
   - ECDSA-P256 vs ML-DSA-44/65/87
   - Certificate size impact
   - Verification time

2. **Key Exchange Comparison**
   - Classical (X25519) vs Pure PQC (MLKEM768) vs Hybrid (X25519MLKEM768)
   - Handshake latency
   - Network overhead

3. **Combined Scenarios**
   - All combinations of signature and key exchange algorithms
   - Real-world performance analysis

## PKI Best Practices

This configuration follows production-level PKI:

1. **Client Key Generation**: Clients generate their own private keys
2. **CSR Workflow**: Certificate Signing Request (CSR) sent to broker
3. **CA Signing**: Broker signs CSR with appropriate CA
4. **Certificate Distribution**: Only signed certificates transferred
5. **Private Key Security**: Private keys never leave their origin system

## Performance Notes

Based on benchmarking results:

- **ML-DSA**: 22-86% slower than ECDSA (certificate size 8-16x larger)
- **ML-KEM**: 3-5% slower than X25519 (negligible overhead)
- **Hybrid**: Similar performance to pure PQC with enhanced security
- **Network**: 5G/Wi-Fi minimal impact, handshake dominates latency

## Troubleshooting

### Broker doesn't start

```bash
# Check logs
sudo tail -f /var/log/mosquitto/mosquitto.log

# Common issues:
# 1. Certificate permission denied
sudo chmod 644 /path/to/certs/*.pem
sudo chmod 755 /path/to/certs/

# 2. OpenSSL library not found
sudo ldconfig
/usr/local/ssl/bin/openssl version

# 3. Port already in use
sudo ss -tlnp | grep 888
```

### Client connection refused

```bash
# 1. Check firewall
sudo ufw status
sudo ss -tlnp | grep mosquitto

# 2. Test port forwarding (WSL)
nc -zv <SERVER_IP> 8883

# 3. Verify certificates
/usr/local/ssl/bin/openssl x509 -in /path/to/cert.pem -text -noout
```

### ML-KEM not working

```bash
# 1. Verify OpenSSL configuration
echo $OPENSSL_CONF

# 2. Check supported groups
/usr/local/ssl/bin/openssl list -kem-algorithms | grep MLKEM

# 3. Restart mosquitto with environment variable
sudo systemctl restart mosquitto
```

## Security Considerations

- ✅ TLS 1.3 only (no downgrade)
- ✅ Mutual TLS authentication required
- ✅ Client certificate validation enforced
- ✅ Anonymous connections disabled
- ✅ Forward secrecy (ephemeral keys)
- ✅ Post-quantum resistant key exchange

## License

See LICENSE file in the repository root.

## References

- [NIST FIPS 203 (ML-KEM)](https://csrc.nist.gov/publications/detail/fips/203/final)
- [NIST FIPS 204 (ML-DSA)](https://csrc.nist.gov/publications/detail/fips/204/final)
- [OpenSSL 3.6.0 Release Notes](https://www.openssl.org/news/openssl-3.6-notes.html)
- [TLS 1.3 RFC 8446](https://datatracker.ietf.org/doc/html/rfc8446)
- [Eclipse Mosquitto](https://mosquitto.org/)

## Related Projects

- Client implementation: See `../Client/` directory
- Benchmark results: See main repository README
- Certificate management: See `scripts/` directory

