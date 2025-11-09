# TLS 1.3 Handshake Benchmark with Post-Quantum Cryptography

Comprehensive benchmarking framework for measuring TLS 1.3 handshake performance with NIST-standardized Post-Quantum Cryptographic algorithms (ML-KEM, ML-DSA) and classical algorithms (ECDSA).

## Overview

This project measures and compares TLS 1.3 handshake performance across:
- **Signature Algorithms**: ECDSA-P256, ML-DSA-44/65/87
- **Key Exchange**: Classical (X25519), Pure PQC (MLKEM512/768/1024), Hybrid (X25519MLKEM768, SecP256r1MLKEM768, etc.)
- **Real-world scenarios**: Multi-port MQTT broker with mutual TLS authentication

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                    MQTT Broker (Server)                       │
│              OpenSSL 3.6.0 + Mosquitto 2.0.18                │
├──────────────────────────────────────────────────────────────┤
│  Port 8883  │  Port 8884  │  Port 8885  │  Port 8886        │
│  ECDSA-P256 │  ML-DSA-44  │  ML-DSA-65  │  ML-DSA-87        │
├──────────────────────────────────────────────────────────────┤
│         TLS 1.3 + Mutual Authentication                       │
│    Key Exchange: MLKEM512/768/1024 + Hybrid                  │
└──────────────────────────────────────────────────────────────┘
            │                                  │
            ▼                                  ▼
    ┌───────────────┐                  ┌──────────────┐
    │   Client 1    │                  │   Client 2   │
    │   Benchmark   │                  │  Benchmark   │
    └───────────────┘                  └──────────────┘
```

## Key Features

-  **Native PQC Support**: OpenSSL 3.6.0 with NIST FIPS 203/204 (ML-KEM/ML-DSA)
-  **Multi-Algorithm**: 28 combinations of signature and key exchange algorithms
-  **Automated Testing**: Script-driven benchmark execution with 30 iterations per test
-  **Statistical Analysis**: Outlier removal, mean/median/stddev calculation
-  **Real-world Setup**: MQTT broker with mutual TLS on separate ports
-  **Production PKI**: Proper CSR workflow, no shared private keys

## Benchmark Results Summary

| Key Exchange  | Signature  | Type              | Success | Handshake (ms) | Cert Size (bytes) |
|---------------|------------|-------------------|---------|----------------|-------------------|
| X25519        | ECDSA-P256 | Classical         | 100%    | 16.92 ± 0.58   | 474               |
| MLKEM768      | ML-DSA-65  | Pure PQC          | 100%    | 20.73 ± 1.04   | 5,620             |
| X25519MLKEM768| ML-DSA-65  | Hybrid PQC        | 100%    | 21.15 ± 0.89   | 5,620             |
| MLKEM1024     | ML-DSA-87  | Pure PQC / Level 5| 100%    | 25.28 ± 1.38   | 7,565             |

**Key Findings:**
- ML-DSA: 22-86% slower than ECDSA (8-16x larger certificates)
- ML-KEM: Only 3-5% overhead vs classical ECDH
- Hybrid: Minimal overhead with quantum resistance
- 100% success rate across all 28 combinations

## Project Structure

```
├── Server/                 # MQTT broker configuration
│   ├── mosquitto.conf.example
│   ├── openssl-kem.cnf.example
│   └── scripts/
│       └── generate_certs.sh
├── Client/                 # Client benchmark automation
│   ├── run_benchmark.py
│   ├── analyze_results.py
│   └── README.md
└── Common/                 # Shared utilities and certificate management
    └── cert_utils/
```

## Quick Start

### 1. Server Setup (MQTT Broker)

```bash
# Install OpenSSL 3.6.0
cd /tmp
wget https://github.com/openssl/openssl/releases/download/openssl-3.6.0/openssl-3.6.0.tar.gz
tar -xzf openssl-3.6.0.tar.gz
cd openssl-3.6.0
./Configure --prefix=/usr/local/ssl shared
make -j$(nproc)
sudo make install
sudo ldconfig

# Build Mosquitto with OpenSSL 3.6.0
cd /tmp
git clone https://github.com/eclipse/mosquitto.git
cd mosquitto
mkdir build && cd build
cmake .. -DCMAKE_INSTALL_PREFIX=/opt/mosquitto \
         -DWITH_TLS=ON \
         -DOPENSSL_ROOT_DIR=/usr/local/ssl
make -j$(nproc)
sudo make install

# Generate certificates
cd Server/scripts
./generate_certs.sh <SERVER_IP>

# Configure broker
sudo cp ../mosquitto.conf.example /etc/mosquitto/mosquitto.conf
# Edit certificate paths in mosquitto.conf

# Enable ML-KEM support
sudo cp ../openssl-kem.cnf.example /usr/local/ssl/openssl-kem.cnf
sudo mkdir -p /etc/systemd/system/mosquitto.service.d
echo '[Service]' | sudo tee /etc/systemd/system/mosquitto.service.d/openssl.conf
echo 'Environment="OPENSSL_CONF=/usr/local/ssl/openssl-kem.cnf"' | sudo tee -a /etc/systemd/system/mosquitto.service.d/openssl.conf

# Start broker
sudo systemctl daemon-reload
sudo systemctl restart mosquitto
```

### 2. Client Setup

#### Prerequisites
- OpenSSL 3.6.0+
- Python 3.8+ (for automation scripts)
- Network access to broker

#### Install OpenSSL 3.6.0 (if needed)
```bash
# Same as server installation above
cd /tmp
wget https://github.com/openssl/openssl/releases/download/openssl-3.6.0/openssl-3.6.0.tar.gz
tar -xzf openssl-3.6.0.tar.gz
cd openssl-3.6.0
./Configure --prefix=/usr/local/openssl-3.6.0 shared
make -j$(nproc)
sudo make install
```

#### Generate Client Certificates
```bash
# Client generates private key
/usr/local/openssl-3.6.0/bin/openssl ecparam -genkey -name prime256v1 -out client_key.pem

# Generate CSR
/usr/local/openssl-3.6.0/bin/openssl req -new -key client_key.pem -out client.csr \
  -subj "/C=US/O=Example/CN=Client1"

# Send CSR to server for signing
# Receive signed certificate from server
```

### 3. Run Benchmark

#### Automated Benchmark
```bash
cd Client
python3 run_benchmark.py --server <BROKER_IP> --iterations 30
```

#### Manual Test
```bash
/usr/local/openssl-3.6.0/bin/openssl s_client \
  -connect <BROKER_IP>:8885 \
  -cert client_cert_mldsa65.pem \
  -key client_key.pem \
  -CAfile ca_cert_mldsa65.pem \
  -groups MLKEM768 \
  -tls1_3
```


## Measured Metrics

### Handshake Performance
- Total handshake time (ms)
- Component breakdown:
  - ClientHello → ServerHello
  - Certificate verification
  - Key exchange (KEM encapsulation/decapsulation)
  - Signature generation/verification
  - Finished messages

### Certificate & Traffic
- Certificate chain size (bytes)
- Total bytes transmitted/received
- Number of TLS records
- Number of network packets

### Statistics (30 iterations)
- Mean, Median, Min, Max
- Standard deviation
- Success rate (%)
- Outlier removal (top 4 + bottom 4)

## Supported Algorithms

### Signature Algorithms (NIST FIPS 204)
| Algorithm   | Security Level | Cert Size | Speed vs ECDSA |
|-------------|----------------|-----------|----------------|
| ECDSA-P256  | Classical      | ~700 B    | Baseline       |
| ML-DSA-44   | Level 2        | ~5 KB     | -22%           |
| ML-DSA-65   | Level 3        | ~7.5 KB   | -54%           |
| ML-DSA-87   | Level 5        | ~11 KB    | -86%           |

### Key Exchange Mechanisms (NIST FIPS 203)
| Algorithm          | Type         | Security Level | Speed vs X25519 |
|--------------------|--------------|----------------|-----------------|
| X25519             | Classical    | ~128-bit       | Baseline        |
| MLKEM512           | Pure PQC     | Level 1        | -3%             |
| MLKEM768           | Pure PQC     | Level 3        | -4%             |
| MLKEM1024          | Pure PQC     | Level 5        | -5%             |
| X25519MLKEM768     | Hybrid       | Level 3        | -4%             |
| SecP256r1MLKEM768  | Hybrid       | Level 3        | -5%             |
| SecP384r1MLKEM1024 | Hybrid       | Level 5        | -6%             |

## Configuration

### Broker Ports
- **8883**: ECDSA-P256 certificates
- **8884**: ML-DSA-44 certificates  
- **8885**: ML-DSA-65 certificates
- **8886**: ML-DSA-87 certificates

All ports support all key exchange algorithms (client selects during handshake).

### Benchmark Settings
```python
ITERATIONS = 30           # Number of test runs per combination
TIMEOUT_MS = 2000         # Handshake timeout
OUTLIER_REMOVAL = 8       # Remove 4 highest + 4 lowest
```

## Security Features

-  **TLS 1.3 only**: No protocol downgrade
-  **Mutual TLS**: Both server and client authentication
-  **Forward Secrecy**: Ephemeral key exchange
-  **Quantum Resistance**: ML-KEM key exchange
-  **PKI Best Practices**: CSR workflow, no shared keys

## Performance Considerations

### Network Impact
- **5G/Wi-Fi**: Minimal impact (~1-2% variance)
- **Handshake dominates**: Signature verification is main bottleneck
- **ML-KEM overhead**: Only 3-5%, negligible in real-world

### Certificate Size
- **ECDSA**: Small (~700 bytes), fast to transmit
- **ML-DSA**: Large (5-11 KB), more network overhead
- **Impact**: Linear with size, but still <10ms on 5G

### Recommendations
- **High Performance**: ECDSA + X25519 (classical)
- **Balanced**: ECDSA + X25519MLKEM768 (hybrid, quantum-safe key exchange)
- **Maximum Security**: ML-DSA-65 + MLKEM768 (pure PQC, Level 3)
- **Future-proof**: ML-DSA-87 + MLKEM1024 (pure PQC, Level 5)

## Troubleshooting

### Connection Refused
```bash
# Check broker status
sudo systemctl status mosquitto
sudo ss -tlnp | grep mosquitto

# Check firewall
sudo ufw status
nc -zv <BROKER_IP> 8883

# Verify certificates
openssl x509 -in cert.pem -text -noout
```

### ML-KEM Not Working
```bash
# Verify OpenSSL support
/usr/local/ssl/bin/openssl list -kem-algorithms | grep MLKEM

# Check environment
echo $OPENSSL_CONF

# Restart with config
sudo systemctl restart mosquitto
```

### Low Performance
- Check CPU load: `top` or `htop`
- Verify network: `ping`, `iperf3`
- Enable verbose logging for timing breakdown

## References

- [NIST FIPS 203 (ML-KEM)](https://csrc.nist.gov/publications/detail/fips/203/final)
- [NIST FIPS 204 (ML-DSA)](https://csrc.nist.gov/publications/detail/fips/204/final)
- [OpenSSL 3.6.0 Release](https://www.openssl.org/news/openssl-3.6-notes.html)
- [TLS 1.3 RFC 8446](https://datatracker.ietf.org/doc/html/rfc8446)
- [Eclipse Mosquitto](https://mosquitto.org/)

## License

See LICENSE file.

## Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Test thoroughly
4. Submit a pull request

## Citation

If you use this benchmark in your research, please cite:

```bibtex
@misc{tls13_pqc_benchmark,
  title={TLS 1.3 Handshake Benchmark with Post-Quantum Cryptography},
  author={Your Name},
  year={2025},
  url={https://github.com/zlseong/Benchmark_mTLS_with_PQC-ML-KEM-ML-DGS}
}
```


