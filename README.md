# TLS 1.3 Handshake Benchmark with Post-Quantum Cryptography

TLS 1.3 다양한 PQC 알고리즘 조합의 핸드셰이크 성능을 측정하는 벤치마크입니다. NIST 표준 Post-Quantum 알고리즘(ML-KEM, ML-DSA)과 기존 알고리즘(ECDSA)을 비교

## 측정사항

- **서명 알고리즘**: ECDSA-P256, ML-DSA-44/65/87
- **키 교환**: X25519, MLKEM512/768/1024, 하이브리드 방식들
- **실제 환경**: MQTT 브로커에서 mutual TLS로 테스트

## 구조

MQTT 브로커로 한번에 여러 포트에서 다른 서명 알고리즘을 사용합니다
- 8883: ECDSA-P256
- 8884: ML-DSA-44
- 8885: ML-DSA-65
- 8886: ML-DSA-87

각 포트는 모든 키 교환 알고리즘을 지원 (클라이언트가 선택).

## 주요 결과

| 키 교환 | 서명 | 타입 | 성공률 | 핸드셰이크 (ms) |
|---------|------|------|--------|-----------------|
| X25519 | ECDSA-P256 | 기존 | 100% | 16.92 ± 0.58 |
| MLKEM768 | ML-DSA-65 | 순수 PQC | 100% | 20.73 ± 1.04 |
| X25519MLKEM768 | ML-DSA-65 | 하이브리드 | 100% | 21.15 ± 0.89 |
| MLKEM1024 | ML-DSA-87 | 순수 PQC | 100% | 25.28 ± 1.38 |


## 설치 및 실행

### 서버 설정

OpenSSL 3.6.0이 필요합니다 (ML-KEM/ML-DSA 지원).

```bash
# OpenSSL 3.6.0 설치
cd /tmp
wget https://github.com/openssl/openssl/releases/download/openssl-3.6.0/openssl-3.6.0.tar.gz
tar -xzf openssl-3.6.0.tar.gz
cd openssl-3.6.0
./Configure --prefix=/usr/local/ssl shared
make -j$(nproc)
sudo make install
sudo ldconfig

# Mosquitto 빌드
cd /tmp
git clone https://github.com/eclipse/mosquitto.git
cd mosquitto
mkdir build && cd build
cmake .. -DCMAKE_INSTALL_PREFIX=/opt/mosquitto \
         -DWITH_TLS=ON \
         -DOPENSSL_ROOT_DIR=/usr/local/ssl
make -j$(nproc)
sudo make install

# 인증서 생성
cd Server/scripts
./generate_certs.sh <서버IP>

# mosquitto.conf 설정 후 서비스 시작
sudo systemctl restart mosquitto
```

### 클라이언트 설정

동일하게 OpenSSL  3.6.0 설치 필요

```bash
# 클라이언트 인증서 생성
/usr/local/openssl-3.6.0/bin/openssl ecparam -genkey -name prime256v1 -out client_key.pem
/usr/local/openssl-3.6.0/bin/openssl req -new -key client_key.pem -out client.csr \
  -subj "/C=US/O=Example/CN=Client1"
# CSR을 서버로 보내서 서명받기
```

### 벤치마크 실행

```bash
cd Client
python3 run_benchmark.py --server <브로커IP> --iterations 30
```

수동 테스트:
```bash
/usr/local/openssl-3.6.0/bin/openssl s_client \
  -connect <브로커IP>:8885 \
  -cert client_cert_mldsa65.pem \
  -key client_key.pem \
  -CAfile ca_cert_mldsa65.pem \
  -groups MLKEM768 \
  -tls1_3
```

## 측정 항목

- 핸드셰이크 전체 시간 (ms)
- 인증서 크기 (bytes)
- 성공률
- 30회 반복 후 평균/중앙값/표준편차

## 알고리즘 정보

### 서명 알고리즘 (NIST FIPS 204)
- ECDSA-P256: 기존 방식, ~700B 인증서
- ML-DSA-44: Level 2, ~5KB 인증서, ECDSA 대비 -22%
- ML-DSA-65: Level 3, ~7.5KB 인증서, ECDSA 대비 -54%
- ML-DSA-87: Level 5, ~11KB 인증서, ECDSA 대비 -86%

### 키 교환 (NIST FIPS 203)
- X25519: 기존 방식
- MLKEM512/768/1024: 순수 PQC, 기존 대비 3-5% 느림
- 하이브리드 방식들: X25519MLKEM768 등



## 참고 자료

- NIST FIPS 203 (ML-KEM)
- NIST FIPS 204 (ML-DSA)
- OpenSSL 3.6.0
- TLS 1.3 RFC 8446
