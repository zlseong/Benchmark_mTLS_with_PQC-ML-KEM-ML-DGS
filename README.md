# PQC_hybrid-mTLS

양자 내성(PQC) 알고리즘과 기존 암호를 혼합한 하이브리드 mTLS 실험 레포지입니다. TLS 1.3 고정 환경에서 서버/클라이언트 핸드셰이크를 수행하고, 성공률과 시간 통계를 수집합니다.

## 주요 기능

- TLS 1.3 고정, Cipher: TLS_AES_128_GCM_SHA256
- 하이브리드(KEM + 서명) 알고리즘 조합 실험
- N회 반복 실행 후 평균/백분위/표준편차 산출 (아웃라이어 제거)
- JSON/MD 결과 저장 (자동화 스크립트)

## 디렉토리 구조

- `Server/`: WSL/Linux mTLS 서버 (Mosquitto MQTT Broker)
- `Client/`: WSL/Linux mTLS 클라이언트
- `mac_client/`: macOS 클라이언트 (OpenSSL 3.6.0 네이티브 PQC)
  - `pqc_tls/`: PQC TLS 핸드셰이크 라이브러리 (C)
  - `test_pqc_handshake.c`: 벤치마크 클라이언트
  - `run_benchmark.py`: 자동화 스크립트 (통계 처리)
- `Common/`: 공통 메트릭 정의 및 집계
- `generate_certs.sh`: 테스트용 인증서 생성
- `benchmark.py`: 파이썬 기반 벤치마크 (JSON/CSV 출력)

## 요구 사항

### 서버 (WSL/Linux)
- Linux 또는 WSL2
- GCC/Clang, Make
- OpenSSL 3.6.0 이상
- Mosquitto MQTT Broker

### 클라이언트 (macOS)
- macOS (M-series 또는 Intel)
- Homebrew OpenSSL 3.6.0+
- CMake 3.15+
- Python 3.x

## 빠른 시작

### macOS 클라이언트 (권장)

```bash
cd mac_client

# 빌드
./build.sh

# 벤치마크 실행 (30회 × 28개 조합)
python3 run_benchmark.py

# 결과 확인
cat benchmark_results/benchmark_report_*.md
```

### Linux 서버/클라이언트

```bash
# 의존성(예: Ubuntu/WSL)
sudo apt update
sudo apt install -y build-essential clang make openssl libssl-dev python3 python3-pip

# 인증서 생성
chmod +x generate_certs.sh
./generate_certs.sh

# 빌드
make clean && make

# 서버 실행(터미널 A)
./build/tls_server certs/x25519_ecdsa_secp256r1_sha256_server.crt \
                   certs/x25519_ecdsa_secp256r1_sha256_server.key \
                   certs/ca.crt x25519 ecdsa_secp256r1_sha256 4433

# 클라이언트 실행(터미널 B)
./build/tls_client certs/x25519_ecdsa_secp256r1_sha256_client.crt \
                   certs/x25519_ecdsa_secp256r1_sha256_client.key \
                   certs/ca.crt x25519 ecdsa_secp256r1_sha256 127.0.0.1 4433
```

## 벤치마크 실행

```bash
# macOS 자동화 스크립트 (권장)
cd mac_client
python3 run_benchmark.py

# Linux 셸 스크립트 (성공률 요약)
chmod +x run_benchmark.sh
./run_benchmark.sh

# Linux 파이썬 스크립트 (시간 통계 + JSON/CSV)
python3 benchmark.py
# 결과: results/tls13_pqc_benchmark.json, results/tls13_pqc_benchmark.csv
```

## 벤치마크 결과

### PQC-Hybrid TLS 1.3 핸드셰이크 성능 (Wi-Fi 환경, macOS 클라이언트)

| KEM Algorithm | Signature | NIST Level | Success Rate | Handshake (ms) | Cert Size (bytes) |
| :------------ | :-------- | :--------- | :----------- | :------------- | :---------------- |
| X25519 | ECDSA-P256 | Classical / Classical | 100% | 9.68 ± 0.46 | 474 |
| X25519 | ML-DSA-44 | Classical / Level 2 | 100% | 11.80 ± 1.69 | 4,078 |
| X25519 | ML-DSA-65 | Classical / Level 3 | 100% | 15.03 ± 0.84 | 5,607 |
| X25519 | ML-DSA-87 | Classical / Level 5 | 100% | 18.02 ± 0.68 | 7,565 |
| ML-KEM-768 | ECDSA-P256 | Level 3 / Classical | 100% | 10.00 ± 0.41 | 474 |
| ML-KEM-768 | ML-DSA-65 | Level 3 / Level 3 | 100% | 15.94 ± 0.77 | 5,607 |
| ML-KEM-1024 | ECDSA-P256 | Level 5 / Classical | 100% | 10.11 ± 0.51 | 474 |
| ML-KEM-1024 | ML-DSA-87 | Level 5 / Level 5 | 100% | 19.23 ± 0.93 | 7,565 |
| X25519MLKEM768 | ECDSA-P256 | Hybrid / Classical | 100% | 10.06 ± 0.52 | 474 |
| X25519MLKEM768 | ML-DSA-65 | Hybrid / Level 3 | 100% | 15.25 ± 0.88 | 5,607 |
| X448MLKEM1024 | ECDSA-P256 | Hybrid / Classical | 100% | 16.92 ± 0.58 | 474 |
| X448MLKEM1024 | ML-DSA-87 | Hybrid / Level 5 | 100% | 26.01 ± 1.61 | 7,565 |

**실험 환경:** 
- 네트워크: Wi-Fi (무선)
- 서버: WSL Ubuntu + Mosquitto (xxx.xxx.xxx.xxx)
- 클라이언트: macOS + OpenSSL 3.6.0
- 반복 횟수: 30회 (상위 4개 + 하위 4개 아웃라이어 제거)

**주요 발견:**
1. **ML-DSA 서명**: ECDSA 대비 22-86% 느림 (인증서 크기 8-16배)
2. **ML-KEM**: X25519 대비 3-5% 느림 (무시할 수준)
3. **Hybrid KEM**: 순수 PQC와 유사한 성능 (보안성 향상)
4. **성공률**: 모든 조합 100% 달성

## 측정 항목(메트릭)

### macOS 클라이언트 측정 항목

- **핸드셰이크 성능**
  - 핸드셰이크 시간 (ms): Mean, Median, Min, Max, StdDev
  - 성공률 (%): 30회 중 성공 비율
  - 아웃라이어 제거: 상위 4개 + 하위 4개

- **네트워크**
  - 총 트래픽 (bytes): 송수신 합계

- **인증서**
  - 인증서 체인 크기 (bytes)
    - ECDSA: ~474 bytes
    - ML-DSA-44: ~4 KB
    - ML-DSA-65: ~5.6 KB
    - ML-DSA-87: ~7.6 KB

- **암호 알고리즘**
  - KEM: X25519, ML-KEM-768/1024, Hybrid
  - Signature: ECDSA-P256, ML-DSA-44/65/87
  - Cipher Suite: TLS_AES_128_GCM_SHA256

### Linux 측정 항목 (상세)

- **시간 (핸드셰이크 레이턴시)**
  - t_handshake_total_ms
  - t_clienthello_to_serverhello_ms
  - t_cert_verify_ms
  - t_finished_flight_ms
  - rtt_ms (옵션)

- **트래픽**
  - bytes_tx_handshake, bytes_rx_handshake
  - records_count, packets_count, retransmits

- **암호 연산**
  - kem_keyshare_len
  - kem_encap_ms_{client,server}, kem_decap_ms_{client,server}
  - sig_len, sign_ms_{client,server}, verify_ms_{client,server}
  - cert_chain_size_{excluding,including}_root

- **리소스**
  - peak_heap_bytes, stack_usage_bytes, cpu_cycles, energy_mJ

- **신뢰성**
  - success_rate, alert_codes[], alert_count
  - session_resumption_ok, t_resumption_ms
  - zero_rtt_ok, t_0rtt_ms

- **집계 (다회 실행)**
  - mean, p50, p90, p99, stddev (시간 항목)
  - 트래픽/리소스 평균, 성공률

## 구현된 파라미터

### macOS 클라이언트

- **벤치마크 설정**
  - 반복 횟수: 30회
  - 아웃라이어 제거: 8개 (상위 4 + 하위 4)
  - 타임아웃: 2000ms
  - 재시도 간격: 성공 0.3초, 실패 1초

- **KEM 알고리즘**
  - X25519 (Classical)
  - ML-KEM-768 (Level 3)
  - ML-KEM-1024 (Level 5)
  - X25519MLKEM768 (Hybrid)
  - X448MLKEM1024 (Hybrid)
  - SecP256r1MLKEM768 (Hybrid)
  - SecP384r1MLKEM1024 (Hybrid)

- **서명 알고리즘**
  - ECDSA-P256 (Classical)
  - ML-DSA-44 (Level 2)
  - ML-DSA-65 (Level 3)
  - ML-DSA-87 (Level 5)

- **서버 포트 매핑**
  - ECDSA-P256: 8883
  - ML-DSA-44: 8884
  - ML-DSA-65: 8885
  - ML-DSA-87: 8886

### Linux 서버/클라이언트

- **서버 실행 (`tls_server`)**
  - 인자: `<cert> <key> <ca> <groups> [sigalgs] [port]`
  - 예: `./build/tls_server ... x25519 ecdsa_secp256r1_sha256 4433`

- **클라이언트 실행 (`tls_client`)**
  - 인자: `<cert> <key> <ca> <groups> [sigalgs] [host] [port]`
  - 예: `./build/tls_client ... x25519 ecdsa_secp256r1_sha256 127.0.0.1 4433`

- **알고리즘 그룹 (`groups`)**
  - x25519, mlkem512, mlkem768, mlkem1024

- **서명 알고리즘 (`sigalgs`)**
  - ecdsa_secp256r1_sha256
  - mldsa44, mldsa65, mldsa87 (내부적으로 OpenSSL 명칭 dilithium2/3/5로 매핑)

- **인증서 파일 규칙**
  - `<group>_<sigalg>_server.{crt,key}`
  - `<group>_<sigalg>_client.{crt,key}`
  - `ca.crt`

## 벤치마크 기본 설정

### macOS 스크립트 (`mac_client/run_benchmark.py`)

```python
ITERATIONS = 30  # 30회 반복
HANDSHAKE_TIMEOUT_MS = 2000  # 2초 타임아웃
ITERATION_DELAY = 0.3  # 성공 시 0.3초 대기
# 실패 시 1초 대기
# 아웃라이어: 상위 4개 + 하위 4개 제거
```

### Linux 스크립트

- **공통 변수**
  - RUNS_PER_COMBO=30, SERVER_PORT=4433
  - SERVER_BIN=`build/tls_server`, CLIENT_BIN=`build/tls_client`
  - CERTS_DIR=`certs`, RESULTS_DIR=`results`, PCAP_DIR=`results/pcap`

- **알고리즘 조합 (예)**
  - Baseline: (x25519 + ecdsa)
  - KEM + ECDSA: (mlkem{512,768,1024} + ecdsa)
  - KEM + ML-DSA: (mlkem{512,768,1024} + dilithium{52,64,76})

## 프로젝트 특징

### macOS 클라이언트 (새로운 기능)

✅ **OpenSSL 3.6.0 네이티브 PQC 지원**
- oqs-provider 불필요
- NIST 표준 알고리즘 직접 사용

✅ **자동화된 벤치마크**
- 28개 조합 자동 테스트
- 통계 처리 (아웃라이어 제거)
- Markdown 리포트 자동 생성

✅ **견고한 에러 처리**
- 타임아웃 자동 감지
- 소켓 정리 최적화
- 성공률 추적

✅ **상세한 메트릭**
- 핸드셰이크 시간
- 인증서 크기
- 성공률

### Linux 구현 (기존)

✅ **상세한 메트릭 수집**
- CPU cycles, 메모리 사용량
- 네트워크 패킷 분석
- 세션 재개 테스트

✅ **다양한 출력 형식**
- JSON, CSV, Markdown

## TLS 1.3 핸드셰이크 측정 범위

모든 핸드셰이크 시간 측정에 포함되는 연산:

```
ClientHello
  ↓ [KEM 키 교환]
ServerHello
  ↓ [서버 인증서 서명 검증]
Server Certificate
Server CertificateVerify
  ↓ [클라이언트 인증서 서명]
Client Certificate
Client CertificateVerify
  ↓ [HMAC]
Finished (양방향)
```

1. **KEM 키 교환**: 공개키 생성 및 캡슐화/디캡슐화
2. **서버 인증서 서명 검증**: ML-DSA 또는 ECDSA 검증
3. **클라이언트 인증서 서명**: ECDSA 서명 생성
4. **CA 체인 검증**: 루트 CA까지 인증서 체인 검증
5. **Finished 메시지**: HMAC 연산

## 라이선스

라이선스는 `LICENSE` 파일을 참고하세요.

## 참고 문헌

- NIST FIPS 203 (ML-KEM)
- NIST FIPS 204 (ML-DSA)
- OpenSSL 3.6.0 Release Notes
- TLS 1.3 RFC 8446
