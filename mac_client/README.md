# Vehicle Mobile Gateway - PQC TLS Benchmark

PQC-Hybrid TLS 1.3 mTLS 핸드셰이크 성능 측정 프로젝트

## 환경

- **클라이언트**: macOS (M-series or Intel)
- **서버**: Windows WSL Ubuntu (Mosquitto MQTT Broker)
- **OpenSSL**: 3.6.0 (native PQC support)
- **프로토콜**: TLS 1.3 with mTLS

## 측정 알고리즘

### KEM (Key Encapsulation Mechanism)
- X25519 (Classical ECDH)
- ML-KEM-768 (NIST Level 3)
- ML-KEM-1024 (NIST Level 5)
- X25519MLKEM768 (Hybrid)
- X448MLKEM1024 (Hybrid)
- SecP256r1MLKEM768 (Hybrid)
- SecP384r1MLKEM1024 (Hybrid)

### Signature Algorithms
- ECDSA-P256 (Classical)
- ML-DSA-44 (Dilithium2, Level 2)
- ML-DSA-65 (Dilithium3, Level 3)
- ML-DSA-87 (Dilithium5, Level 5)

**총 조합**: 7 KEM × 4 Signature = 28개

## 핸드셰이크 측정 범위

TLS 1.3 mTLS 핸드셰이크 전체 과정을 측정:

```
ClientHello
  ↓
ServerHello (KEM 키 교환)
  ↓
Server Certificate (서버 인증서)
Server CertificateVerify (서버 서명 검증)
  ↓
Client Certificate (클라이언트 인증서)
Client CertificateVerify (클라이언트 서명)
  ↓
Finished (양방향)
```

### 포함되는 연산
1. **KEM 키 교환**: 공개키 생성 및 캡슐화/디캡슐화
2. **서버 인증서 서명 검증**: ML-DSA 또는 ECDSA 검증
3. **클라이언트 인증서 서명**: ECDSA 서명 생성
4. **CA 체인 검증**: 루트 CA까지 인증서 체인 검증
5. **Finished 메시지**: HMAC 연산

## 측정 파라미터

### 핸드셰이크 성능
- **Handshake Time** (ms): Mean, Median, Min, Max, StdDev
- **Success Rate** (%): 30회 중 성공 비율

### 네트워크
- **Total Traffic** (bytes): 송수신 총량

### 인증서
- **Certificate Chain Size** (bytes): 인증서 체인 크기
  - ECDSA: ~500-600 bytes
  - ML-DSA-44: ~2-3 KB
  - ML-DSA-65: ~15-16 KB
  - ML-DSA-87: ~20+ KB

### 통계 처리
- **반복 횟수**: 30회
- **아웃라이어 제거**: 상위 4개 + 하위 4개 제거 후 평균 계산

## 빌드

```bash
./build.sh
```

## 벤치마크 실행

```bash
python3 run_benchmark.py
```

결과는 `benchmark_results/` 폴더에 저장됨:
- `benchmark_report_YYYYMMDD_HHMMSS.md`: 결과 리포트
- `benchmark_data_YYYYMMDD_HHMMSS.json`: 원본 데이터

## 서버 포트 매핑

각 서명 알고리즘별로 다른 포트 사용:

| Signature | Port |
|-----------|------|
| ECDSA-P256 | 8883 |
| MLDSA44 | 8884 |
| MLDSA65 | 8885 |
| MLDSA87 | 8886 |

## 파일 구조

```
Vehicle_Mobile_Gateway/
├── src/
│   ├── pqc_tls/          # PQC TLS 핸드셰이크 (C)
│   ├── mqtt/             # MQTT 클라이언트 (C++)
│   └── https/            # HTTPS 클라이언트 (C++)
├── examples/
│   ├── test_pqc_handshake.c
│   ├── test_mqtt.cpp
│   └── test_https.cpp
├── benchmark_results/    # 벤치마크 결과
├── run_benchmark.py      # 자동화 스크립트
├── build.sh
└── CMakeLists.txt
```

## 주의사항

- OpenSSL 3.6.0+ 필수 (native PQC support)
- ML-KEM-512는 서버 미지원으로 제외
- MLDSA87 포트(8886)가 닫혀있으면 해당 조합 실패
- 실패 시 1초, 성공 시 0.3초 대기

## 참고

- NIST FIPS 203 (ML-KEM)
- NIST FIPS 204 (ML-DSA)
- OpenSSL 3.6.0 Release Notes

