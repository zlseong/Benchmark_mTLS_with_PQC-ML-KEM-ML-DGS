# PQC_hybrid-mTLS

양자 내성(PQC) 알고리즘과 기존 암호를 혼합한 하이브리드 mTLS 실험 레포지입니다. TLS 1.3 고정 환경에서 서버/클라이언트 핸드셰이크를 수행하고, 성공률과 시간 통계를 수집합니다.

## 주요 기능
- TLS 1.3 고정, Cipher: TLS_AES_128_GCM_SHA256
- 하이브리드(KEM + 서명) 알고리즘 조합 실험
- N회 반복 실행 후 평균/백분위/표준편차 산출
- JSON/CSV 결과 저장(파이썬 스크립트)

## 디렉토리 구조
- `Server/tls_server.c`: mTLS 서버
- `Client/tls_client.c`: mTLS 클라이언트
- `Common/metrics.*`: 시간·트래픽·리소스·신뢰성 메트릭 정의/집계
- `Common/json_output.h`: JSON/CSV 출력 인터페이스
- `Common/algo_config.h`: 알고리즘 조합 및 OpenSSL 명칭 매핑
- `generate_certs.sh`: 테스트용 인증서 생성
- `run_benchmark.sh`: 셸 기반 벤치마크(성공률 요약)
- `benchmark.py`: 파이썬 기반 벤치마크(시간 통계 + JSON/CSV)
- `Makefile`: 빌드 스크립트

## 요구 사항
- Linux 또는 WSL2
- GCC/Clang, Make
- OpenSSL 3.6.0 이상
- Python 3.x(선택, `benchmark.py` 사용 시)

## 빠른 시작
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
# 셸 스크립트(성공률 요약)
chmod +x run_benchmark.sh
./run_benchmark.sh

# 파이썬 스크립트(시간 통계 + JSON/CSV)
python3 benchmark.py
# 결과: results/tls13_pqc_benchmark.json, results/tls13_pqc_benchmark.csv
```

## 벤치마크 결과

### PQC-Hybrid 상호 TLS 핸드셰이크 성능 (무선 환경)

| Key encryption Algorithm | Mean (ms) | vs baseline | Traffic (bytes) | CPU cycles |
| :----------------------- | :-------- | :---------- | :-------------- | :--------- |
| x25519                   | 8.79      | -           | 1,943           | -          |
| ML-KEM 512               | 9.29      | +5.7%       | 3,454           | 223,187    |
| ML-KEM 768               | 10.53     | +19.8%      | 4,159           | 252,939    |
| ML-KEM 1024              | 10.72     | +22.2%      | 5,023           | 255,232    |

**실험 환경:** Wi-Fi (30 Mbps). 레이턴시(Latency)와 트래픽(Traffic)은 동일한 조건에서 반복 실행된 결과의 평균값입니다.

## 측정 항목(메트릭)
- 시간(핸드셰이크 레이턴시)
  - t_handshake_total_ms
  - t_clienthello_to_serverhello_ms
  - t_cert_verify_ms
  - t_finished_flight_ms
  - rtt_ms(옵션)
- 트래픽
  - bytes_tx_handshake, bytes_rx_handshake
  - records_count, packets_count, retransmits
- 암호 연산
  - kem_keyshare_len
  - kem_encap_ms_{client,server}, kem_decap_ms_{client,server}
  - sig_len, sign_ms_{client,server}, verify_ms_{client,server}
  - cert_chain_size_{excluding,including}_root
- 리소스
  - peak_heap_bytes, stack_usage_bytes, cpu_cycles, energy_mJ
- 신뢰성
  - success_rate, alert_codes[], alert_count
  - session_resumption_ok, t_resumption_ms
  - zero_rtt_ok, t_0rtt_ms
- 집계(다회 실행)
  - mean, p50, p90, p99, stddev(시간 항목)
  - 트래픽/리소스 평균, 성공률

참고:
- `benchmark.py`: 각 조합에 대해 t_handshake_total_ms의 mean/p50/p90/p99/stddev, success_rate를 JSON/CSV로 저장
- `run_benchmark.sh`: 성공/실패와 성공률만 요약 출력

## 구현된 파라미터(실행/설정)
- 서버 실행(`tls_server`)
  - 인자: `<cert> <key> <ca> <groups> [sigalgs] [port]`
  - 예: `./build/tls_server ... x25519 ecdsa_secp256r1_sha256 4433`
- 클라이언트 실행(`tls_client`)
  - 인자: `<cert> <key> <ca> <groups> [sigalgs] [host] [port]`
  - 예: `./build/tls_client ... x25519 ecdsa_secp256r1_sha256 127.0.0.1 4433`
- 알고리즘 그룹(`groups`)
  - x25519, mlkem512, mlkem768, mlkem1024
- 서명 알고리즘(`sigalgs`)
  - ecdsa_secp256r1_sha256
  - mldsa44, mldsa65, mldsa87(내부적으로 OpenSSL 명칭 dilithium2/3/5로 매핑)
- 인증서 파일 규칙
  - `<group>_<sigalg>_server.{crt,key}`, `<group>_<sigalg>_client.{crt,key}`, `ca.crt`

## 벤치마크 기본 설정(스크립트)
- 공통 변수
  - RUNS_PER_COMBO=30, SERVER_PORT=4433
  - SERVER_BIN=`build/tls_server`, CLIENT_BIN=`build/tls_client`
  - CERTS_DIR=`certs`, RESULTS_DIR=`results`, PCAP_DIR=`results/pcap`
- 알고리즘 조합(예)
  - Baseline: (x25519 + ecdsa)
  - KEM + ECDSA: (mlkem{512,768,1024} + ecdsa)
  - KEM + ML-DSA: (mlkem{512,768,1024} + dilithium{52,64,76})

## 라이선스
- 라이선스는 `LICENSE` 파일을 참고하세요.
