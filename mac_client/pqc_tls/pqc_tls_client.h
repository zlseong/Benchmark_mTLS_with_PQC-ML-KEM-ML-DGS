/**
 * @file pqc_tls_client.h
 * @brief PQC-Hybrid TLS Client API
 * 
 * OpenSSL 3.6.0 네이티브 PQC 지원을 사용한 TLS 1.3 클라이언트
 * oqs-provider 불필요
 */

#ifndef PQC_TLS_CLIENT_H
#define PQC_TLS_CLIENT_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// Type Definitions
// ============================================================================

/**
 * @brief PQC TLS 설정 구조체
 */
typedef struct {
    const char *host;              /**< 서버 호스트명 또는 IP */
    uint16_t port;                 /**< 서버 포트 */
    const char *cert_file;         /**< 클라이언트 인증서 파일 경로 */
    const char *key_file;          /**< 클라이언트 키 파일 경로 */
    const char *ca_file;           /**< CA 인증서 파일 경로 */
    const char *kem_algorithm;     /**< KEM 알고리즘 (예: "mlkem768") */
    const char *sig_algorithm;     /**< 서명 알고리즘 (예: "ecdsa_secp256r1_sha256") */
    uint32_t timeout_ms;           /**< 연결 타임아웃 (밀리초) */
    bool verify_peer;              /**< 서버 인증서 검증 여부 */
} pqc_tls_config_t;

/**
 * @brief PQC TLS 메트릭 구조체
 */
typedef struct {
    double handshake_time_ms;         /**< 전체 핸드셰이크 시간 (ms) */
    double cert_verify_time_ms;       /**< 인증서 검증 시간 (ms) */
    uint32_t bytes_sent;              /**< 송신 바이트 수 */
    uint32_t bytes_received;          /**< 수신 바이트 수 */
    uint32_t cert_chain_size;         /**< 인증서 체인 크기 (bytes) */
    uint64_t cpu_cycles;              /**< CPU 사이클 (측정 가능한 경우) */
    char negotiated_kem[64];          /**< 협상된 KEM 알고리즘 */
    char negotiated_sig[64];          /**< 협상된 서명 알고리즘 */
    char cipher_suite[64];            /**< 사용된 cipher suite */
} pqc_metrics_t;

/**
 * @brief PQC TLS 클라이언트 핸들 (불투명 타입)
 */
typedef struct pqc_tls_client pqc_tls_client_t;

// ============================================================================
// Client Lifecycle Functions
// ============================================================================

/**
 * @brief PQC TLS 클라이언트 생성
 * 
 * @param config TLS 설정
 * @return 클라이언트 핸들, 실패 시 NULL
 */
pqc_tls_client_t* pqc_tls_client_create(const pqc_tls_config_t *config);

/**
 * @brief 서버에 연결 및 TLS 핸드셰이크 수행
 * 
 * @param client 클라이언트 핸들
 * @return 성공 시 0, 실패 시 -1
 */
int pqc_tls_client_connect(pqc_tls_client_t *client);

/**
 * @brief 연결 여부 확인
 * 
 * @param client 클라이언트 핸들
 * @return 연결됨: true, 아니면 false
 */
bool pqc_tls_client_is_connected(const pqc_tls_client_t *client);

/**
 * @brief 연결 종료
 * 
 * @param client 클라이언트 핸들
 */
void pqc_tls_client_disconnect(pqc_tls_client_t *client);

/**
 * @brief 클라이언트 리소스 해제
 * 
 * @param client 클라이언트 핸들
 */
void pqc_tls_client_destroy(pqc_tls_client_t *client);

// ============================================================================
// Data Transfer Functions
// ============================================================================

/**
 * @brief 데이터 송신
 * 
 * @param client 클라이언트 핸들
 * @param data 송신할 데이터
 * @param len 데이터 길이
 * @return 송신된 바이트 수, 실패 시 -1
 */
int pqc_tls_client_send(pqc_tls_client_t *client, const void *data, size_t len);

/**
 * @brief 데이터 수신
 * 
 * @param client 클라이언트 핸들
 * @param buffer 수신 버퍼
 * @param len 버퍼 크기
 * @return 수신된 바이트 수, 실패 시 -1, 연결 종료 시 0
 */
int pqc_tls_client_recv(pqc_tls_client_t *client, void *buffer, size_t len);

// ============================================================================
// Metrics and Information Functions
// ============================================================================

/**
 * @brief 핸드셰이크 메트릭 조회
 * 
 * @param client 클라이언트 핸들
 * @param metrics 메트릭 구조체 포인터 (출력)
 * @return 성공 시 0, 실패 시 -1
 */
int pqc_tls_client_get_metrics(const pqc_tls_client_t *client, pqc_metrics_t *metrics);

/**
 * @brief 마지막 에러 메시지 조회
 * 
 * @param client 클라이언트 핸들
 * @return 에러 메시지 문자열
 */
const char* pqc_tls_client_get_error(const pqc_tls_client_t *client);

/**
 * @brief 연결된 소켓의 파일 디스크립터 조회
 * 
 * @param client 클라이언트 핸들
 * @return 소켓 파일 디스크립터, 실패 시 -1
 */
int pqc_tls_client_get_fd(const pqc_tls_client_t *client);

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * @brief OpenSSL 버전 및 PQC 지원 확인
 * 
 * @return OpenSSL 버전 문자열
 */
const char* pqc_tls_get_openssl_version(void);

/**
 * @brief 지원되는 KEM 알고리즘 목록 조회
 * 
 * @param buffer 결과 버퍼
 * @param buf_size 버퍼 크기
 * @return 성공 시 0, 실패 시 -1
 */
int pqc_tls_list_kem_algorithms(char *buffer, size_t buf_size);

/**
 * @brief 지원되는 서명 알고리즘 목록 조회
 * 
 * @param buffer 결과 버퍼
 * @param buf_size 버퍼 크기
 * @return 성공 시 0, 실패 시 -1
 */
int pqc_tls_list_sig_algorithms(char *buffer, size_t buf_size);

#ifdef __cplusplus
}
#endif

#endif // PQC_TLS_CLIENT_H


