/**
 * @file pqc_tls_client.c
 * @brief PQC-Hybrid TLS Client Implementation
 * 
 * OpenSSL 3.6.0 네이티브 PQC 지원 사용
 */

#include "pqc_tls_client.h"
#include "pqc_metrics.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/bio.h>

// ============================================================================
// Internal Structures
// ============================================================================

struct pqc_tls_client {
    pqc_tls_config_t config;
    SSL_CTX *ssl_ctx;
    SSL *ssl;
    int sockfd;
    bool connected;
    pqc_metrics_t metrics;
    char error_buf[256];
};

// ============================================================================
// Internal Helper Functions
// ============================================================================

/**
 * @brief 현재 시간을 밀리초로 반환
 */
static double get_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1000000.0;
}

/**
 * @brief OpenSSL 에러를 문자열로 저장
 */
static void store_ssl_error(pqc_tls_client_t *client, const char *prefix) {
    unsigned long err = ERR_get_error();
    if (err != 0) {
        char ssl_err[128];
        ERR_error_string_n(err, ssl_err, sizeof(ssl_err));
        snprintf(client->error_buf, sizeof(client->error_buf), "%s: %s", prefix, ssl_err);
    } else {
        snprintf(client->error_buf, sizeof(client->error_buf), "%s", prefix);
    }
}

/**
 * @brief SSL_CTX 초기화
 */
static int init_ssl_ctx(pqc_tls_client_t *client) {
    const SSL_METHOD *method = TLS_client_method();
    client->ssl_ctx = SSL_CTX_new(method);
    if (!client->ssl_ctx) {
        store_ssl_error(client, "Failed to create SSL_CTX");
        return -1;
    }
    
    // TLS 1.3만 사용
    SSL_CTX_set_min_proto_version(client->ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(client->ssl_ctx, TLS1_3_VERSION);
    
    // Cipher suite 설정 (TLS_AES_128_GCM_SHA256)
    if (SSL_CTX_set_ciphersuites(client->ssl_ctx, "TLS_AES_128_GCM_SHA256") != 1) {
        store_ssl_error(client, "Failed to set cipher suite");
        return -1;
    }
    
    // KEM 알고리즘 설정 (groups)
    if (client->config.kem_algorithm) {
        if (SSL_CTX_set1_groups_list(client->ssl_ctx, client->config.kem_algorithm) != 1) {
            store_ssl_error(client, "Failed to set KEM algorithm");
            return -1;
        }
    }
    
    // 서명 알고리즘 설정
    if (client->config.sig_algorithm) {
        if (SSL_CTX_set1_sigalgs_list(client->ssl_ctx, client->config.sig_algorithm) != 1) {
            store_ssl_error(client, "Failed to set signature algorithm");
            return -1;
        }
    }
    
    // 인증서 로드
    if (client->config.cert_file && client->config.key_file) {
        if (SSL_CTX_use_certificate_file(client->ssl_ctx, client->config.cert_file, 
                                         SSL_FILETYPE_PEM) != 1) {
            store_ssl_error(client, "Failed to load client certificate");
            return -1;
        }
        
        if (SSL_CTX_use_PrivateKey_file(client->ssl_ctx, client->config.key_file, 
                                        SSL_FILETYPE_PEM) != 1) {
            store_ssl_error(client, "Failed to load client private key");
            return -1;
        }
        
        if (SSL_CTX_check_private_key(client->ssl_ctx) != 1) {
            store_ssl_error(client, "Private key does not match certificate");
            return -1;
        }
    }
    
    // CA 인증서 로드
    if (client->config.ca_file) {
        if (SSL_CTX_load_verify_locations(client->ssl_ctx, client->config.ca_file, NULL) != 1) {
            store_ssl_error(client, "Failed to load CA certificate");
            return -1;
        }
    }
    
    // 서버 인증서 검증 모드 설정
    if (client->config.verify_peer) {
        SSL_CTX_set_verify(client->ssl_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    } else {
        SSL_CTX_set_verify(client->ssl_ctx, SSL_VERIFY_NONE, NULL);
    }
    
    return 0;
}

/**
 * @brief TCP 연결 수립
 */
static int tcp_connect(pqc_tls_client_t *client) {
    struct addrinfo hints, *res, *rp;
    char port_str[16];
    int ret;
    
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    
    snprintf(port_str, sizeof(port_str), "%u", client->config.port);
    
    ret = getaddrinfo(client->config.host, port_str, &hints, &res);
    if (ret != 0) {
        snprintf(client->error_buf, sizeof(client->error_buf), 
                 "getaddrinfo failed: %s", gai_strerror(ret));
        return -1;
    }
    
    // 연결 시도
    for (rp = res; rp != NULL; rp = rp->ai_next) {
        client->sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (client->sockfd == -1) {
            continue;
        }
        
        // 타임아웃 설정
        if (client->config.timeout_ms > 0) {
            struct timeval tv;
            tv.tv_sec = client->config.timeout_ms / 1000;
            tv.tv_usec = (client->config.timeout_ms % 1000) * 1000;
            setsockopt(client->sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            setsockopt(client->sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        }
        
        if (connect(client->sockfd, rp->ai_addr, rp->ai_addrlen) == 0) {
            break; // Success
        }
        
        close(client->sockfd);
        client->sockfd = -1;
    }
    
    freeaddrinfo(res);
    
    if (client->sockfd == -1) {
        snprintf(client->error_buf, sizeof(client->error_buf), 
                 "Failed to connect to %s:%u", client->config.host, client->config.port);
        return -1;
    }
    
    return 0;
}

/**
 * @brief TLS 핸드셰이크 수행 및 메트릭 수집
 */
static int perform_handshake(pqc_tls_client_t *client) {
    double start_time = get_time_ms();
    
    client->ssl = SSL_new(client->ssl_ctx);
    if (!client->ssl) {
        store_ssl_error(client, "Failed to create SSL object");
        return -1;
    }
    
    SSL_set_fd(client->ssl, client->sockfd);
    
    // 핸드셰이크 수행
    int ret = SSL_connect(client->ssl);
    double end_time = get_time_ms();
    
    if (ret != 1) {
        int ssl_err = SSL_get_error(client->ssl, ret);
        snprintf(client->error_buf, sizeof(client->error_buf), 
                 "SSL handshake failed: error code %d", ssl_err);
        ERR_print_errors_fp(stderr);
        return -1;
    }
    
    // 메트릭 수집
    client->metrics.handshake_time_ms = end_time - start_time;
    
    // 협상된 알고리즘 정보 수집
    const char *cipher = SSL_get_cipher_name(client->ssl);
    
    if (cipher) {
        snprintf(client->metrics.cipher_suite, sizeof(client->metrics.cipher_suite), "%s", cipher);
    }
    
    // 협상된 그룹 (KEM) 정보
    int group_id = SSL_get_shared_group(client->ssl, 0);
    if (group_id != 0) {
        const char *group_name = SSL_group_to_name(client->ssl, group_id);
        if (group_name) {
            snprintf(client->metrics.negotiated_kem, sizeof(client->metrics.negotiated_kem), 
                     "%s", group_name);
        }
    }
    
    // 인증서 체인 크기 측정
    X509 *peer_cert = SSL_get_peer_certificate(client->ssl);
    if (peer_cert) {
        int cert_size = i2d_X509(peer_cert, NULL);
        if (cert_size > 0) {
            client->metrics.cert_chain_size = cert_size;
        }
        X509_free(peer_cert);
    }
    
    return 0;
}

// ============================================================================
// Public API Implementation
// ============================================================================

pqc_tls_client_t* pqc_tls_client_create(const pqc_tls_config_t *config) {
    if (!config || !config->host) {
        return NULL;
    }
    
    pqc_tls_client_t *client = calloc(1, sizeof(pqc_tls_client_t));
    if (!client) {
        return NULL;
    }
    
    // 설정 복사
    client->config = *config;
    client->sockfd = -1;
    client->connected = false;
    
    // 기본값 설정
    if (client->config.timeout_ms == 0) {
        client->config.timeout_ms = 10000; // 10초 기본 타임아웃
    }
    if (client->config.verify_peer == false && config->ca_file != NULL) {
        client->config.verify_peer = true; // CA가 제공되면 기본적으로 검증
    }
    
    // OpenSSL 초기화
    if (init_ssl_ctx(client) != 0) {
        pqc_tls_client_destroy(client);
        return NULL;
    }
    
    return client;
}

int pqc_tls_client_connect(pqc_tls_client_t *client) {
    if (!client) {
        return -1;
    }
    
    if (client->connected) {
        snprintf(client->error_buf, sizeof(client->error_buf), "Already connected");
        return -1;
    }
    
    // TCP 연결
    if (tcp_connect(client) != 0) {
        return -1;
    }
    
    // TLS 핸드셰이크
    if (perform_handshake(client) != 0) {
        close(client->sockfd);
        client->sockfd = -1;
        return -1;
    }
    
    client->connected = true;
    return 0;
}

bool pqc_tls_client_is_connected(const pqc_tls_client_t *client) {
    return client ? client->connected : false;
}

void pqc_tls_client_disconnect(pqc_tls_client_t *client) {
    if (!client) {
        return;
    }
    
    if (client->ssl) {
        // Graceful shutdown
        SSL_shutdown(client->ssl);
        SSL_free(client->ssl);
        client->ssl = NULL;
    }
    
    if (client->sockfd >= 0) {
        // Ensure socket closes immediately
        struct linger linger_opt = {1, 0};  // Enable linger with 0 timeout
        setsockopt(client->sockfd, SOL_SOCKET, SO_LINGER, &linger_opt, sizeof(linger_opt));
        
        shutdown(client->sockfd, SHUT_RDWR);  // Shutdown both directions
        close(client->sockfd);
        client->sockfd = -1;
    }
    
    client->connected = false;
}

void pqc_tls_client_destroy(pqc_tls_client_t *client) {
    if (!client) {
        return;
    }
    
    pqc_tls_client_disconnect(client);
    
    if (client->ssl_ctx) {
        SSL_CTX_free(client->ssl_ctx);
    }
    
    free(client);
}

int pqc_tls_client_send(pqc_tls_client_t *client, const void *data, size_t len) {
    if (!client || !client->connected || !client->ssl) {
        return -1;
    }
    
    int ret = SSL_write(client->ssl, data, len);
    if (ret > 0) {
        client->metrics.bytes_sent += ret;
    }
    
    return ret;
}

int pqc_tls_client_recv(pqc_tls_client_t *client, void *buffer, size_t len) {
    if (!client || !client->connected || !client->ssl) {
        return -1;
    }
    
    int ret = SSL_read(client->ssl, buffer, len);
    if (ret > 0) {
        client->metrics.bytes_received += ret;
    }
    
    return ret;
}

int pqc_tls_client_get_metrics(const pqc_tls_client_t *client, pqc_metrics_t *metrics) {
    if (!client || !metrics) {
        return -1;
    }
    
    *metrics = client->metrics;
    return 0;
}

const char* pqc_tls_client_get_error(const pqc_tls_client_t *client) {
    return client ? client->error_buf : "Invalid client";
}

int pqc_tls_client_get_fd(const pqc_tls_client_t *client) {
    return client ? client->sockfd : -1;
}

const char* pqc_tls_get_openssl_version(void) {
    return OpenSSL_version(OPENSSL_VERSION);
}

int pqc_tls_list_kem_algorithms(char *buffer, size_t buf_size) {
    if (!buffer || buf_size == 0) {
        return -1;
    }
    
    // OpenSSL 3.6.0에서 지원하는 PQC KEM 알고리즘
    const char *algorithms = "mlkem512, mlkem768, mlkem1024, x25519, x448";
    snprintf(buffer, buf_size, "%s", algorithms);
    
    return 0;
}

int pqc_tls_list_sig_algorithms(char *buffer, size_t buf_size) {
    if (!buffer || buf_size == 0) {
        return -1;
    }
    
    // OpenSSL 3.6.0에서 지원하는 PQC 서명 알고리즘
    const char *algorithms = "mldsa44, mldsa65, mldsa87, ecdsa_secp256r1_sha256, ecdsa_secp384r1_sha384";
    snprintf(buffer, buf_size, "%s", algorithms);
    
    return 0;
}


