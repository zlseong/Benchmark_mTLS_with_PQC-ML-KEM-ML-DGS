/**
 * @file test_pqc_handshake.c
 * @brief PQC TLS Handshake Test Program
 * 
 * OpenSSL 3.6.0 네이티브 PQC 지원 테스트
 */

#include "pqc_tls_client.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void print_usage(const char *prog_name) {
    printf("Usage: %s --host <host> --port <port> [options]\n\n", prog_name);
    printf("Options:\n");
    printf("  --host <host>        Server hostname or IP (required)\n");
    printf("  --port <port>        Server port (required)\n");
    printf("  --cert <file>        Client certificate file\n");
    printf("  --key <file>         Client private key file\n");
    printf("  --ca <file>          CA certificate file\n");
    printf("  --kem <algorithm>    KEM algorithm (default: mlkem768)\n");
    printf("                       Options: mlkem512, mlkem768, mlkem1024\n");
    printf("  --sig <algorithm>    Signature algorithm (default: ecdsa_secp256r1_sha256)\n");
    printf("                       Options: ecdsa_secp256r1_sha256, mldsa44, mldsa65, mldsa87\n");
    printf("  --help               Show this help message\n\n");
    printf("Examples:\n");
    printf("  # Hybrid mode (ML-KEM + ECDSA)\n");
    printf("  %s --host 192.168.1.10 --port 8443 \\\n", prog_name);
    printf("    --cert certs/client_cert.pem \\\n");
    printf("    --key certs/client_key.pem \\\n");
    printf("    --ca certs/ca_cert.pem \\\n");
    printf("    --kem mlkem768 --sig ecdsa_secp256r1_sha256\n\n");
    printf("  # Full PQC mode (ML-KEM + ML-DSA)\n");
    printf("  %s --host 192.168.1.10 --port 8443 \\\n", prog_name);
    printf("    --cert certs/client_cert_pqc.pem \\\n");
    printf("    --key certs/client_key_pqc.pem \\\n");
    printf("    --ca certs/ca_cert_pqc.pem \\\n");
    printf("    --kem mlkem768 --sig mldsa65\n");
}

int main(int argc, char *argv[]) {
    pqc_tls_config_t config = {0};
    
    // 기본값 설정
    config.kem_algorithm = "mlkem768";
    config.sig_algorithm = "ecdsa_secp256r1_sha256";
    config.timeout_ms = 10000;
    config.verify_peer = false;
    
    // 인자 파싱
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "--host") == 0 && i + 1 < argc) {
            config.host = argv[++i];
        } else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            config.port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--cert") == 0 && i + 1 < argc) {
            config.cert_file = argv[++i];
        } else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
            config.key_file = argv[++i];
        } else if (strcmp(argv[i], "--ca") == 0 && i + 1 < argc) {
            config.ca_file = argv[++i];
            config.verify_peer = true;
        } else if (strcmp(argv[i], "--kem") == 0 && i + 1 < argc) {
            config.kem_algorithm = argv[++i];
        } else if (strcmp(argv[i], "--sig") == 0 && i + 1 < argc) {
            config.sig_algorithm = argv[++i];
        }
    }
    
    // 필수 인자 확인
    if (!config.host || config.port == 0) {
        fprintf(stderr, "Error: --host and --port are required\n\n");
        print_usage(argv[0]);
        return 1;
    }
    
    printf("=================================================================\n");
    printf("   PQC-Hybrid TLS Handshake Test\n");
    printf("=================================================================\n");
    printf("OpenSSL Version: %s\n", pqc_tls_get_openssl_version());
    printf("\n");
    
    // 지원되는 알고리즘 출력
    char kem_list[256];
    char sig_list[256];
    pqc_tls_list_kem_algorithms(kem_list, sizeof(kem_list));
    pqc_tls_list_sig_algorithms(sig_list, sizeof(sig_list));
    
    printf("Supported KEM algorithms: %s\n", kem_list);
    printf("Supported SIG algorithms: %s\n", sig_list);
    printf("\n");
    
    // 연결 정보 출력
    printf("Connection Configuration:\n");
    printf("  Server:     %s:%u\n", config.host, config.port);
    printf("  KEM:        %s\n", config.kem_algorithm);
    printf("  Signature:  %s\n", config.sig_algorithm);
    printf("  Client Cert: %s\n", config.cert_file ? config.cert_file : "(none)");
    printf("  CA Cert:     %s\n", config.ca_file ? config.ca_file : "(none)");
    printf("  Verify Peer: %s\n", config.verify_peer ? "yes" : "no");
    printf("\n");
    
    // 클라이언트 생성
    printf("Creating PQC TLS client...\n");
    pqc_tls_client_t *client = pqc_tls_client_create(&config);
    if (!client) {
        fprintf(stderr, "❌ Failed to create PQC TLS client\n");
        return 1;
    }
    printf("✅ Client created\n\n");
    
    // 연결 및 핸드셰이크
    printf("Connecting to server and performing TLS handshake...\n");
    int ret = pqc_tls_client_connect(client);
    if (ret != 0) {
        fprintf(stderr, "❌ Connection failed: %s\n", pqc_tls_client_get_error(client));
        pqc_tls_client_destroy(client);
        return 1;
    }
    printf("✅ Connection established!\n\n");
    
    // 메트릭 조회
    pqc_metrics_t metrics;
    if (pqc_tls_client_get_metrics(client, &metrics) == 0) {
        printf("=================================================================\n");
        printf("   TLS Handshake Metrics\n");
        printf("=================================================================\n");
        printf("Handshake Time:         %.2f ms\n", metrics.handshake_time_ms);
        printf("Certificate Verify Time: %.2f ms\n", metrics.cert_verify_time_ms);
        printf("Bytes Sent:             %u bytes\n", metrics.bytes_sent);
        printf("Bytes Received:         %u bytes\n", metrics.bytes_received);
        printf("Certificate Chain Size: %u bytes\n", metrics.cert_chain_size);
        
        if (metrics.negotiated_kem[0] != '\0') {
            printf("Negotiated KEM:         %s\n", metrics.negotiated_kem);
        }
        if (metrics.negotiated_sig[0] != '\0') {
            printf("Negotiated Signature:   %s\n", metrics.negotiated_sig);
        }
        if (metrics.cipher_suite[0] != '\0') {
            printf("Cipher Suite:           %s\n", metrics.cipher_suite);
        }
        
        printf("=================================================================\n\n");
    }
    
    // 간단한 데이터 송수신 테스트
    printf("Sending test message...\n");
    const char *test_msg = "Hello from PQC TLS client!";
    ret = pqc_tls_client_send(client, test_msg, strlen(test_msg));
    if (ret > 0) {
        printf("✅ Sent %d bytes\n", ret);
    } else {
        fprintf(stderr, "❌ Failed to send data\n");
    }
    
    printf("\nReceiving response...\n");
    char buffer[1024];
    ret = pqc_tls_client_recv(client, buffer, sizeof(buffer) - 1);
    if (ret > 0) {
        buffer[ret] = '\0';
        printf("✅ Received %d bytes: %s\n", ret, buffer);
    } else if (ret == 0) {
        printf("⚠️  Connection closed by server\n");
    } else {
        fprintf(stderr, "❌ Failed to receive data\n");
    }
    
    // 정리
    printf("\nClosing connection...\n");
    pqc_tls_client_disconnect(client);
    pqc_tls_client_destroy(client);
    
    printf("✅ Test completed successfully!\n");
    printf("=================================================================\n");
    
    return 0;
}

