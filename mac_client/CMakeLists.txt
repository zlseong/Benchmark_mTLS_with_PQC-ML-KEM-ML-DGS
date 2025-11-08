cmake_minimum_required(VERSION 3.15)
project(PQC_TLS_Benchmark C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

if(OpenSSL_FOUND)
    message(STATUS "Found OpenSSL ${OPENSSL_VERSION}")
    message(STATUS "OpenSSL include: ${OPENSSL_INCLUDE_DIR}")
    message(STATUS "OpenSSL libraries: ${OPENSSL_LIBRARIES}")
endif()

# PQC TLS library
add_library(pqc_tls STATIC
    pqc_tls/pqc_tls_client.c
)

target_include_directories(pqc_tls PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(pqc_tls PUBLIC
    OpenSSL::SSL
    OpenSSL::Crypto
)

# Test executable
add_executable(test_pqc_handshake
    test_pqc_handshake.c
)

target_link_libraries(test_pqc_handshake PRIVATE
    pqc_tls
)

# Configuration summary
message(STATUS "")
message(STATUS "=== PQC TLS Benchmark Configuration ===")
message(STATUS "OpenSSL Version: ${OPENSSL_VERSION}")
message(STATUS "C Compiler: ${CMAKE_C_COMPILER}")
message(STATUS "Build Type: ${CMAKE_BUILD_TYPE}")
message(STATUS "========================================")
message(STATUS "")

