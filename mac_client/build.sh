#!/bin/bash
# Build script for Vehicle Mobile Gateway

set -e

echo "==================================================================="
echo "   Vehicle Mobile Gateway - Build Script"
echo "==================================================================="

# 색상 정의
RED='\033[0:31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# OpenSSL 버전 확인
echo -e "\n${YELLOW}Checking OpenSSL version...${NC}"

# Homebrew OpenSSL 우선 사용
if [ -f "/opt/homebrew/bin/openssl" ]; then
    OPENSSL_BIN="/opt/homebrew/bin/openssl"
elif [ -f "/usr/local/bin/openssl" ]; then
    OPENSSL_BIN="/usr/local/bin/openssl"
else
    OPENSSL_BIN="openssl"
fi

OPENSSL_VERSION=$($OPENSSL_BIN version | awk '{print $2}')
echo "Found OpenSSL: $OPENSSL_VERSION"

if [[ "$OPENSSL_VERSION" < "3.6" ]]; then
    echo -e "${RED}Error: OpenSSL 3.6.0 or higher is required for native PQC support${NC}"
    echo "Current version: $OPENSSL_VERSION"
    exit 1
fi

echo -e "${GREEN}✅ OpenSSL version OK${NC}"

# PQC 지원 확인
echo -e "\n${YELLOW}Checking PQC algorithm support...${NC}"
KEM_SUPPORT=$($OPENSSL_BIN list -kem-algorithms 2>/dev/null | grep -i mlkem | wc -l)
if [ "$KEM_SUPPORT" -gt 0 ]; then
    echo -e "${GREEN}✅ ML-KEM algorithms supported${NC}"
else
    echo -e "${RED}⚠️  Warning: ML-KEM algorithms not found${NC}"
    echo "Please ensure OpenSSL was built with PQC support"
fi

# 빌드 디렉토리 생성
echo -e "\n${YELLOW}Creating build directory...${NC}"
mkdir -p build
cd build

# CMake 설정
echo -e "\n${YELLOW}Running CMake...${NC}"
cmake .. \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
    -DOPENSSL_ROOT_DIR=/opt/homebrew/opt/openssl@3 \
    -DOPENSSL_CRYPTO_LIBRARY=/opt/homebrew/opt/openssl@3/lib/libcrypto.dylib \
    -DOPENSSL_SSL_LIBRARY=/opt/homebrew/opt/openssl@3/lib/libssl.dylib

# 빌드
echo -e "\n${YELLOW}Building project...${NC}"
make -j$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)

# 빌드 결과 확인
echo -e "\n==================================================================="
echo -e "   Build Summary"
echo -e "==================================================================="

if [ -f "test_pqc_handshake" ]; then
    echo -e "${GREEN}✅ test_pqc_handshake${NC}"
else
    echo -e "${RED}❌ test_pqc_handshake${NC}"
fi

if [ -f "test_https" ]; then
    echo -e "${GREEN}✅ test_https${NC}"
else
    echo -e "${RED}❌ test_https${NC}"
fi

if [ -f "test_mqtt" ]; then
    echo -e "${GREEN}✅ test_mqtt${NC}"
else
    echo -e "${YELLOW}⚠️  test_mqtt (optional - Paho MQTT C++ required)${NC}"
fi

echo -e "\n==================================================================="
echo -e "${GREEN}Build completed successfully!${NC}"
echo -e "==================================================================="
echo -e "\nTest programs are in: $(pwd)"
echo -e "\nNext steps:"
echo -e "  1. Prepare certificates (see docs/OPENSSL_PQC_SETUP.md)"
echo -e "  2. Run tests:"
echo -e "     ./test_pqc_handshake --host <server> --port <port>"
echo -e "     ./test_https --url https://<server>:<port>/api/status"
echo -e "     ./test_mqtt --broker <server> --port 8883"
echo -e "==================================================================="

