#!/bin/bash
set -e

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}======================================================${NC}"
echo -e "${GREEN}   A D R I A   D O C K E R   F U N C T I O N A L   ${NC}"
echo -e "${GREEN}======================================================${NC}"

# 1. Setup
echo -e "${GREEN}[TEST] Starting Docker Cluster...${NC}"
docker-compose up -d --build

echo -e "${GREEN}[TEST] Waiting for API (127.0.0.1:10802)...${NC}"
# Wait loop
for i in {1..30}; do
    if nc -z 127.0.0.1 10802; then
        echo -e "${GREEN}[OK] Port 10802 is open!${NC}"
        break
    fi
    echo -n "."
    sleep 1
done

# Double check if it timed out
if ! nc -z 127.0.0.1 10802; then
    echo -e "${RED}[ERROR] Timeout waiting for 127.0.0.1:10802${NC}"
    docker-compose logs
    docker-compose down
    exit 1
fi

# Give it a second to actually service requests
sleep 2

# 2. Run Python Client Test
echo -e "${GREEN}[TEST] Running gl_app.py against Docker Orderer...${NC}"

# Ensure CLI is built (needed for gl_app.py)
cd core-sdk && zig build && cd ..

# We need to clean up local DB first so we don't mix state
rm -f ledger.db

# Create Wallet (Locally)
./core-sdk/zig-out/bin/apl wallet create admin > /dev/null 2>&1 || true

# Run Record
echo -e "${GREEN}[TEST] Recording Entry...${NC}"
# gl_app.py uses localhost:10802 by default via the 'apl' CLI which uses config defaults or current config
# WARNING: The 'apl' CLI reads 'adria-config.json'. 
# IF adria-config.json points to 127.0.0.1:10802, this works because we mapped the port.

./tests/functional/gl_app.py record --debit "Docker:Test" --credit "Docker:Cash" --amount 999.00 --desc "Docker Test"

# Verify
echo -e "${GREEN}[TEST] Verifying...${NC}"
./tests/functional/gl_app.py list

# 3. Cleanup
echo -e "${GREEN}[TEST] Cleaning up...${NC}"
docker-compose down

echo -e "${GREEN}[PASS] Docker Functional Test Passed${NC}"
