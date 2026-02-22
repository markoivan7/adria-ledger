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
echo -e "${GREEN}[TEST] Building Core SDK (Required for CLI)...${NC}"
cd core-sdk && zig build -Doptimize=ReleaseSafe && cd ..

echo -e "${GREEN}[TEST] Preparing Identities...${NC}"
docker-compose down -v 2>/dev/null || true
rm -rf apl_data
mkdir -p apl_data
./core-sdk/zig-out/bin/apl wallet create orderer > /dev/null || true
./core-sdk/zig-out/bin/apl wallet create admin > /dev/null || true
./core-sdk/zig-out/bin/apl wallet create root_ca > /dev/null || true

./core-sdk/zig-out/bin/apl cert issue root_ca orderer > /dev/null
./core-sdk/zig-out/bin/apl cert issue root_ca admin > /dev/null

ROOT_PUBKEY=$(./core-sdk/zig-out/bin/apl pubkey root_ca --raw | head -n 1)

cat <<EOF > adria-config.json
{
    "network": {
        "p2p_port": 10801,
        "api_port": 10802,
        "discovery": true,
        "seeds": [],
        "network_id": 1,
        "bind_address": "0.0.0.0"
    },
    "storage": {
        "data_dir": "data",
        "log_level": "info"
    },
    "consensus": {
        "mode": "solo",
        "role": "orderer",
        "seed_root_ca": "$ROOT_PUBKEY"
    }
}
EOF

# Workaround for Docker Desktop macOS bind mount permission issues:
# Briefly overwrite the example config and patch Dockerfile so it gets copied into the image during build.
cp adria-config.example.json adria-config.example.json.bak
cp adria-config.json adria-config.example.json
cp Dockerfile Dockerfile.bak
echo "COPY apl_data/ /app/data/" >> Dockerfile

trap 'mv adria-config.example.json.bak adria-config.example.json 2>/dev/null || true; mv Dockerfile.bak Dockerfile 2>/dev/null || true; docker-compose down -v 2>/dev/null || true' EXIT

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

# We need to clean up local DB first so we don't mix state
rm -f ledger.db


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
# Cleanup handled by trap

echo -e "${GREEN}[PASS] Docker Functional Test Passed${NC}"
