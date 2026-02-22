#!/bin/bash
set -e

# Benchmark Configuration
BATCH_SIZE=5000
ORDERER_PORT=10802
TARGET_IP="127.0.0.1"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}======================================================${NC}"
echo -e "${BLUE}   A D R I A   D O C K E R   B E N C H M A R K   ${NC}"
echo -e "${BLUE}======================================================${NC}"

# 1. Setup Environment
echo -e "${GREEN}[INFO] Preparing Identities & Configuration...${NC}"
# Assume executed from root or tests/benchmarks
if [ -d "core-sdk" ]; then
    # Already in root
    :
elif [ -d "../core-sdk" ]; then
    cd ..
elif [ -d "../../core-sdk" ]; then
    cd ../..
else
    echo -e "${RED}[ERROR] Could not find project root (core-sdk not found)${NC}"
    exit 1
fi

echo -e "${GREEN}[INFO] Building Core SDK (Required for CLI)...${NC}"
cd core-sdk && zig build -Doptimize=ReleaseSafe && cd ..

echo -e "${GREEN}[INFO] Cleaning up old containers...${NC}"
docker-compose down -v --remove-orphans > /dev/null 2>&1 || true
rm -rf apl_data
mkdir -p apl_data

# Create identities
./core-sdk/zig-out/bin/apl wallet create orderer > /dev/null || true
./core-sdk/zig-out/bin/apl wallet create admin > /dev/null || true
./core-sdk/zig-out/bin/apl wallet create bench_user > /dev/null || true
./core-sdk/zig-out/bin/apl wallet create root_ca > /dev/null || true

# Issue certificates
./core-sdk/zig-out/bin/apl cert issue root_ca orderer > /dev/null
./core-sdk/zig-out/bin/apl cert issue root_ca admin > /dev/null
./core-sdk/zig-out/bin/apl cert issue root_ca bench_user > /dev/null

ROOT_PUBKEY=$(./core-sdk/zig-out/bin/apl pubkey root_ca --raw | head -n 1)

# Generate node configuration
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

trap 'mv adria-config.example.json.bak adria-config.example.json 2>/dev/null || true; mv Dockerfile.bak Dockerfile 2>/dev/null || true; docker-compose down -v > /dev/null 2>&1 || true' EXIT

# Build and Start
echo -e "${GREEN}[INFO] Starting Cluster (Orderer + 2 Peers)...${NC}"
docker-compose up -d --build

echo -e "${GREEN}[INFO] Waiting 10s for cluster formation...${NC}"
sleep 10

# 2. Skip Redundant Build step since we did it above
# (Already built before identity generation)

# 3. Run Benchmark
echo -e "${GREEN}[INFO] Probing Orderer ${TARGET_IP}:${ORDERER_PORT}...${NC}"
if nc -z -v -w 5 $TARGET_IP $ORDERER_PORT; then
    echo -e "${GREEN}[INFO] Port ${ORDERER_PORT} is OPEN${NC}"
else
    echo -e "${RED}[ERROR] Port ${ORDERER_PORT} is CLOSED or UNREACHABLE${NC}"
    echo -e "${RED}[HINT] Ensure docker-compose is running and ports are mapped.${NC}"
    exit 1
fi

echo -e "${GREEN}[INFO] Running Pipelined Benchmark against Orderer...${NC}"
echo -e "${GREEN}[INFO] Target Batch Size: ${BATCH_SIZE}${NC}"

# Run the e2e benchmark with args
if ./core-sdk/zig-out/bin/bench_e2e --batch "$BATCH_SIZE" --ip "$TARGET_IP" --port "$ORDERER_PORT" --wallet bench_user; then
    echo -e "${GREEN}[PASS] Benchmark Execution Successful${NC}"
else
    echo -e "${RED}[FAIL] Benchmark Execution Failed${NC}"
    exit 1
fi

# 4. Check Peer Propagation
echo -e "${BLUE}------------------------------------------------------${NC}"
echo -e "${BLUE}   C H E C K I N G   P R O P A G A T I O N   ${NC}"
echo -e "${BLUE}------------------------------------------------------${NC}"

echo -e "${GREEN}[INFO] Inspecting Peer Logs for Block Commit...${NC}"
# Inspect logs for last committed block
PEER1_LOG=$(docker logs adria-peer1 2>&1 | grep "Executed Block" | tail -n 1)
PEER2_LOG=$(docker logs adria-peer2 2>&1 | grep "Executed Block" | tail -n 1)

echo -e "Peer 1 (adria-peer1): ${PEER1_LOG:="[NO BLOCKS COMMITTED]"}"
echo -e "Peer 2 (adria-peer2): ${PEER2_LOG:="[NO BLOCKS COMMITTED]"}"

echo -e "${GREEN}[INFO] Benchmark Complete. Use 'docker-compose down' to cleanup.${NC}"
