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
echo -e "${GREEN}[INFO] Building Docker Cluster...${NC}"
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

# Clean slate
echo -e "${GREEN}[INFO] Cleaning up old containers...${NC}"
docker-compose down -v --remove-orphans > /dev/null 2>&1 || true

# Build and Start
echo -e "${GREEN}[INFO] Starting Cluster (Orderer + 2 Peers)...${NC}"
docker-compose up -d --build

echo -e "${GREEN}[INFO] Waiting 10s for cluster formation...${NC}"
sleep 10

# 2. Build Benchmark Tool
echo -e "${GREEN}[INFO] Building Benchmark Tool (Locally)...${NC}"
cd core-sdk
zig build -Doptimize=ReleaseSafe
cd ..

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
if ./core-sdk/zig-out/bin/bench_e2e --batch "$BATCH_SIZE" --ip "$TARGET_IP" --port "$ORDERER_PORT"; then
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
