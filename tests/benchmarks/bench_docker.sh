#!/bin/bash
set -e

# Benchmark Configuration
BATCH_SIZE=2000
ORDERER_PORT=10802

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}======================================================${NC}"
echo -e "${BLUE}   A D R I A   D O C K E R   B E N C H M A R K   ${NC}"
echo -e "${BLUE}======================================================${NC}"

# 1. Setup Environment
echo -e "${GREEN}[INFO] Building Docker Cluster...${NC}"
cd "$(dirname "$0")/../.."

# Clean slate
docker-compose down -v --remove-orphans > /dev/null 2>&1 || true

# Build and Start
docker-compose up -d --build

echo -e "${GREEN}[INFO] Waiting 10s for cluster formation...${NC}"
sleep 10

# 2. Build Benchmark Tool
echo -e "${GREEN}[INFO] Building Benchmark Tool (Locally)...${NC}"
cd core-sdk
zig build
cd ..

# 3. Run Benchmark
echo -e "${GREEN}[INFO] Running Benchmark against Orderer (Host -> Docker:10802)${NC}"
echo -e "${GREEN}[INFO] Target Batch Size: ${BATCH_SIZE}${NC}"

echo -e "${GREEN}[INFO] Probing Orderer Port 10802...${NC}"
if nc -z -v -w 5 localhost 10802; then
    echo -e "${GREEN}[INFO] Port 10802 is OPEN${NC}"
else
    echo -e "${RED}[ERROR] Port 10802 is CLOSED or UNREACHABLE${NC}"
    exit 1
fi

# Run the e2e benchmark
# Note: bench_e2e uses localhost:10802 by default, which maps to our Orderer
./core-sdk/zig-out/bin/bench_e2e

# 4. Check Peer Propagation (Optional but recommended for multi-node)
echo -e "${BLUE}------------------------------------------------------${NC}"
echo -e "${BLUE}   C H E C K I N G   P R O P A G A T I O N   ${NC}"
echo -e "${BLUE}------------------------------------------------------${NC}"

# We can't query peers easily from host because their ports aren't exposed in docker-compose.yml
# But we can inspect their logs for block commits
PEER1_HEIGHT=$(docker logs adria-peer1 2>&1 | grep "Committed block" | tail -n 1)
PEER2_HEIGHT=$(docker logs adria-peer2 2>&1 | grep "Committed block" | tail -n 1)

echo -e "Peer 1 Status: ${PEER1_HEIGHT:-"No blocks committed yet"}"
echo -e "Peer 2 Status: ${PEER2_HEIGHT:-"No blocks committed yet"}"

echo -e "${GREEN}[INFO] Benchmark Complete. Use 'docker-compose down' to cleanup.${NC}"
