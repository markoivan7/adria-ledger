#!/bin/bash
set -e

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}[INFO] Building and starting Adria Docker Cluster...${NC}"

# Ensure we are in the project root
cd "$(dirname "$0")/../.."

# Build and Start
docker-compose down # Cleanup old run
docker-compose up -d --build

echo -e "${GREEN}[INFO] Cluster started! Waiting 10s for peers to connect...${NC}"
sleep 10

# Check running containers
RUNNING=$(docker ps | grep adria- | wc -l)
if [ "$RUNNING" -ne 3 ]; then
    echo -e "${RED}[ERROR] Expected 3 running containers, found $RUNNING${NC}"
    docker-compose ps
    exit 1
fi

echo -e "${GREEN}[INFO] Checking Orderer Logs for connections...${NC}"
docker logs adria-orderer --tail 50 > logs/orderer_startup.log 2>&1 || true

echo -e "${GREEN}[INFO] Running Connectivity Test...${NC}"
# Use the local `apl` CLI to query the Orderer exposed on localhost:10802
./core-sdk/zig-out/bin/apl status

if [ $? -eq 0 ]; then
    echo -e "${GREEN}[SUCCESS] Docker Cluster is operational!${NC}"
    echo -e "   - Orderer: localhost:10802"
    echo -e "   - Peer 1: Internal"
    echo -e "   - Peer 2: Internal"
    echo -e "To stop: docker-compose down"
else
    echo -e "${RED}[ERROR] Failed to connect to Orderer API${NC}"
    exit 1
fi
