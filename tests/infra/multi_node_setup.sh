#!/bin/bash
set -e

# Cleanup on exit
trap 'kill $(jobs -p) 2>/dev/null' EXIT

# Build
echo "[INFO] Building Adria..."
cd core-sdk
zig build
cd ..

BIN="./core-sdk/zig-out/bin/adria_server"

echo "[INFO] Starting Node 1 (Orderer) on 10801/10802..."
$BIN --orderer --p2p-port=10801 --api-port=10802 --no-discovery > logs/node1.log 2>&1 &
PID1=$!

echo "[INFO] Starting Node 2 (Peer) on 10803/10804..."
export ADRIA_BOOTSTRAP="127.0.0.1:10801"
$BIN --p2p-port=10803 --api-port=10804 --no-discovery > logs/node2.log 2>&1 &
PID2=$!

echo "[INFO] Starting Node 3 (Peer) on 10805/10806..."
export ADRIA_BOOTSTRAP="127.0.0.1:10801"
$BIN --p2p-port=10805 --api-port=10806 --no-discovery > logs/node3.log 2>&1 &
PID3=$!

echo "[INFO] Nodes running. PIDs: $PID1, $PID2, $PID3"
echo "[INFO] Waiting 5s for handshake..."
sleep 5

echo "[INFO] Checking Status of Node 1..."
./core-sdk/zig-out/bin/apl status

echo "[INFO] Success! Press Ctrl+C to stop cluster."
wait
