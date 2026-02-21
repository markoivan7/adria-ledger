#!/bin/bash
# test_offline_signing.sh
# Tests the full CLI offline signing workflow to ensure air-gapped security model works

set -e

# Configuration
SERVER_IP="127.0.0.1"
API_PORT="10802"
# Get absolute path to project root
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$(dirname $(dirname $SCRIPT_DIR))"
BIN_DIR="$PROJECT_ROOT/core-sdk/zig-out/bin"
SERVER_BIN="$BIN_DIR/adria_server"
CLI_BIN="$BIN_DIR/apl"

echo "Using BIN_DIR: $BIN_DIR"
echo "========================================"
echo "    A D R I A   O F F L I N E   T E S T "
echo "========================================"

# [SETUP] Clean environment
rm -rf apl_data adria-config.json

echo "[SETUP] Ensuring port $API_PORT is free..."
lsof -ti :$API_PORT | xargs kill -9 2>/dev/null || true
lsof -ti :10801 | xargs kill -9 2>/dev/null || true # P2P port
sleep 1

# [STEP 1] Start the Server
echo "[SETUP] Starting Server..."
$SERVER_BIN --bootstrap --orderer &
SERVER_PID=$!
sleep 2 # Wait for server to boot

# Ensure the server processes actually exit on script exit
trap "echo '[CLEANUP] Stopping Server...'; kill -9 $SERVER_PID 2>/dev/null || true" EXIT

# [STEP 2] Create wallet
echo "\n[TEST] Creating offline wallet..."
$CLI_BIN wallet create offline_tester > /dev/null

# Get raw 64 character hex string from `apl address`
ADDRESS=$($CLI_BIN address offline_tester --raw)
if [ -z "$ADDRESS" ]; then
    echo "[FAIL] Could not get Address from CLI"
    exit 1
fi
echo "[PASS] Address generated: $ADDRESS"

# [STEP 3] Fetch Status & Nonce (Online Operation)
echo "\n[TEST] Fetching Network ID..."
NETWORK_ID=$($CLI_BIN status --raw | grep -o "NETWORK_ID=[0-9]*" | cut -d'=' -f2 | tr -d '\r')
if [ -z "$NETWORK_ID" ]; then
    echo "[FAIL] Could not fetch Network ID"
    exit 1
fi
echo "[PASS] Network ID: $NETWORK_ID"

echo "\n[TEST] Fetching Nonce..."
NONCE=$($CLI_BIN nonce $ADDRESS --raw)
if [ -z "$NONCE" ]; then
    echo "[FAIL] Could not fetch Nonce"
    exit 1
fi
echo "[PASS] Nonce: $NONCE"


# [STEP 4] Generate Offline Signature (Offline Operation)
echo "\n[TEST] Generating Raw Signature locally..."
PAYLOAD="general_ledger|record_entry|offline_key|ItWorksFromColdStorage!"
RAW_TX=$($CLI_BIN tx sign "$PAYLOAD" "$NONCE" "$NETWORK_ID" offline_tester)
if [[ $RAW_TX != CLIENT_TRANSACTION* ]]; then
    echo "[FAIL] Raw transaction string formatted incorrectly: $RAW_TX"
    exit 1
fi
echo "[PASS] Generated signature string."
echo "         RAW: ${RAW_TX:0:50}..."

# [STEP 5] Broadcast (Online Operation)
echo "\n[TEST] Broadcasting string to network..."
BROADCAST_RESP=$($CLI_BIN tx broadcast "$RAW_TX" --raw)
if [ "$BROADCAST_RESP" != "CLIENT_TRANSACTION_ACCEPTED" ]; then
    echo "[FAIL] Broadcast rejected: $BROADCAST_RESP"
    exit 1
fi
echo "[PASS] Transaction accepted by pool."

# [STEP 6] Verify execution
echo "\n[TEST] Waiting 10s for block inclusion..."
sleep 10
QUERY_RESP=$($CLI_BIN ledger query offline_key)
if [ "$QUERY_RESP" != "ItWorksFromColdStorage!" ]; then
    echo "[FAIL] Ledger state mismatch, got: $QUERY_RESP"
    exit 1
fi
echo "[PASS] State verified on ledger."

echo "\n========================================"
echo "    OFFLINE SIGNING VERIFIED!           "
echo "========================================"
exit 0
