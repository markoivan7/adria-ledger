#!/bin/bash
set -e

# reconstruct_test.sh
# Verifies that 'apl hydrate' correctly reconstructs the World State from the Blockchain.

echo "========================================"
echo "    ADRIA STATE RECONSTRUCTION TEST     "
echo "========================================"

SERVER_BIN="./core-sdk/zig-out/bin/adria_server"
CLI_BIN="./core-sdk/zig-out/bin/apl"

# 1. Clean Environment
echo "[TEST] Cleaning environment..."
make reset > /dev/null

# 2. Build

echo "[TEST] Building binaries..."
cd core-sdk && zig build
cd ..

# 3. Start Server
echo "[TEST] Starting Server (Orderer Mode)..."
$SERVER_BIN --orderer > /dev/null 2>&1 &
SERVER_PID=$!
sleep 5 # increased sleep for startup and key generation


# 4. Generate Data
echo "[TEST] Generating State (Wallets & Transactions)..."
$CLI_BIN wallet create audit_alice > /dev/null
$CLI_BIN wallet create audit_bob > /dev/null

for i in {1..5}; do
    $CLI_BIN ledger record "audit_key_$i" "audit_value_$i" audit_alice > /dev/null
    echo "   ... $i/5 transactions"
    sleep 1
done

sleep 2 # Allow blocks to be mined/synced

# 5. Stop Server
echo "[TEST] Stopping Server..."
kill $SERVER_PID
wait $SERVER_PID || true

# 6. Verify Original State (Sanity Check)
# We don't checksum anymore because Bitcask timestamps change on reconstruction.
echo "[TEST] Original State generated."

# 7. Test Fast Mode
echo "[TEST] Running 'apl hydrate' (Fast Mode)..."
# Hydrate wipes state and rebuilds it
$CLI_BIN hydrate

echo "[TEST] Verifying Reconstructed State (Fast Mode)..."
for i in {1..5}; do
    KEY="audit_key_$i"
    EXPECTED="audit_value_$i"
    
    # Query directly from DB
    RESULT=$($CLI_BIN ledger query "$KEY" apl_data)
    
    if [[ "$RESULT" != *"$EXPECTED"* ]]; then
        echo "[FAIL] Key $KEY mismatch!"
        echo "Expected: $EXPECTED"
        echo "Actual:   $RESULT"
        exit 1
    fi
done

# 8. Test Audit Mode
echo "[TEST] Running 'apl hydrate --verify-all' (Audit Mode)..."
$CLI_BIN hydrate --verify-all

echo "[TEST] Verifying Reconstructed State (Audit Mode)..."
for i in {1..5}; do
    KEY="audit_key_$i"
    EXPECTED="audit_value_$i"
    
    RESULT=$($CLI_BIN ledger query "$KEY" apl_data)
    
    if [[ "$RESULT" != *"$EXPECTED"* ]]; then
        echo "[FAIL] Key $KEY mismatch (Audit Mode)!"
        echo "Expected: $EXPECTED"
        echo "Actual:   $RESULT"
        exit 1
    fi
done

echo "[SUCCESS] State Reconstruction Verified!"
make reset > /dev/null
