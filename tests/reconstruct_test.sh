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

for i in {1..20}; do
    $CLI_BIN ledger record "audit_key_$i" "audit_value_$i" audit_alice > /dev/null
    if [ $((i % 5)) -eq 0 ]; then
        echo "   ... $i/20 transactions"
    fi
done

sleep 2 # Allow blocks to be mined/synced

# 5. Stop Server
echo "[TEST] Stopping Server..."
kill $SERVER_PID
wait $SERVER_PID || true

# 6. Checksum Original State
state_checksum() {
    # Checksum of all files in state directory (sorted by name)
    # Using specific find arguments to handle having no files gracefully (though we expect files here)
    if [ -d "apl_data/state" ]; then
         find apl_data/state -type f -print0 | sort -z | xargs -0 cat | shasum -a 256 | awk '{print $1}'
    else
        echo "EMPTY"
    fi
}

SUM_ORIG=$(state_checksum)
echo "[TEST] Original State Checksum: $SUM_ORIG"

# 7. Test Fast Mode
echo "[TEST] Running 'apl hydrate' (Fast Mode)..."
$CLI_BIN hydrate

SUM_FAST=$(state_checksum)
echo "[TEST] Fast Replay Checksum:    $SUM_FAST"

if [ "$SUM_ORIG" != "$SUM_FAST" ]; then
    echo "[FAIL] Fast Mode Checksum Mismatch!"
    echo "Expected: $SUM_ORIG"
    echo "Actual:   $SUM_FAST"
    exit 1
fi

# 8. Test Audit Mode
echo "[TEST] Running 'apl hydrate --verify-all' (Audit Mode)..."
$CLI_BIN hydrate --verify-all

SUM_AUDIT=$(state_checksum)
echo "[TEST] Audit Replay Checksum:   $SUM_AUDIT"

if [ "$SUM_ORIG" != "$SUM_AUDIT" ]; then
    echo "[FAIL] Audit Mode Checksum Mismatch!"
    echo "Expected: $SUM_ORIG"
    echo "Actual:   $SUM_AUDIT"
    exit 1
fi

echo "[SUCCESS] State Reconstruction Verified!"
make reset > /dev/null
