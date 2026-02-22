#!/bin/bash
set -e

# Adria Benchmark Wrapper
# Usage: ./tests/bench.sh

echo "========================================"
echo "    ADRIA PERMISSIONED LEDGER BENCH     "
echo "========================================"

# 1. Cleanup old data
echo "[BENCH] Cleaning up old data..."
pkill -f "adria_server" || true
rm -rf apl_data logs
rm -f adria-config.json
mkdir -p logs

# 2. Build Project
echo "[BENCH] Building Core SDK..."
cd core-sdk
zig build -Doptimize=ReleaseSafe
cd ..

# 3. Generate Identities
echo "[BENCH] Generating Identities..."
mkdir -p apl_data
./core-sdk/zig-out/bin/apl wallet create orderer > /dev/null
./core-sdk/zig-out/bin/apl wallet create bench_user > /dev/null
./core-sdk/zig-out/bin/apl wallet create root_ca > /dev/null

./core-sdk/zig-out/bin/apl cert issue root_ca orderer > /dev/null
./core-sdk/zig-out/bin/apl cert issue root_ca bench_user > /dev/null

ROOT_PUBKEY=$(./core-sdk/zig-out/bin/apl pubkey root_ca --raw | head -n 1)

cat <<EOF > adria-config.json
{
    "network": {
        "p2p_port": 10801,
        "api_port": 10802,
        "discovery": true,
        "seeds": [],
        "network_id": 1,
        "bind_address": "127.0.0.1"
    },
    "storage": {
        "data_dir": "apl_data",
        "log_level": "info"
    },
    "consensus": {
        "mode": "solo",
        "role": "orderer",
        "seed_root_ca": "$ROOT_PUBKEY"
    }
}
EOF

# 3. Start Server in Background
echo "[BENCH] Starting Server (Orderer Mode)..."
./core-sdk/zig-out/bin/adria_server --orderer > logs/server.log 2>&1 &
SERVER_PID=$!
echo "[BENCH] Server PID: $SERVER_PID"

# Wait for server to initialize
echo "[BENCH] Waiting 2s for server initialization..."
sleep 2

# 4. Run Benchmark
echo "[BENCH] Running E2E Benchmark..."
if ./core-sdk/zig-out/bin/bench_e2e --wallet bench_user; then
    echo "========================================"
    echo "[PASS] Benchmark Completed Successfully!"
    RESULT=0
else
    echo "========================================"
    echo "[FAIL] Benchmark Failed!"
    RESULT=1
fi

# 5. Cleanup
echo "[BENCH] Stopping Server..."
kill $SERVER_PID || true
wait $SERVER_PID 2>/dev/null || true

echo "[BENCH] Complete."
exit $RESULT
