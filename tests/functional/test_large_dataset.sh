#!/bin/bash
export ADRIA_WALLET_PASSWORD=testpassword
set -e

echo "====================================="
echo "  Running Large Dataset Test"
echo "====================================="

SERVER_PID=""
DATA_DIR="apl_data"

cleanup() {
    echo "[9] Cleaning up..."
    if [ -n "$SERVER_PID" ]; then
        kill $SERVER_PID 2>/dev/null || true
        wait $SERVER_PID 2>/dev/null || true
    fi
    rm -rf "$DATA_DIR" adria-config.json server_large_dataset.log
    rm -f dataset_v1.json dataset_v2.json
    echo "Done!"
}
trap cleanup EXIT

echo "[0] Generating random datasets..."
python3 tests/functional/generate_large_datasets.py

rm -rf "$DATA_DIR"
mkdir -p "$DATA_DIR/wallets"

export ADRIA_SERVER="127.0.0.1"
export ADRIA_BOOTSTRAP=""
API_PORT=10802
P2P_PORT=10801

echo "[1] Creating Identities..."
./core-sdk/zig-out/bin/apl wallet create mywallet > /dev/null
./core-sdk/zig-out/bin/apl wallet create orderer > /dev/null
./core-sdk/zig-out/bin/apl wallet create root_ca > /dev/null

# Issue a cert 
./core-sdk/zig-out/bin/apl cert issue root_ca mywallet > /dev/null
./core-sdk/zig-out/bin/apl cert issue root_ca orderer > /dev/null

ROOT_PUBKEY=$(./core-sdk/zig-out/bin/apl pubkey root_ca --raw | head -n 1)

echo "[2] Writing config..."
cat <<EOF > adria-config.json
{
  "network": {
    "api_port": $API_PORT,
    "p2p_port": $P2P_PORT,
    "max_connections": 50,
    "connection_timeout_ms": 5000,
    "network_id": 1,
    "bind_address": "127.0.0.1",
    "discovery": false
  },
  "consensus": {
    "block_interval_ms": 1000,
    "max_transactions_per_block": 2000,
    "batch_timeout_ms": 200,
    "mode": "solo",
    "role": "orderer",
    "seed_root_ca": "$ROOT_PUBKEY"
  },
  "storage": {
    "data_dir": "$DATA_DIR",
    "log_level": "info"
  }
}
EOF

echo "[3] Starting Server..."
./core-sdk/zig-out/bin/adria_server --orderer > server_large_dataset.log 2>&1 &
SERVER_PID=$!
sleep 3

echo "[4] Appending chunks for snapshot_v1 (100k rows)..."
time ./core-sdk/zig-out/bin/apl dataset append my_app_state snap_v1 dataset_v1.json mywallet
sleep 2

echo "[5] Committing snapshot_v1..."
./core-sdk/zig-out/bin/apl dataset commit my_app_state snap_v1 '{"version": 1}' mywallet
sleep 2

echo "[6] Appending chunks for snapshot_v2 (100k rows)..."
time ./core-sdk/zig-out/bin/apl dataset append my_app_state snap_v2 dataset_v2.json mywallet
sleep 2

echo "[7] Committing snapshot_v2..."
./core-sdk/zig-out/bin/apl dataset commit my_app_state snap_v2 '{"version": 2}' mywallet
sleep 2

echo "[8] Querying dataset diff (snap_v1 -> snap_v2)..."
time ./core-sdk/zig-out/bin/apl dataset diff snap_v1 snap_v2 "$DATA_DIR" > diff_large.json

echo "Diff completed. Formatting output..."
python3 -m json.tool diff_large.json > diff_large_pretty.json
mv diff_large_pretty.json diff_large.json

echo "Here is a preview of the structured diff:"
head -n 25 diff_large.json
echo "..."
echo ""
echo "Saved the full formatted 1.1MB diff to diff_large.json! You can open it in your editor."
