#!/bin/bash
set -e

# Cleanup
# Cleanup
echo "Cleaning up..."
pkill -f "adria_server" || true
# Kill Docker containers if running (prevent port conflict)
docker-compose -f ../../docker-compose.yml down 2>/dev/null || true

# Wait for it to actually die
count=0
while pgrep -f "adria_server" > /dev/null; do
    echo "Waiting for old server to stop..."
    sleep 1
    count=$((count+1))
    if [ $count -ge 5 ]; then
        echo "Forcing kill..."
        pkill -9 -f "adria_server"
        break
    fi
done

# Wait for port 10802 to be released (handle TIME_WAIT or Docker Proxy lag)
echo "Ensuring port 10802 is free..."
while nc -z localhost 10802 2>/dev/null; do
    echo "Waiting for port 10802 to be free..."
    sleep 1
done
rm -rf apl_data
rm -f ledger.db

mkdir -p apl_data
echo "Creating Identities..."
./core-sdk/zig-out/bin/apl wallet create admin > /dev/null
./core-sdk/zig-out/bin/apl wallet create orderer > /dev/null
./core-sdk/zig-out/bin/apl wallet create root_ca > /dev/null

./core-sdk/zig-out/bin/apl cert issue root_ca admin > /dev/null
./core-sdk/zig-out/bin/apl cert issue root_ca orderer > /dev/null

ROOT_PUBKEY=$(./core-sdk/zig-out/bin/apl pubkey root_ca --raw | head -n 1)

cat <<EOF > adria-config.json
{
    "network": {
        "p2p_port": 10801,
        "api_port": 10802,
        "discovery": true,
        "seeds": [],
        "network_id": 1
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

# Start Server
echo "Starting APL Server..."
./core-sdk/zig-out/bin/adria_server --orderer > server.log 2>&1 &
SERVER_PID=$!
sleep 2

# Run gl_app.py to Record Entry
echo "Recording Entry via Hybrid App..."
./tests/functional/gl_app.py record --debit "Expenses:Travel" --credit "Assets:Cash" --amount 150.00 --desc "Flight to NYC" --meta '{"flight":"UA123"}'

# Verify SQLite Status
echo "Checking SQLite Status..."
./tests/functional/gl_app.py list

# Verify manually if needed (the python script already verified, but we can double check)
# The python script prints "VERIFICATION SUCCESSFUL" if it works.

kill $SERVER_PID
echo "Test Complete"
