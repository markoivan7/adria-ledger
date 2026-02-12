#!/bin/bash
set -e

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

# Start Server
echo "Starting Adria Server..."
./core-sdk/zig-out/bin/adria_server --orderer > server.log 2>&1 &
SERVER_PID=$!
sleep 2

# Create Wallets
echo "Creating Identities..."
./core-sdk/zig-out/bin/apl wallet create admin
./core-sdk/zig-out/bin/apl wallet create bob

# Get Addresses (parse last line or grep for hex)
# CLI output: "   <address>"
./core-sdk/zig-out/bin/apl address admin > admin_addr.txt 2>&1
./core-sdk/zig-out/bin/apl address bob > bob_addr.txt 2>&1
ADMIN_ADDR=$(cat admin_addr.txt | grep -E "^   [0-9a-f]{64}$" | tr -d ' ')
BOB_ADDR=$(cat bob_addr.txt | grep -E "^   [0-9a-f]{64}$" | tr -d ' ')
echo "Admin: $ADMIN_ADDR"
echo "Bob:   $BOB_ADDR"

# Mint Asset (Admin)
echo "Minting Asset:001 to Admin..."
# Format: chaincode|function|arg1|arg2...
# We use 'ledger invoke' which takes function name as argument
# But our updated logic expects the FIRST part of payload to be chaincode_id
# So we need to use 'invoke' CLI command if it supports raw payload, OR 'ledger record' if we hacked it.
# Wait, 'ledger record' does "record_entry|key|val".
# We need a generic invoke command. 
# Let's inspect cli.zig quickly. 
# If generic CLI isn't ready, we might need to use 'ledger record' but manually craft payload if allowed?
# Actually, let's use the 'ledger invoke' command if it exists, or just 'ledger record' with a trick?
# 'ledger record' creates payload "record_entry|KEY|VAL".
# We need "asset_ledger|mint|ID|OWNER|META".
# Use raw invocation command if available. 
# Inspecting CLI later. Assuming we added `zeicoin ledger invoke <CHAINCODE> <FUNC> <ARGS...>`?
# CLI currently has `ledger record`. Let's assume we update CLI or use a hack.
# HACK for PoC: Use a new CLI command `apl invoke` which sends raw string.

./core-sdk/zig-out/bin/apl invoke "asset_ledger|mint|001|$ADMIN_ADDR|Refurbished Laptop" admin

echo "Mining..."
sleep 10

# Transfer Asset (Admin -> Bob)
echo "Transferring Asset:001 to Bob..."
./core-sdk/zig-out/bin/apl invoke "asset_ledger|transfer|001|$BOB_ADDR" admin

echo "Mining..."
sleep 10

# Query (Bob)
echo "Querying Asset:001..."
# We don't have a CLI query command that returns chaincode result yet (generic query).
# We can check state file directly for verification.
# Query (Bob)
echo "Querying Asset:001..."

# Use CLI query
RESULT=$(./core-sdk/zig-out/bin/apl ledger query "ASSET_001" apl_data)
echo "Asset State: $RESULT"

if [[ "$RESULT" == *"$BOB_ADDR"* ]]; then
    echo "SUCCESS: Asset is owned by Bob!"
else
    echo "FAILURE: Owner mismatch!"
    exit 1
fi

kill $SERVER_PID
