#!/bin/bash
set -e

# ==============================================================================
# Adria CLI Test Suite
# Verifies every command in: apl --help
# ==============================================================================

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}    A D R I A   C L I   T E S T S       ${NC}"
echo -e "${BLUE}========================================${NC}"

# --- Setup ---
echo -e "\n${BLUE}[SETUP] Cleaning environment...${NC}"
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

# Wait for port 10802
echo "Ensuring port 10802 is free..."
while nc -z localhost 10802 2>/dev/null; do
    echo "Waiting for port 10802 to be free..."
    sleep 1
done

rm -rf apl_data

# Binaries
APL_BIN="./core-sdk/zig-out/bin/apl"
SERVER_BIN="./core-sdk/zig-out/bin/adria_server"

if [ ! -f "$APL_BIN" ] || [ ! -f "$SERVER_BIN" ]; then
    echo -e "${RED}[ERROR] Binaries not found. Run 'make build' first.${NC}"
    exit 1
fi

# --- Test 1: Wallet Commands (Offline) ---
echo -e "\n${BLUE}[TEST 1] Wallet Commands (Offline)${NC}"

# 1. Create
echo -n "   - apl wallet create cli_test... "
$APL_BIN wallet create cli_test > /dev/null
if [ -f "apl_data/wallets/cli_test.wallet" ]; then
    echo -e "${GREEN}PASS${NC}"
else
    echo -e "${RED}FAIL (Wallet file not created)${NC}"
    exit 1
fi

# 2. List
echo -n "   - apl wallet list... "
LIST_OUTPUT=$($APL_BIN wallet list 2>&1)
if echo "$LIST_OUTPUT" | grep -q "cli_test"; then
    echo -e "${GREEN}PASS${NC}"
else
    echo -e "${RED}FAIL (cli_test not found in list)${NC}"
    echo "$LIST_OUTPUT"
    exit 1
fi

# 3. Load
echo -n "   - apl wallet load cli_test... "
LOAD_OUTPUT=$($APL_BIN wallet load cli_test 2>&1)
if echo "$LOAD_OUTPUT" | grep -q "loaded successfully"; then
    echo -e "${GREEN}PASS${NC}"
else
    echo -e "${RED}FAIL${NC}"
    echo "$LOAD_OUTPUT"
    exit 1
fi

# 4. Address
echo -n "   - apl address cli_test... "
ADDR_OUTPUT=$($APL_BIN address cli_test 2>&1)
if echo "$ADDR_OUTPUT" | grep -iq "address:"; then
    echo -e "${GREEN}PASS${NC}"
else
    echo -e "${RED}FAIL${NC}"
    echo "$ADDR_OUTPUT"
    exit 1
fi

# --- Start Server ---
echo -e "\n${BLUE}[SETUP] Starting Server for Network Tests...${NC}"
$SERVER_BIN --orderer > server.log 2>&1 &
SERVER_PID=$!
sleep 2

# Verify server is up
if ! echo "" | nc localhost 10802 2>/dev/null; then
    # Usually nc returns 0 if connection succeeds.
    # Actually nc -z is better check
    if nc -z localhost 10802; then
         : # OK
    else
         echo -e "${RED}[ERROR] Server failed to start (Port 10802 closed)${NC}"
         cat server.log
         exit 1
    fi
fi

# --- Test 2: Network Commands ---
echo -e "\n${BLUE}[TEST 2] Network Commands${NC}"

# 5. Status
echo -n "   - apl status... "
STATUS_OUTPUT=$($APL_BIN status 2>&1)
if echo "$STATUS_OUTPUT" | grep -q "HEIGHT="; then
    echo -e "${GREEN}PASS${NC}"
else
    echo -e "${RED}FAIL${NC}"
    echo "$STATUS_OUTPUT"
    exit 1
fi

# --- Test 3: Ledger Commands ---
echo -e "\n${BLUE}[TEST 3] Ledger Commands${NC}"

# 6. Record
echo -n "   - apl ledger record... "
$APL_BIN ledger record "cli:key" "cli:value" cli_test > output.log 2>&1
if grep -q "submitted successfully" output.log; then
    echo -e "${GREEN}PASS${NC}"
else
    echo -e "${RED}FAIL${NC}"
    cat output.log
    exit 1
fi

echo -e "   - Mining (Waiting 10s)..."
sleep 10

# 7. Query (CLI not implemented check)
echo -n "   - apl ledger query (Expect Warning)... "
QUERY_OUTPUT=$($APL_BIN ledger query "cli:key" cli_test 2>&1)
if echo "$QUERY_OUTPUT" | grep -q "not implemented yet"; then
    echo -e "${GREEN}PASS (Correctly warned)${NC}"
else
    echo -e "${RED}FAIL (Unexpected output)${NC}"
    echo "$QUERY_OUTPUT"
    exit 1
fi

# 8. Physical Verification (State File)
echo -n "   - Physical State Verification... "
# Key hex for "cli:key" -> 636c693a6b6579
# We have to handle double hexing if db.zig does it.
# Check 'apl_data/state' for any new file
# If only 1 tx, there should be one file (besides genesis ones?)
# We can grep for "cli:value" in the state dir
if grep -r "cli:value" apl_data/state > /dev/null; then
    echo -e "${GREEN}PASS (Found 'cli:value' in persisted storage)${NC}"
else
    echo -e "${RED}FAIL (State not persisted)${NC}"
    ls -l apl_data/state
    exit 1
fi

# Cleanup
echo -e "\n${BLUE}[CLEANUP] Stopping Server...${NC}"
kill $SERVER_PID
wait $SERVER_PID 2>/dev/null || true

echo -e "\n${BLUE}========================================${NC}"
echo -e "${GREEN}    ALL CLI COMMANDS VERIFIED!          ${NC}"
echo -e "${BLUE}========================================${NC}"
exit 0
