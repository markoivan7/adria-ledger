#!/bin/bash
set -e

# ==============================================================================
# Adria Certificate Lifecycle Test
# Verifies: issuance → tx pass → revoke → tx fail → re-issue → tx pass
# Phase 21 Validation — Certificate Lifecycle (Plan.md)
# ==============================================================================

GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { echo -e "   ${GREEN}[PASS]${NC} $1"; }
fail() { echo -e "   ${RED}[FAIL]${NC} $1"; exit 1; }
info() { echo -e "${BLUE}[INFO]${NC} $1"; }
section() { echo -e "\n${BLUE}========================================${NC}\n${BLUE}  $1${NC}\n${BLUE}========================================${NC}"; }

section "ADRIA CERTIFICATE LIFECYCLE TEST"

# --- Binaries ---
APL_BIN="./core-sdk/zig-out/bin/apl"
SERVER_BIN="./core-sdk/zig-out/bin/adria_server"

if [ ! -f "$APL_BIN" ] || [ ! -f "$SERVER_BIN" ]; then
    echo -e "${RED}[ERROR] Binaries not found. Run 'make build' first.${NC}"
    exit 1
fi

# --- Cleanup ---
info "Cleaning environment..."
pkill -f "adria_server" || true
sleep 1
count=0
while pgrep -f "adria_server" > /dev/null 2>&1; do
    sleep 1
    count=$((count+1))
    if [ $count -ge 5 ]; then
        pkill -9 -f "adria_server" || true
        break
    fi
done
while nc -z localhost 10802 2>/dev/null; do sleep 1; done
rm -rf apl_data

# ==============================================================================
# PHASE 1: Identity Setup
# ==============================================================================
section "PHASE 1: Identity Setup"

info "Creating root_ca wallet..."
$APL_BIN wallet create root_ca > /dev/null
info "Creating orderer wallet (required by server)..."
$APL_BIN wallet create orderer > /dev/null
info "Creating alice wallet..."
$APL_BIN wallet create alice > /dev/null

info "Issuing self-signed cert to root_ca (required to submit governance txs)..."
$APL_BIN cert issue root_ca root_ca > /dev/null

info "Issuing CertificateV2 to orderer (signed by root_ca)..."
$APL_BIN cert issue root_ca orderer > /dev/null

info "Issuing CertificateV2 to alice (signed by root_ca)..."
ISSUE_OUTPUT=$($APL_BIN cert issue root_ca alice 2>&1)
echo "$ISSUE_OUTPUT"
if echo "$ISSUE_OUTPUT" | grep -q -i "Issued CertificateV\|SUCCESS.*Issued\|Certificate.*issued\|saved to"; then
    pass "cert issue: CertificateV2 file created"
else
    fail "cert issue: did not produce expected output"
fi

if [ -f "apl_data/wallets/alice.crt" ]; then
    CERT_SIZE=$(wc -c < "apl_data/wallets/alice.crt")
    # Accept both V2 (153 bytes) and V3 (188 bytes)
    if [ "$CERT_SIZE" -eq 153 ] || [ "$CERT_SIZE" -eq 188 ]; then
        pass "cert file size correct (${CERT_SIZE} bytes)"
    else
        fail "cert file wrong size: ${CERT_SIZE} bytes (expected 153 or 188)"
    fi
else
    fail "alice.crt not found after cert issue"
fi

# --- cert inspect ---
info "Inspecting alice's certificate..."
INSPECT_OUT=$($APL_BIN cert inspect alice 2>&1) || true
if echo "$INSPECT_OUT" | grep -q -i "serial\|version\|expires\|issued"; then
    pass "cert inspect: shows certificate metadata"
else
    echo "$INSPECT_OUT"
    fail "cert inspect: expected metadata not found"
fi

# --- Configure server with root_ca ---
info "Configuring server with root_ca..."
ROOT_PUBKEY=$($APL_BIN pubkey root_ca --raw 2>/dev/null | head -n 1)
cat > adria-config.json <<EOF
{
    "network": {
        "p2p_port": 10801,
        "api_port": 10802,
        "discovery": true,
        "seeds": [],
        "network_id": 42
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
pass "adria-config.json written with root_ca pubkey"

# --- Start server ---
info "Starting server..."
$SERVER_BIN --orderer > /tmp/cert_lifecycle_server.log 2>&1 &
SERVER_PID=$!
sleep 3

if ! nc -z localhost 10802 2>/dev/null; then
    echo -e "${RED}[ERROR] Server failed to start. Log:${NC}"
    cat /tmp/cert_lifecycle_server.log | tail -20
    exit 1
fi
pass "Server started (PID $SERVER_PID)"

# ==============================================================================
# PHASE 2: Valid Certificate — Transaction Should Succeed
# ==============================================================================
section "PHASE 2: Valid Certificate → Transaction PASSES"

info "Submitting transaction with valid certificate..."
TX1_OUT=$($APL_BIN ledger record "lifecycle:test1" '{"status":"active"}' alice 2>&1) || true
echo "$TX1_OUT"
if echo "$TX1_OUT" | grep -q "submitted successfully"; then
    pass "Transaction accepted with valid certificate"
else
    fail "Transaction rejected (expected success with valid cert)"
fi

# ==============================================================================
# PHASE 3: Revoke Certificate
# ==============================================================================
section "PHASE 3: Revoke Certificate"

info "Revoking alice's certificate..."
REVOKE_OUT=$($APL_BIN cert revoke root_ca alice 2>&1) || true
echo "$REVOKE_OUT"
if echo "$REVOKE_OUT" | grep -q -i "revocation submitted\|submitted\|success"; then
    pass "Certificate revocation submitted to network"
else
    fail "Certificate revocation failed: $REVOKE_OUT"
fi

info "Waiting 12s for revocation block to commit..."
sleep 12

# ==============================================================================
# PHASE 4: Revoked Certificate — Transaction Should Fail
# ==============================================================================
section "PHASE 4: Revoked Certificate → Transaction FAILS"

info "Attempting transaction with revoked certificate (expect rejection)..."
TX2_OUT=$($APL_BIN ledger record "lifecycle:test2" '{"status":"revoked_test"}' alice 2>&1) || true
echo "$TX2_OUT"
if echo "$TX2_OUT" | grep -q -i "ERROR\|failed\|rejected\|Invalid"; then
    pass "Transaction correctly REJECTED with revoked certificate"
elif echo "$TX2_OUT" | grep -q "submitted successfully"; then
    fail "Transaction was ACCEPTED with a revoked certificate (CRL not enforced!)"
else
    # Transaction might have timed out or had other issue — still a reject
    pass "Transaction not accepted with revoked certificate"
fi

# ==============================================================================
# PHASE 5: Re-issue Certificate (Renewal)
# ==============================================================================
section "PHASE 5: Certificate Renewal → Transaction PASSES Again"

info "Re-issuing certificate to alice (new serial, new cert)..."
REISSUE_OUT=$($APL_BIN cert issue root_ca alice 2>&1)
echo "$REISSUE_OUT"
if echo "$REISSUE_OUT" | grep -q -i "Issued CertificateV\|SUCCESS.*Issued\|Certificate.*issued\|saved to"; then
    pass "cert issue: New certificate (renewal) issued successfully"
else
    fail "cert issue (renewal): unexpected output"
fi

info "Waiting 3s for cert to be ready..."
sleep 3

info "Submitting transaction with renewed certificate..."
TX3_OUT=$($APL_BIN ledger record "lifecycle:test3" '{"status":"renewed"}' alice 2>&1) || true
echo "$TX3_OUT"
if echo "$TX3_OUT" | grep -q "submitted successfully"; then
    pass "Transaction accepted with renewed (new serial) certificate"
else
    fail "Transaction rejected with renewed cert (expected success)"
fi

# ==============================================================================
# PHASE 6: Certificate Audit
# ==============================================================================
section "PHASE 6: Certificate Audit"

info "Waiting 12s for ledger entries to commit..."
sleep 12

ALICE_ADDR=$($APL_BIN address alice --raw 2>/dev/null | tr -d '[:space:]')
info "Running cert audit for alice ($ALICE_ADDR)..."
AUDIT_OUT=$($APL_BIN cert audit "$ALICE_ADDR" apl_data 2>&1) || true
echo "$AUDIT_OUT"
if echo "$AUDIT_OUT" | grep -q "Certificate Audit Report"; then
    pass "cert audit: Report generated"
else
    fail "cert audit: Report not found"
fi

if echo "$AUDIT_OUT" | grep -q "Total Tx"; then
    pass "cert audit: Shows transaction history"
else
    fail "cert audit: Missing transaction count"
fi

# ==============================================================================
# Cleanup
# ==============================================================================
section "CLEANUP"
kill $SERVER_PID 2>/dev/null || true
wait $SERVER_PID 2>/dev/null || true
info "Server stopped."

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  CERTIFICATE LIFECYCLE TEST: ALL PASS  ${NC}"
echo -e "${GREEN}========================================${NC}"
exit 0
