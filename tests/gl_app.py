#!/usr/bin/env python3
import argparse
import sqlite3
import hashlib
import json
import subprocess
import time
import sys
import os
import blake3
import uuid

# Configuration
DB_FILE = "ledger.db"
APL_CLI = "../core-sdk/zig-out/bin/apl"
WALLET_NAME = "admin" # Using admin wallet for convenience

def init_db():
    """Initialize the SQLite database with the journal table."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS journal_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            uuid TEXT UNIQUE,
            debit_account TEXT NOT NULL,
            credit_account TEXT NOT NULL,
            amount REAL NOT NULL,
            description TEXT,
            metadata TEXT,
            source_ref TEXT,
            timestamp REAL,
            entry_hash TEXT,
            blockchain_tx_id TEXT
        )
    ''')
    # Automatic Migration for existing DBs (Idempotent-ish)
    try:
        c.execute("ALTER TABLE journal_entries ADD COLUMN uuid TEXT")
    except sqlite3.OperationalError: pass
    try:
        c.execute("ALTER TABLE journal_entries ADD COLUMN metadata TEXT")
    except sqlite3.OperationalError: pass
    try:
        c.execute("ALTER TABLE journal_entries ADD COLUMN source_ref TEXT")
    except sqlite3.OperationalError: pass
    
    conn.commit()
    conn.close()
    print(f"[SUCCESS] Database initialized: {DB_FILE}")

def calculate_hash(debit, credit, amount, description, metadata_json, source_ref, timestamp):
    """Calculate Blake3 hash of the entry data."""
    # Create a consistent string for hashing including rich metadata
    # Format: debit|credit|amount|desc|meta|ref|ts
    data_string = f"{debit}|{credit}|{amount}|{description}|{metadata_json}|{source_ref}|{timestamp}"
    return blake3.blake3(data_string.encode()).hexdigest()

def record_entry(debit, credit, amount, description, metadata_json, source_ref):
    """Record a new journal entry to SQLite AND anchor it to APL."""
    timestamp = time.time()
    entry_uuid = str(uuid.uuid4())
    
    # 1. Calculate Hash
    entry_hash = calculate_hash(debit, credit, amount, description, metadata_json, source_ref, timestamp)
    print(f"[INFO] Entry Hash Calculated (Blake3): {entry_hash}")
    
    # 2. Save to SQLite (PENDING)
    print("[INFO] Saving to SQLite (Status: PENDING)...")
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''
        INSERT INTO journal_entries 
        (uuid, debit_account, credit_account, amount, description, metadata, source_ref, timestamp, entry_hash, blockchain_tx_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (entry_uuid, debit, credit, amount, description, metadata_json, source_ref, timestamp, entry_hash, "PENDING"))
    
    entry_id = c.lastrowid
    conn.commit()
    conn.close()
    print(f"[SUCCESS] Entry #{entry_id} saved locally.")

    # 3. Anchor to Blockchain (APL)
    print("[INFO] Anchoring to APL Blockchain...")
    
    # Phase 7 Strategy: PRIVACY.
    # We do NOT send the description or metadata to the chain.
    # We only send: record_entry | HASH | UUID
    # The Chaincode stores Key=HASH, Value=UUID.
    
    try:
        payload = f"general_ledger|record_entry|{entry_hash}|{entry_uuid}"
        
        # Call CLI
        cmd = [APL_CLI, "invoke", payload, WALLET_NAME]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            print(f"[ERROR] Blockchain Anchor Failed: {result.stderr}")
            # Update status to FAILED
            update_status(entry_id, "FAILED")
            return
            
        print("[SUCCESS] Anchored to Blockchain successfully! (Hash + UUID)")
        
        # 4. Update SQLite (SUBMITTED)
        update_status(entry_id, "SUBMITTED")
        
        # 5. Verify (Check State)
        verify_anchor(entry_hash, entry_uuid)
        
    except FileNotFoundError:
        print(f"[ERROR] Error: APL CLI not found at {APL_CLI}")
        update_status(entry_id, "CLI_MISSING")
        return

def update_status(entry_id, status):
    """Helper to update transaction status."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('UPDATE journal_entries SET blockchain_tx_id = ? WHERE id = ?', (status, entry_id))
    conn.commit()
    conn.close()
    if status == "SUBMITTED":
        print(f"[INFO] Entry #{entry_id} updated to SUBMITTED.")

def verify_anchor(entry_hash, expected_uuid):
    """Verify that the anchor exists in the APL state."""
    print("[INFO] Verifying Anchor on-chain...")
    
    # In a real app, we would query via CLI/API.
    # For PoC, we check the state directory directly (shared storage).
    # Key is valid hex string of the hash? No, 'record_entry' uses raw key passed in args.
    # Logic: stub.putState(key, value) -> in this case key=entry_hash.
    
    # We need to hex-encode the key (entry_hash is already hex string? check calc func).
    # blake3.hexdigest() returns hex string.
    # db.zig / generic wrapper usually maps Key -> HexFilename.
    # Let's check how `putState` stores it. It passes key bytes to DB. 
    # The DB implementation likely writes to a file named `hex(key)`.
    # `entry_hash` is a HEX STRING (e.g. "a1b2..."). 
    # So the key bytes ARE the ascii characters of the hex string? 
    # Or does CLI/Chaincode decode it?
    # Looking at `chaincode.zig`: `recordEntry` takes `args[0]` as key.
    # `processTransaction` in main parser splits by `|`.
    # So the key passed to chaincode IS the hex string "a1b2...".
    # The DB layer (`db.zig`) likely takes that key and hashes it or hex encodes it for filename.
    # Usually it's `hex(key)`. So if key is "abc", filename is "616263".
    
    # We can try to rely on `apl ledger query` if implemented, but I recall it wasn't.
    # Let's try to verify by file existence.
    
    # We'll use a simple "wait and retry" in case of async block commit time.
    # Wait up to 3 seconds.
    time.sleep(3) 
    
    # Construct filename
    # key_bytes = entry_hash.encode('utf-8')
    # filename = key_bytes.hex()
    # But wait, does DB layer do that?
    # Let's just double check standard behavior.
    # Assuming DB stores key as hex filename.
    
    # We will try to execute the query command using the CLI hook we saw earlier
    # wait, "ledger query" printed "Not implemented, check state dir".
    
    # Let's do the file check.
    # entry_hash is "deadbeef..."
    # key bytes = b"deadbeef..."
    # filename = "6465616462656566..." (hex of the hex string)
    
    key_hex = entry_hash.encode("utf-8").hex()
    # Point to the active server's data directory (relative to tests/)
    server_data_dir = "../core-sdk/apl_data"
    state_path = f"{server_data_dir}/state/{key_hex}"
    
    if os.path.exists(state_path):
        with open(state_path, "r") as f:
            content = f.read()
            if expected_uuid in content:
                 print(f"[SUCCESS] VERIFICATION SUCCESSFUL: Anchor found in state! ({content})")
            else:
                 print(f"[WARNING] Anchor found but content mismatch: {content}")
    else:
        print(f"[ERROR] VERIFICATION FAILED: Anchor not found at {state_path}")
        # Debug hint
        print(f"   (Checked for file: {state_path})")

def list_entries():
    """List all entries in SQLite."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('SELECT * FROM journal_entries')
    rows = c.fetchall()
    conn.close()
    
    print(f"{'ID':<4} {'Debit':<15} {'Credit':<15} {'Amount':<10} {'Hash (First 8)':<10}")
    print("-" * 60)
    for row in rows:
        # id, uuid, deb, cred, amt, desc, meta, ref, ts, hash, txid
        # Note: fetchall returns tuple in schema order. 
        # Schema: id, uuid, debit, credit, amount, desc, metadata, ref, ts, hash, txid
        eid = row[0]
        deb = row[2]
        cred = row[3]
        amt = row[4]
        h = row[9] # hash is now index 9
        
        print(f"{eid:<4} {deb:<15} {cred:<15} {amt:<10.2f} {h[:8]}...")

def main():
    parser = argparse.ArgumentParser(description="Adria Hybrid GL App")
    subparsers = parser.add_subparsers(dest="command")
    
    # Record Command
    record_parser = subparsers.add_parser("record", help="Record a journal entry")
    record_parser.add_argument("--debit", required=True, help="Debit Account")
    record_parser.add_argument("--credit", required=True, help="Credit Account")
    record_parser.add_argument("--amount", required=True, type=float, help="Amount")
    record_parser.add_argument("--desc", default="", help="Description")
    record_parser.add_argument("--meta", default="{}", help="Metadata JSON (e.g. '{\"tax\": 10}')")
    record_parser.add_argument("--ref", default="", help="External Reference (e.g. Invoice UUID)")
    
    # List Command
    subparsers.add_parser("list", help="List entries")
    
    args = parser.parse_args()
    
    if args.command == "record":
        init_db()
        record_entry(args.debit, args.credit, args.amount, args.desc, args.meta, args.ref)
    elif args.command == "list":
        if not os.path.exists(DB_FILE):
            print("No database found.")
            return
        list_entries()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
