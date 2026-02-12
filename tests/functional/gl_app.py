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
APL_CLI = "./core-sdk/zig-out/bin/apl"
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
    """Verify that the anchor exists in the APL state using CLI."""
    print("[INFO] Verifying Anchor on-chain...")
    
    # Retry loop to allow for block production latency
    max_retries = 10
    for i in range(max_retries):
        # We query the key (entry_hash) from the 'apl_data' directory
        # The CLI command is: apl ledger query <key> [data_dir]
        cmd = [APL_CLI, "ledger", "query", entry_hash, "apl_data"]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        # Check if the UUID is in the output
        if expected_uuid in result.stdout:
            print(f"[SUCCESS] VERIFICATION SUCCESSFUL: Anchor found in state! ({expected_uuid})")
            return
        
        # Check if "Key not found" is in output
        if "Key not found" in result.stdout or "Error" in result.stdout:
            # Wait and retry
            time.sleep(1)
            continue
            
        # If we got some other output, maybe it's a mismatch?
        print(f"[WARNING] Unexpected output: {result.stdout}")
        time.sleep(1)

    print(f"[ERROR] VERIFICATION FAILED: Anchor not found after {max_retries} attempts.")
    print(f"   (Key: {entry_hash})")

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
