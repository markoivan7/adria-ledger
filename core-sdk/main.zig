// main.zig - Adria Blockchain Core
// A minimalist proof-of-work blockchain implementation written in Zig
// Features account-based model, Ed25519 signatures, permissioned consensus, Bech32 addresses, and role-based access control
// Additional features: P2P networking, file-based persistence, system chaincodes, CLI wallet
// Now with pluggable consensus (Solo/Raft)

const std = @import("std");
const print = std.debug.print;
const ArrayList = std.ArrayList;
const HashMap = std.HashMap;

const types = @import("common").types;
const util = @import("common").util;
const serialize = @import("common").serialize;
const db = @import("execution").db;
const key = @import("crypto").key;
const net = @import("network/net.zig");
const chaincode = @import("execution").chaincode;
const acl_module = @import("execution").acl;
const consensus = @import("consensus");
const solo = @import("consensus").solo;
const verifier = @import("execution").verifier;
const ingestion_pool = @import("ingestion/pool.zig");
const governance = @import("execution").system.governance;

// Helper function to format ZEI amounts with proper decimal places
// formatZEI removed in Phase 5

// Type aliases for clarity
const Transaction = types.Transaction;
const Block = types.Block;
const BlockHeader = types.BlockHeader;
const Account = types.Account;
const Address = types.Address;
const Hash = types.Hash;

/// Adria blockchain state and operations
pub const ZeiCoin = struct {
    // Persistent database storage
    database: db.Database,
    // Mutex for thread-safety (World State Access)
    mutex: std.Thread.Mutex,

    // Mempool moved to Consensus
    // mempool: ArrayList(Transaction),

    // Network manager for P2P communication (pointer to external manager)
    network: ?*net.NetworkManager,

    // Allocator for dynamic memory
    allocator: std.mem.Allocator,

    // Identity Root (The "Gatekeeper")
    root_public_key: [32]u8,

    // The Pluggable Consensus Engine
    consensus_engine: consensus.Consenter,
    // We keep a reference to the specific impl to deinit it
    // For PoC, we hold a pointer to the specific implementation to manage lifecycle
    solo_impl: *solo.SoloOrderer,

    // Access Control System
    acl: acl_module.AccessControl,

    // Parallel Signature Verifier
    verifier: *verifier.ParallelVerifier,

    // Ingestion Worker Pool (Parallel Verification)
    ingestion_pool: ?*ingestion_pool.IngestionPool,

    // Execution Sync State
    sync_thread: ?std.Thread,
    should_stop_sync: std.atomic.Value(bool),

    /// Initialize new Adria blockchain with persistent storage
    pub fn init(allocator: std.mem.Allocator) !*ZeiCoin {
        // Initialize State (World State KV Store)
        const data_dir = "apl_data";
        const database = try db.Database.init(allocator, data_dir);

        // TODO: Load this from a file or config in production
        // For now, we default to all zeros (which allows any invalid sig to fail securely)
        // or a hardcoded development key.
        const root_pk = std.mem.zeroes([32]u8);

        const self = try allocator.create(ZeiCoin);
        self.* = ZeiCoin{
            .database = database,
            .mutex = .{},
            // .mempool = ArrayList(Transaction).init(allocator), // Mempool moved to Consensus
            .network = null,
            .allocator = allocator,
            .root_public_key = root_pk,
            .solo_impl = undefined, // Will be initialized below
            .consensus_engine = undefined, // Will be initialized below
            .sync_thread = null,
            .should_stop_sync = std.atomic.Value(bool).init(false),
            .acl = undefined,
            .verifier = undefined,
            .ingestion_pool = null,
        };

        // Initialize Parallel Verifier
        self.verifier = try verifier.ParallelVerifier.init(allocator, null);

        // Initialize ACL
        self.acl = acl_module.AccessControl.init();

        self.verifier = try verifier.ParallelVerifier.init(allocator, null); // Use default thread count

        // Initialize Ingestion Pool (CpuCount - 2 workers)
        const cpu_count = std.Thread.getCpuCount() catch 4;
        const worker_count = if (cpu_count > 2) cpu_count - 2 else 1;
        self.ingestion_pool = try ingestion_pool.IngestionPool.init(allocator, self, worker_count);

        // Create genesis block if database is empty
        if (try self.getHeight() == 0) {
            try self.createGenesis();
        }

        // We pass the validator identity if we have it
        const validator_id: ?key.Identity = null;

        // Init Solo Orderer (Pluggable architecture allows Raft here in future)
        const solo_engine = try solo.SoloOrderer.init(allocator, &self.database, validator_id);
        self.consensus_engine = solo_engine.consenter();
        self.solo_impl = solo_engine;

        self.consensus_engine.start() catch |err| {
            print("[ERROR] Failed to start consensus engine: {}\n", .{err});
            return err;
        };

        return self;
    }

    /// Start the background sync loop
    pub fn start(self: *ZeiCoin) !void {
        self.should_stop_sync.store(false, .release);
        if (self.sync_thread == null) {
            self.sync_thread = try std.Thread.spawn(.{}, syncLoop, .{self});
        }
    }

    /// Cleanup blockchain resources
    pub fn deinit(self: *ZeiCoin) void {
        self.should_stop_sync.store(true, .release);
        if (self.sync_thread) |t| {
            t.join();
        }

        if (self.ingestion_pool) |pool| {
            pool.deinit();
        }

        self.consensus_engine.stop();

        self.solo_impl.deinit();

        self.verifier.deinit();

        self.database.deinit();
        if (self.network) |n| n.deinit();
        self.allocator.destroy(self);
    }

    /// Set the validator identity for the underlying Consensus engine (Solo)
    pub fn setValidator(self: *ZeiCoin, identity: key.Identity) void {
        // Direct access to solo_impl specific field
        // In full pluggable model, we might need a generic 'setIdentity' or configure at init
        self.solo_impl.validator = identity;
        print("[INFO] Validator Identity set for Consensus Engine\n", .{});
    }

    /// Create the genesis block with initial distribution
    fn createGenesis(self: *ZeiCoin) !void {
        // Genesis public key (zero for simplicity) and derive address
        const genesis_public_key = std.mem.zeroes([32]u8);
        const genesis_addr = util.hash(&genesis_public_key);

        // Create genesis account with initial supply
        const genesis_account = Account{
            .address = genesis_addr,
            .nonce = 0,
            .role = 1, // 1 = Admin Role for Genesis
        };

        // Save genesis account to database
        try self.database.saveAccount(genesis_addr, genesis_account);

        var policy_json: []u8 = undefined;

        // Attempt to load genesis.json
        if (std.fs.cwd().openFile("genesis.json", .{})) |file| {
            defer file.close();
            const size = try file.getEndPos();
            policy_json = try self.allocator.alloc(u8, size);
            _ = try file.readAll(policy_json);
            print("[INFO] Loaded genesis configuration from genesis.json\n", .{});
        } else |_| {
            // Fallback to default policy
            const initial_policy = governance.GovernancePolicy{
                .root_cas = &[_][]const u8{
                // Genesis Admin (derived from zero key for PoC)
                "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29"},
                .min_validator_count = 1,
                .block_creation_interval = 10,
            };
            policy_json = try initial_policy.toJson(self.allocator);
            print("[INFO] Using default genesis configuration\n", .{});
        }
        defer self.allocator.free(policy_json);

        // Save to DB directly as sys_config
        try self.database.put(governance.GovernanceSystem.CONFIG_KEY, policy_json);

        // Create genesis block (no transactions, just establishes the chain)
        const genesis_transactions = try self.allocator.alloc(Transaction, 0);
        defer self.allocator.free(genesis_transactions);

        const genesis_block = Block{
            .header = BlockHeader{
                .previous_hash = std.mem.zeroes(Hash),
                .merkle_root = std.mem.zeroes(Hash),
                .timestamp = types.Genesis.timestamp,
                .validator_public_key = std.mem.zeroes([32]u8),
                .validator_cert = std.mem.zeroes([64]u8),
                .signature = std.mem.zeroes(types.Signature),
            },
            .transactions = genesis_transactions,
        };

        // Save genesis block to database
        try self.database.saveBlock(0, genesis_block);

        print("[INFO] APL Genesis Block Created!\n", .{});
        print("[INFO] Block #{}: {} transactions\n", .{ 0, genesis_block.txCount() });
    }

    /// Get account for an address (creates new account if doesn't exist)
    /// Internal getAccount (No Lock - Caller must hold mutex)
    fn getAccountInternal(self: *ZeiCoin, address: Address) !Account {
        // Try to load from database
        if (self.database.getAccount(address)) |account| {
            return account;
        } else |err| switch (err) {
            error.NotFound => {
                // Create new account with zero balance
                const new_account = Account{
                    .address = address,
                    .nonce = 0,
                    .role = 2, // Default role = Writer (For PoC Verification)
                };
                // Save to database immediately
                try self.database.saveAccount(address, new_account);
                return new_account;
            },
            else => return err,
        }
    }

    /// Get account for an address (creates new account if doesn't exist)
    pub fn getAccount(self: *ZeiCoin, address: Address) !Account {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.getAccountInternal(address);
    }

    /// Add transaction to the network (submit to Consensus)
    pub fn addTransaction(self: *ZeiCoin, tx: types.Transaction) !void {
        // Validation (syntax check)
        if (!try self.validateTransaction(tx)) {
            return error.InvalidTransaction;
        }

        try self.addVerifiedTransaction(tx);
    }

    /// Add a PRE-VERIFIED transaction to consensus (Internal/Worker use only)
    pub fn addVerifiedTransaction(self: *ZeiCoin, tx: types.Transaction) !void {
        try self.consensus_engine.recvTransaction(tx);
        // print("[INFO] Tx submitted to Consensus\n", .{});
    }

    /// Validate a transaction against current blockchain state
    pub fn validateTransaction(self: *ZeiCoin, tx: Transaction) !bool {
        // Basic structure validation
        if (!tx.isValid()) return false;

        // Get sender account
        const sender_account = try self.getAccount(tx.sender);

        // Check nonce (must be >= next expected nonce for Mempool)
        if (tx.nonce < sender_account.nextNonce()) {
            print("[WARN] Invalid nonce: expected >= {}, got {}\n", .{ sender_account.nextNonce(), tx.nonce });
            return false;
        }

        // Balance/Fee checks removed in Phase 5
        // Spam prevention is now handled by Identity/ACLs

        // 🛡️ Verify Identity (The Gatekeeper)
        // Checks if the sender has a valid certificate signed by the Root CA
        if (!key.MSP.verifyCertificate(self.root_public_key, tx.sender_public_key, tx.sender_cert)) {
            // TODO: Enforce strict MSP validation in Production
            // For PoC/Dev, we allow zero-certs if we are just testing
            const is_zero_cert = std.mem.eql(u8, &tx.sender_cert, &std.mem.zeroes([64]u8));
            if (is_zero_cert) {
                print("[WARN] DEV WARN: Transaction allowed with ZERO CERT (Unauthenticated)\n", .{});
            } else {
                print("[ERROR] Permission Denied: Invalid Identity Certificate\n", .{});
                return false;
            }
        }

        // Verify transaction signature
        const tx_hash = tx.hashForSigning();
        if (!key.verify(tx.sender_public_key, &tx_hash, tx.signature)) {
            print("[ERROR] Invalid signature: transaction not signed by sender\n", .{});
            return false;
        }

        return true;
    }

    /// Validate transaction state (Nonce, Account) without verifying signatures
    fn validateTransactionState(self: *ZeiCoin, tx: Transaction) !bool {
        // Basic structure validation
        if (!tx.isValid()) return false;

        // Get sender account
        const sender_account = try self.getAccount(tx.sender);

        // Check nonce (must be >= next expected nonce for Mempool)
        if (tx.nonce < sender_account.nextNonce()) {
            print("[WARN] Invalid nonce: expected >= {}, got {}\n", .{ sender_account.nextNonce(), tx.nonce });
            return false;
        }

        return true;
    }

    /// Process a transaction (apply state changes)
    // Process a transaction (apply state changes)
    fn processTransaction(self: *ZeiCoin, tx: Transaction, block_height: u64, tx_index: u32) !void {
        switch (tx.type) {
            .invoke => {
                // Get sender to increment nonce
                // Get sender account (internal no-lock)
                var sender_account = try self.getAccountInternal(tx.sender);

                // ACL CHECK
                // Check if sender has Writer permission (Role 2)
                if (!try self.acl.checkPermission(&self.database, tx.sender, .Writer)) {
                    print("[ERROR] Permission Denied: Sender does not have Writer role\n", .{});
                    return error.PermissionDenied;
                }

                sender_account.nonce += 1;
                try self.database.saveAccount(tx.sender, sender_account);

                // Instantiate Chaincode Stub
                var stub = chaincode.Stub.init(self.allocator, &self.database);
                defer stub.deinit();

                // Decode payload: function|arg1|arg2...
                var args = std.ArrayList([]const u8).init(self.allocator);
                defer args.deinit();
                // Decode payload: chaincode_id|function|arg1|arg2...
                var splitter = std.mem.splitScalar(u8, tx.payload, '|');
                const chaincode_id = splitter.next() orelse return error.InvalidPayload;
                const function_name = splitter.next() orelse return error.InvalidPayload;

                while (splitter.next()) |arg| {
                    try args.append(arg);
                }

                var payload_result: []const u8 = undefined;

                if (std.mem.eql(u8, chaincode_id, chaincode.GeneralLedger.ID)) {
                    // Requires Writer (checked above)
                    payload_result = chaincode.GeneralLedger.invoke(&stub, function_name, args.items) catch |err| {
                        print("[ERROR] Failed to invoke GeneralLedger: {}\n", .{err});
                        // TODO: Isolate chaincode failure from block validity
                        return err;
                    };
                } else if (std.mem.eql(u8, chaincode_id, chaincode.AssetLedger.ID)) {
                    // Requires Writer (checked above)
                    // Pass sender address for ownership checks
                    const sender_hex = std.fmt.bytesToHex(tx.sender, .lower);
                    payload_result = chaincode.AssetLedger.invoke(&stub, function_name, args.items, &sender_hex) catch |err| {
                        print("[ERROR] Failed to invoke AssetLedger: {}\n", .{err});
                        // TODO: Isolate chaincode failure from block validity
                        return err;
                    };
                } else if (std.mem.eql(u8, chaincode_id, chaincode.DocumentStore.ID)) {
                    // Requires Writer (checked above)
                    payload_result = chaincode.DocumentStore.invoke(&stub, function_name, args.items) catch |err| {
                        print("[ERROR] Failed to invoke DocumentStore: {}\n", .{err});
                        return err;
                    };
                } else if (std.mem.eql(u8, chaincode_id, chaincode.Governance.ID)) {
                    // Requires Admin for most things, managed by chaincode itself
                    const sender_hex = std.fmt.bytesToHex(tx.sender, .lower);
                    payload_result = chaincode.Governance.invoke(&stub, function_name, args.items, &sender_hex) catch |err| {
                        print("[ERROR] Failed to invoke Governance: {}\n", .{err});
                        return err;
                    };
                } else {
                    print("[ERROR] Unknown Chaincode ID: {s}\n", .{chaincode_id});
                    return error.InvalidTransaction;
                }

                // Commit Writes (MVCC)
                var it = stub.write_set.iterator();
                while (it.next()) |entry| {
                    try self.database.putVersioned(entry.key_ptr.*, entry.value_ptr.*, block_height, tx_index);
                }

                print("[INFO] Smart Contract Invoked: {s} on {s}\n", .{ function_name, chaincode_id });
            },
            // .transfer case removed as it is no longer in the enum
        }

        print("[INFO] Processed type={}\n", .{tx.type});
    }

    /// Get blockchain height
    pub fn getHeight(self: *ZeiCoin) !u32 {
        return try self.database.getHeight();
    }

    // getBalance removed in Phase 5

    /// Get block by height
    pub fn getBlockByHeight(self: *ZeiCoin, height: u32) !Block {
        return try self.database.getBlock(height);
    }

    /// Validate an incoming block
    pub fn validateBlock(self: *ZeiCoin, block: Block, expected_height: u32) !bool {
        // Check basic block structure
        if (!block.isValid()) return false;

        // Check block height consistency
        const current_height = try self.getHeight();
        if (expected_height != current_height) return false;

        // PoW check removed for permissioned mode
        // In the future, we will validate the Orderer's signature here
        if (@import("builtin").mode == .Debug) {
            // Debug hook
        }

        // Verify Validator Identity (The "Gatekeeper")
        if (!key.MSP.verifyCertificate(self.root_public_key, block.header.validator_public_key, block.header.validator_cert)) {
            print("[ERROR] Block rejected: Invalid Validator Identity Certificate\n", .{});
            return false;
        }

        // Verify Block Signature
        const header_hash = block.header.hash();
        if (!key.verify(block.header.validator_public_key, &header_hash, block.header.signature)) {
            print("[ERROR] Block rejected: Invalid Validator Signature\n", .{});
            return false;
        }

        // Check previous hash links correctly
        if (expected_height > 0) {
            const prev_block = try self.getBlockByHeight(expected_height - 1);
            defer self.allocator.free(prev_block.transactions);

            const prev_hash = prev_block.hash();
            if (!std.mem.eql(u8, &block.header.previous_hash, &prev_hash)) return false;
        }

        // Validate all transactions in block
        // Phase 9: Parallel Verification
        if (!try self.verifier.verifyBlock(block, self.root_public_key)) {
            print("[ERROR] Block rejected: Parallel verification failed (Bad Signatures)\n", .{});
            return false;
        }

        // Phase 9: Parallel Verification
        if (!try self.verifier.verifyBlock(block, self.root_public_key)) {
            print("[ERROR] Block rejected: Parallel verification failed (Bad Signatures)\n", .{});
            return false;
        }

        // Sequential State Validation (Nonce, etc)
        for (block.transactions) |tx| {
            if (!try self.validateTransactionState(tx)) return false;
        }

        return true;
    }

    /// Apply a valid block to the blockchain
    fn applyBlock(self: *ZeiCoin, block: Block) !void {
        const block_height = try self.getHeight();

        // Process all transactions in the block
        for (block.transactions, 0..) |tx, i| {
            // Handle transactions (no coinbase in permissioned mode)
            try self.processTransaction(tx, block_height, @as(u32, @intCast(i)));
        }

        // Save block to database
        // Save block to database
        // try self.database.saveBlock(block_height, block);
        // MAIN DB SAVE REMOVED: Consensus (Solo) already saved it to DB to "Order" it.
        // But wait... we need to Apply State (Exec) transaction logic!
        // The Solo Orderer saving it just means it's in the chain.
        // It does NOT mean the KV store (State) is updated.
        // So we MUST run processTransaction here.

        // Important: If Solo saved it, we might be double-saving if we call saveBlock.
        // But `db.saveBlock` just writes a file. Overwriting is fine/idempotent.
        // OR we change Solo to NOT save, just return?
        // No, Consensus MUST persist the Log.

        // So here ApplyBlock is really just "Execute Block".
        try self.database.commit();
    }

    /// Clean mempool of transactions that are now in a block
    fn cleanMempool(self: *ZeiCoin, block: Block) void {
        // Mempool is now managed by Consensus engine.
        // We don't touch it here.
        _ = self;
        _ = block;
    }

    /// Start networking on specified port
    pub fn startNetwork(self: *ZeiCoin, port: u16) !void {
        if (self.network != null) return; // Already started

        var network = net.NetworkManager.init(self.allocator);
        try network.start(port);
        self.network = network;

        print("[INFO] APL network started on port {}\n", .{port});
    }

    /// Stop networking
    pub fn stopNetwork(self: *ZeiCoin) void {
        if (self.network) |*network| {
            network.stop();
            network.deinit();
            self.network = null;
            print("[INFO] APL network stopped\n", .{});
        }
    }

    /// Connect to a peer
    pub fn connectToPeer(self: *ZeiCoin, address: []const u8) !void {
        if (self.network) |*network| {
            try network.addPeer(address);
        } else {
            return error.NetworkNotStarted;
        }
    }

    /// Print blockchain status
    /// Thread-safe save account (Zen wrapper)
    pub fn saveAccount(self: *ZeiCoin, address: types.Address, account: types.Account) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.database.saveAccount(address, account);
    }

    pub fn printStatus(self: *ZeiCoin) void {
        print("\n[INFO] APL Blockchain Status:\n", .{});
        const height = self.getHeight() catch 0;
        const account_count = self.database.getStateCount() catch 0;
        print("   Height: {} blocks\n", .{height});
        // Show mempool status (via Consensus if possible, or skip)
        // print("   Pending: {} transactions\n", .{self.mempool.items.len});
        print("   Pending: (Managed by Consensus)\n", .{});
        print("   State Entries: {} (Accounts/KV)\n", .{account_count});

        // Show network status
        if (self.network) |*network| {
            const connected_peers = network.*.getConnectedPeers();
            const total_peers = network.*.peers.items.len;
            print("   Network: {} of {} peers connected\n", .{ connected_peers, total_peers });

            if (total_peers > 0) {
                for (network.*.peers.items) |peer| {
                    var addr_buf: [32]u8 = undefined;
                    const addr_str = peer.address.toString(&addr_buf);
                    const status = switch (peer.state) {
                        .connected => "[CONNECTED]",
                        .connecting => "[CONNECTING]",
                        .handshaking => "[HANDSHAKE]",
                        .reconnecting => "[RETRY]",
                        .disconnecting => "[CLOSING]",
                        .disconnected => "[CLOSED]",
                    };
                    print("     {s} {s}\n", .{ status, addr_str });
                }
            }
        } else {
            print("   Network: offline\n", .{});
        }

        // Show recent blocks
        const start_idx = if (height > 3) height - 3 else 0;
        var i = start_idx;
        while (i < height) : (i += 1) {
            if (self.database.getBlock(i)) |block| {
                print("   Block #{}: {} txs\n", .{ i, block.txCount() });
                // Free block memory after displaying
                self.allocator.free(block.transactions);
            } else |_| {
                print("   Block #{}: Error loading\n", .{i});
            }
        }
        print("\n", .{});
    }

    /// Broadcast newly mined block to network peers (zen flow)
    fn broadcastNewBlock(self: *ZeiCoin, block: types.Block) void {
        if (self.network) |network| {
            network.broadcastBlock(block);
            print("[INFO] Block propagating to {} peers\n", .{network.getPeerCount()});
        }
    }

    /// Handle incoming transaction from network peer
    pub fn handleIncomingTransaction(self: *ZeiCoin, transaction: types.Transaction) !void {
        // Zen wisdom: check if we already have this transaction (prevent duplicates)
        // This check is now handled by the Consensus engine's mempool
        // const tx_hash = transaction.hash();
        // for (self.mempool.items) |existing_tx| {
        //     if (std.mem.eql(u8, &existing_tx.hash(), &tx_hash)) {
        //         print("🌊 Transaction already flows in our zen mempool - gracefully ignored\n", .{});
        //         return;
        //     }
        // }

        // Validate and add to mempool if valid
        self.addTransaction(transaction) catch |err| {
            print("[WARN] Rejected network transaction: {}\n", .{err});
            return err;
        };

        print("[INFO] Network transaction accepted\n", .{});
    }

    /// Handle incoming block from network peer
    pub fn handleIncomingBlock(self: *ZeiCoin, block: types.Block) !void {
        // Basic validation and chain extension
        const current_height = try self.getHeight();

        print("[INFO] Block received from peer with {} transactions\n", .{block.transactions.len});

        // Zen wisdom: check if we already have this block (prevent duplicates)
        const block_hash = block.hash();
        if (current_height > 0) {
            for (0..current_height) |height| {
                const existing_block = self.database.getBlock(@intCast(height)) catch continue;
                defer self.allocator.free(existing_block.transactions);

                if (std.mem.eql(u8, &existing_block.hash(), &block_hash)) {
                    print("[INFO] Block already exists - ignored\n", .{});
                    return;
                }
            }
        }

        // Zen validation: check if block extends our chain properly
        if (current_height > 0) {
            const prev_block = try self.database.getBlock(current_height - 1);
            defer self.allocator.free(prev_block.transactions);

            const expected_prev_hash = prev_block.hash();
            if (!std.mem.eql(u8, &block.header.previous_hash, &expected_prev_hash)) {
                print("[ERROR] Block rejected: previous hash doesn't match\n", .{});
                return;
            }
        }

        // PoW check removed for permissioned mode

        // Process all transactions in the block (zen flow)
        // Handled by syncLoop (Execution Thread) to avoid race conditions and double execution
        // We only save the block here.

        // Save block to database (zen persistence)
        try self.database.saveBlock(current_height, block);

        print("[INFO] Block #{} accepted (Queued for Execution)\n", .{current_height});

        // Zen propagation: relay valid block to other peers (but not back to sender)
        if (self.network) |network| {
            network.*.broadcastBlock(block);
            print("[INFO] Relaying valid block to peers\n", .{});
        }
    }
    /// Background loop: Syncs execution state with committed blocks (Ordering -> Execution)
    fn syncLoop(self: *ZeiCoin) void {
        var executed_height: u32 = 0;

        // Startup catchup check (skipped for PoC simplicity - usually read from DB)
        if (self.database.getHeight()) |h| {
            _ = h;
        } else |_| {}

        while (!self.should_stop_sync.load(.acquire)) {
            const chain_height = self.database.getHeight() catch 0;

            // If chain is ahead of execution
            if (chain_height > executed_height) {
                while (executed_height < chain_height) {
                    if (self.database.getBlock(executed_height)) |block| {
                        defer self.allocator.free(block.transactions);

                        const blk_h = @as(u64, executed_height);

                        // Lock for atomic execution & commit (Fix race with invalidation/reading)
                        {
                            self.mutex.lock();
                            defer self.mutex.unlock();

                            for (block.transactions, 0..) |tx, i| {
                                self.processTransaction(tx, blk_h, @as(u32, @intCast(i))) catch |err| {
                                    print("[ERROR] Execution Failed Block #{}: {}\n", .{ executed_height, err });
                                };
                            }

                            // Flush State Cache to Disk
                            self.database.commit() catch |err| {
                                print("[CRITICAL] Failed to commit block #{}: {}\n", .{ executed_height, err });
                                // In a real system, we might want to panic or halt here
                            };
                        }

                        print("[INFO] Executed Block #{}\n", .{executed_height});
                        executed_height += 1;
                    } else |err| {
                        if (executed_height > 0) {
                            // Only print if we are stuck on a non-genesis block
                            print("[WARN] syncLoop failed to load Block #{}: {}\n", .{ executed_height, err });
                        }
                        std.time.sleep(100 * std.time.ns_per_ms);
                        break;
                    }
                }
            } else {
                // No new blocks. Sleep briefly to avoid CPU spin.
                // Reduced from 500ms to 5ms for high TPS (Phase 9)
                std.time.sleep(5 * std.time.ns_per_ms);
            }
        }
    }
};

// Tests
const testing = std.testing;

test "blockchain initialization" {
    // Use unique data directory for this test
    // Use unique data directory for this test
    const zeicoin = try testing.allocator.create(ZeiCoin);
    zeicoin.* = ZeiCoin{
        .database = try db.Database.init(testing.allocator, "test_zeicoin_data_init"),
        .mutex = .{},
        .network = null,
        .allocator = testing.allocator,
        .root_public_key = std.mem.zeroes([32]u8),
        .consensus_engine = undefined, // Test must manual init if needed
        .solo_impl = undefined,
        .sync_thread = null,
        .should_stop_sync = std.atomic.Value(bool).init(false),
        .acl = undefined,
        .verifier = undefined,
        .ingestion_pool = null,
    };
    zeicoin.verifier = try verifier.ParallelVerifier.init(testing.allocator, 1);
    // Initialize consensus engine for test
    const solo_engine = try solo.SoloOrderer.init(testing.allocator, &zeicoin.database, null);
    zeicoin.consensus_engine = solo_engine.consenter();
    zeicoin.solo_impl = solo_engine;
    try zeicoin.consensus_engine.start();

    zeicoin.acl = acl_module.AccessControl.init();
    defer zeicoin.deinit();

    // Create genesis manually for this test
    if (try zeicoin.getHeight() == 0) {
        try zeicoin.createGenesis();
    }

    // Should have genesis block (height starts at 1 after genesis creation)
    const height = try zeicoin.getHeight();
    try testing.expect(height >= 1); // May be 1 or 2 depending on auto-mining

    // Should have genesis account
    const genesis_public_key = std.mem.zeroes([32]u8);
    const genesis_addr = util.hash(&genesis_public_key);
    const genesis_account_struct = try zeicoin.getAccount(genesis_addr);
    try testing.expectEqual(@as(u8, 1), genesis_account_struct.role);

    // Clean up test data
    std.fs.cwd().deleteTree("test_zeicoin_data_init") catch {};
}

test "transaction processing" {
    // Ensure clean state
    std.fs.cwd().deleteTree("test_zeicoin_data_tx") catch {};

    // Use unique data directory for this test
    const zeicoin = try testing.allocator.create(ZeiCoin);
    zeicoin.* = ZeiCoin{
        .database = try db.Database.init(testing.allocator, "test_zeicoin_data_tx"),
        .mutex = .{},
        .network = null,
        .allocator = testing.allocator,
        .root_public_key = std.mem.zeroes([32]u8),
        .consensus_engine = undefined,
        .solo_impl = undefined,
        .sync_thread = null,
        .should_stop_sync = std.atomic.Value(bool).init(false),
        .acl = undefined,
        .verifier = undefined,
        .ingestion_pool = null,
    };
    zeicoin.verifier = try verifier.ParallelVerifier.init(testing.allocator, 1);
    // Initialize consensus engine for test
    const solo_engine = try solo.SoloOrderer.init(testing.allocator, &zeicoin.database, null);
    zeicoin.consensus_engine = solo_engine.consenter();
    zeicoin.solo_impl = solo_engine;
    try zeicoin.consensus_engine.start();

    zeicoin.acl = acl_module.AccessControl.init();
    defer zeicoin.deinit();

    // Create genesis manually for this test
    if (try zeicoin.getHeight() == 0) {
        try zeicoin.createGenesis();
    }

    // Create a test root CA for this test
    var root_ca = try key.KeyPair.generateUnsignedKey();
    defer root_ca.deinit();
    zeicoin.root_public_key = root_ca.public_key;

    // Create a valid Identity (Key + Cert) for the sender
    var sender_identity = try key.Identity.createNew(root_ca);
    defer sender_identity.deinit();

    // Alias for convenience (to minimal changes to rest of test)
    var sender_keypair = sender_identity.keypair;
    const sender_cert = sender_identity.certificate;

    const sender_addr = sender_keypair.getAddress();
    var alice_addr = std.mem.zeroes(Address);
    // Use a more unique address pattern
    alice_addr[0] = 0xAA;
    alice_addr[1] = 0xBB;
    alice_addr[31] = 0xFF;

    // Create account for sender manually since this is just a test
    const sender_account = Account{
        .address = sender_addr,
        .nonce = 0,
        .role = 2,
    };
    try zeicoin.database.saveAccount(sender_addr, sender_account);

    // Create payload on heap because SoloOrderer.deinit will try to free it
    const payload = try testing.allocator.dupe(u8, "record_entry|test_key|test_val");
    // Note: We don't defer free here because ownership is transferred to the orderer

    // Create and sign transaction
    var tx = Transaction{
        .type = .invoke,
        .sender = sender_addr,
        .recipient = alice_addr,
        .payload = payload,
        .nonce = 0,
        .timestamp = 1704067200,
        .sender_public_key = sender_keypair.public_key,
        .sender_cert = sender_cert,
        .signature = std.mem.zeroes(types.Signature), // Will be replaced
        .network_id = 1,
    };

    // Sign the transaction
    const tx_hash = tx.hashForSigning();
    tx.signature = try sender_keypair.sign(&tx_hash);

    try zeicoin.addTransaction(tx);

    // Test logic removed as it relies on produceBlock which is now in Consensus module
    // and validator_identity which was removed from ZeiCoin struct

    // Clean up test data
    std.fs.cwd().deleteTree("test_zeicoin_data_tx") catch {};
}

test "block retrieval by height" {
    // Use unique data directory for this test
    const zeicoin = try testing.allocator.create(ZeiCoin);
    zeicoin.* = ZeiCoin{
        .database = try db.Database.init(testing.allocator, "test_zeicoin_data_retrieval"),
        .mutex = .{},
        .network = null,
        .allocator = testing.allocator,
        .root_public_key = std.mem.zeroes([32]u8),
        .consensus_engine = undefined,
        .solo_impl = undefined,
        .sync_thread = null,
        .should_stop_sync = std.atomic.Value(bool).init(false),
        .acl = undefined,
        .verifier = undefined,
        .ingestion_pool = null,
    };
    zeicoin.verifier = try verifier.ParallelVerifier.init(testing.allocator, 1);
    // Initialize consensus engine for test
    const solo_engine = try solo.SoloOrderer.init(testing.allocator, &zeicoin.database, null);
    zeicoin.consensus_engine = solo_engine.consenter();
    zeicoin.solo_impl = solo_engine;
    try zeicoin.consensus_engine.start();

    zeicoin.acl = acl_module.AccessControl.init();
    defer zeicoin.deinit();

    // Create genesis manually for this test
    if (try zeicoin.getHeight() == 0) {
        try zeicoin.createGenesis();
    }

    // Should have genesis block at height 0
    const genesis_block = try zeicoin.getBlockByHeight(0);
    defer testing.allocator.free(genesis_block.transactions);

    try testing.expectEqual(@as(u32, 0), genesis_block.txCount());
    try testing.expectEqual(@as(u64, types.Genesis.timestamp), genesis_block.header.timestamp);

    // Clean up test data
    std.fs.cwd().deleteTree("test_zeicoin_data_retrieval") catch {};
}

test "block validation" {
    // Use unique data directory for this test
    const zeicoin = try testing.allocator.create(ZeiCoin);
    zeicoin.* = ZeiCoin{
        .database = try db.Database.init(testing.allocator, "test_zeicoin_data_validation"),
        .mutex = .{},
        .network = null,
        .allocator = testing.allocator,
        .root_public_key = std.mem.zeroes([32]u8),
        .consensus_engine = undefined,
        .solo_impl = undefined,
        .sync_thread = null,
        .should_stop_sync = std.atomic.Value(bool).init(false),
        .acl = undefined,
        .verifier = undefined,
        .ingestion_pool = null,
    };
    zeicoin.verifier = try verifier.ParallelVerifier.init(testing.allocator, 1);
    // Initialize consensus engine for test
    const solo_engine = try solo.SoloOrderer.init(testing.allocator, &zeicoin.database, null);
    zeicoin.consensus_engine = solo_engine.consenter();
    zeicoin.solo_impl = solo_engine;
    try zeicoin.consensus_engine.start();

    zeicoin.acl = acl_module.AccessControl.init();
    defer {
        zeicoin.deinit();
        std.fs.cwd().deleteTree("test_zeicoin_data_validation") catch {};
    }

    // Create a valid test block that extends the genesis
    if (try zeicoin.getHeight() == 0) {
        try zeicoin.createGenesis();
    }
    const current_height = try zeicoin.getHeight();

    const prev_block = try zeicoin.getBlockByHeight(current_height - 1);
    defer testing.allocator.free(prev_block.transactions);

    // Create valid transactions for the block
    const transactions = try testing.allocator.alloc(types.Transaction, 1);
    defer testing.allocator.free(transactions);

    // Create a test root CA
    var root_ca = try key.KeyPair.generateUnsignedKey();
    defer root_ca.deinit();
    zeicoin.root_public_key = root_ca.public_key;

    // Create Validator Identity
    var validator_identity = try key.Identity.createNew(root_ca);
    defer validator_identity.deinit();

    // Create valid Identity
    var sender_identity = try key.Identity.createNew(root_ca);
    // Note: sender_identity owned by function scope, need defer deinit if standard
    // But here we might need manual deinit if KeyPair deinit implementation is strict
    // key.KeyPair.deinit just clears memory.
    defer sender_identity.deinit();

    var sender_keypair = sender_identity.keypair;
    const sender_cert = sender_identity.certificate;
    defer sender_keypair.deinit();
    const sender_addr = sender_keypair.getAddress();

    // Give sender some funds first (so transaction is valid)
    const sender_account = types.Account{
        .address = sender_addr,
        .nonce = 0,
        .role = 2,
    };
    try zeicoin.database.saveAccount(sender_addr, sender_account);

    const payload = try testing.allocator.dupe(u8, "record_entry|test_key|test_val");
    defer testing.allocator.free(payload); // Manually free because we bypass Orderer
    var tx = types.Transaction{
        .type = .invoke,
        .sender = sender_addr,
        .recipient = std.mem.zeroes(types.Address),
        .payload = payload,
        .nonce = 0,
        .timestamp = @intCast(util.getTime()),
        .sender_public_key = sender_keypair.public_key,
        .network_id = 1,
        .sender_cert = sender_cert,
        .signature = std.mem.zeroes(types.Signature),
    };

    // Sign it
    const tx_hash = tx.hashForSigning();
    tx.signature = try sender_keypair.sign(&tx_hash);

    transactions[0] = tx;

    // Create valid block
    var valid_block = types.Block{
        .header = types.BlockHeader{
            .previous_hash = prev_block.hash(),
            .merkle_root = std.mem.zeroes(types.Hash), // TODO: merkle root
            .timestamp = @intCast(util.getTime()),
            .validator_public_key = validator_identity.keypair.public_key,
            .validator_cert = validator_identity.certificate,
            .signature = std.mem.zeroes(types.Signature),
        },
        .transactions = transactions,
    };

    // Sign the block
    const block_hash = valid_block.header.hash();
    valid_block.header.signature = try validator_identity.keypair.sign(&block_hash);

    // No need to find nonce anymore

    // Should validate correctly
    const is_valid = try zeicoin.validateBlock(valid_block, current_height);
    try testing.expect(is_valid);

    // Invalid block with wrong previous hash should fail
    var invalid_block = valid_block;
    invalid_block.header.previous_hash = std.mem.zeroes(types.Hash);
    const is_invalid = try zeicoin.validateBlock(invalid_block, current_height);
    try testing.expect(!is_invalid);
}

test "mempool cleaning after block application" {
    // Use unique data directory for this test
    // Test removed as mempool is no longer managed by ZeiCoin struct
    std.fs.cwd().deleteTree("test_zeicoin_data_mempool") catch {};
}

test "block broadcasting integration" {
    // Use unique data directory for this test
    const zeicoin = try testing.allocator.create(ZeiCoin);
    zeicoin.* = ZeiCoin{
        .database = try db.Database.init(testing.allocator, "test_zeicoin_data_broadcast"),
        .mutex = .{},
        .network = null,
        .allocator = testing.allocator,
        .root_public_key = std.mem.zeroes([32]u8),
        .consensus_engine = undefined,
        .solo_impl = undefined,
        .sync_thread = null,
        .should_stop_sync = std.atomic.Value(bool).init(false),
        .acl = undefined,
        .verifier = undefined,
        .ingestion_pool = null,
    };
    zeicoin.verifier = try verifier.ParallelVerifier.init(testing.allocator, 1);
    // Initialize consensus engine for test
    const solo_engine = try solo.SoloOrderer.init(testing.allocator, &zeicoin.database, null);
    zeicoin.consensus_engine = solo_engine.consenter();
    zeicoin.solo_impl = solo_engine;
    try zeicoin.consensus_engine.start();

    zeicoin.acl = acl_module.AccessControl.init();
    defer {
        zeicoin.deinit();
        std.fs.cwd().deleteTree("test_zeicoin_data_broadcast") catch {};
    }

    // This test verifies that broadcastNewBlock doesn't crash when no network is present
    const transactions = try testing.allocator.alloc(types.Transaction, 0);
    defer testing.allocator.free(transactions);

    const test_block = types.Block{
        .header = types.BlockHeader{
            .previous_hash = std.mem.zeroes(types.Hash),
            .merkle_root = std.mem.zeroes(types.Hash),
            .timestamp = @intCast(util.getTime()),
            .validator_public_key = std.mem.zeroes([32]u8),
            .validator_cert = std.mem.zeroes([64]u8),
            .signature = std.mem.zeroes(types.Signature),
        },
        .transactions = transactions,
    };

    // Should not crash when no network is available
    zeicoin.broadcastNewBlock(test_block);

    // Test passed if we get here without crashing
    try testing.expect(true);
}

test {
    std.testing.refAllDecls(governance);
}
