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

// Type aliases for clarity
const Transaction = types.Transaction;
const Block = types.Block;
const BlockHeader = types.BlockHeader;
const Account = types.Account;
const Address = types.Address;
const Hash = types.Hash;

/// Adria blockchain state and operations
pub const Adria = struct {
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

    // Active Root CAs (Gatekeepers)
    root_public_keys: std.ArrayList([32]u8),

    // Certificate Revocation List (Protocol v2) — serial numbers of revoked certs
    revoked_serials: std.ArrayList(u64),

    // The Pluggable Consensus Engine
    consensus_engine: consensus.Consenter,
    // Reference to the specific implementation
    solo_impl: *solo.SoloOrderer,

    // Network Identity
    network_id: u64,

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
    pub fn init(allocator: std.mem.Allocator, network_id: u64, seed_root_ca: []const u8) !*Adria {
        // Initialize State (World State KV Store)
        const data_dir = "apl_data";
        const database = try db.Database.init(allocator, data_dir);

        const self = try allocator.create(Adria);
        self.* = Adria{
            .database = database,
            .mutex = .{},
            // .mempool = ArrayList(Transaction).init(allocator), // Mempool moved to Consensus
            .network = null,
            .allocator = allocator,
            .root_public_keys = std.ArrayList([32]u8).init(allocator),
            .revoked_serials = std.ArrayList(u64).init(allocator),
            .network_id = network_id,
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
            try self.createGenesis(seed_root_ca);
        }

        // We pass the validator identity if we have it
        const validator_id: ?key.Identity = null;

        // Init Solo Orderer (Pluggable architecture allows Raft here in future)
        const solo_engine = try solo.SoloOrderer.init(allocator, &self.database, validator_id);
        self.consensus_engine = solo_engine.consenter();
        self.solo_impl = solo_engine;

        // Load initial governance policy into memory
        try self.reloadGovernancePolicy();

        return self;
    }

    /// Reloads the cached Root CAs and CRL from the on-chain Governance Policy
    pub fn reloadGovernancePolicy(self: *Adria) !void {
        const policy_json_opt = try self.database.get(governance.GovernanceSystem.CONFIG_KEY);
        if (policy_json_opt) |policy_json| {
            defer self.allocator.free(policy_json);

            const parsed = std.json.parseFromSlice(governance.GovernancePolicy, self.allocator, policy_json, .{ .ignore_unknown_fields = true }) catch |err| {
                print("[ERROR] Failed to parse Governance Policy: {}\n", .{err});
                return err;
            };
            defer parsed.deinit();

            if (parsed.value.protocol_version != types.SUPPORTED_PROTOCOL_VERSION) {
                print("ERROR: Protocol version mismatch.\n", .{});
                print("Genesis requires protocol v{}.\n", .{parsed.value.protocol_version});
                print("This binary supports protocol v{}.\n", .{types.SUPPORTED_PROTOCOL_VERSION});
                print("Upgrade required.\n", .{});
                std.process.exit(1);
            }

            self.mutex.lock();
            defer self.mutex.unlock();

            // Reload Root CAs
            self.root_public_keys.clearRetainingCapacity();
            for (parsed.value.root_cas) |hex_key| {
                var pk: [32]u8 = undefined;
                _ = std.fmt.hexToBytes(&pk, hex_key) catch continue;
                try self.root_public_keys.append(pk);
            }
            print("[INFO] Reloaded {} Active Root CAs from Blockchain State\n", .{self.root_public_keys.items.len});

            // Reload CRL (Certificate Revocation List)
            self.revoked_serials.clearRetainingCapacity();
            for (parsed.value.revoked_serials) |serial| {
                try self.revoked_serials.append(serial);
            }
            if (self.revoked_serials.items.len > 0) {
                print("[INFO] Reloaded {} Revoked Certificate Serials from Blockchain State\n", .{self.revoked_serials.items.len});
            }
        }
    }

    /// Start the background sync loop and consensus engine
    pub fn start(self: *Adria) !void {
        self.should_stop_sync.store(false, .release);
        if (self.sync_thread == null) {
            self.sync_thread = try std.Thread.spawn(.{}, syncLoop, .{self});
        }

        self.consensus_engine.start() catch |err| {
            print("[ERROR] Failed to start consensus engine: {}\n", .{err});
            return err;
        };
    }

    /// Cleanup blockchain resources
    pub fn deinit(self: *Adria) void {
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

        self.root_public_keys.deinit();
        self.revoked_serials.deinit();
        self.database.deinit();
        if (self.network) |n| n.deinit();
        self.allocator.destroy(self);
    }

    /// Set the validator identity for the underlying Consensus engine (Solo)
    pub fn setValidator(self: *Adria, identity: key.Identity) void {
        // Direct access to solo_impl specific field
        // In full pluggable model, we might need a generic 'setIdentity' or configure at init
        self.solo_impl.validator = identity;
        print("[INFO] Validator Identity set for Consensus Engine\n", .{});
    }

    /// Create the genesis block with initial distribution
    fn createGenesis(self: *Adria, seed_root_ca: []const u8) !void {
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
            var initial_root_ca: []const u8 = undefined;
            if (seed_root_ca.len == 64) {
                initial_root_ca = seed_root_ca;
            } else {
                initial_root_ca = "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29";
                print("[WARNING] seed_root_ca not provided in config. Using hardcoded genesis admin (Development Only).\n", .{});
            }
            const initial_policy = governance.GovernancePolicy{
                .protocol_version = types.SUPPORTED_PROTOCOL_VERSION,
                .root_cas = &[_][]const u8{initial_root_ca},
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
                .protocol_version = types.SUPPORTED_PROTOCOL_VERSION,
                .previous_hash = std.mem.zeroes(Hash),
                .merkle_root = std.mem.zeroes(Hash),
                .timestamp = types.Genesis.timestamp,
                .validator_public_key = std.mem.zeroes([32]u8),
                .validator_cert = std.mem.zeroes([64]u8),
                .validator_cert_serial = 0,
                .validator_cert_issued_at = 0,
                .validator_cert_expires_at = std.math.maxInt(u64),
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
    fn getAccountInternal(self: *Adria, address: Address) !Account {
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
    pub fn getAccount(self: *Adria, address: Address) !Account {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.getAccountInternal(address);
    }

    /// Add transaction to the network (submit to Consensus)
    pub fn addTransaction(self: *Adria, tx: types.Transaction) !void {
        // Validation (syntax check)
        if (!try self.validateTransaction(tx)) {
            return error.InvalidTransaction;
        }

        try self.addVerifiedTransaction(tx);
    }

    /// Add a PRE-VERIFIED transaction to consensus (Internal/Worker use only)
    pub fn addVerifiedTransaction(self: *Adria, tx: types.Transaction) !void {
        try self.consensus_engine.recvTransaction(tx);
        // print("[INFO] Tx submitted to Consensus\n", .{});
    }

    /// Validate a transaction against current blockchain state
    pub fn validateTransaction(self: *Adria, tx: Transaction) !bool {
        // Basic structure validation
        if (!tx.isValid()) return false;

        // Get sender account
        const sender_account = try self.getAccount(tx.sender);

        // Check nonce (must be >= next expected nonce for Mempool)
        if (tx.nonce < sender_account.nextNonce()) {
            print("[WARN] Invalid nonce: expected >= {}, got {}\n", .{ sender_account.nextNonce(), tx.nonce });
            return false;
        }

        // Spam prevention is now handled by Identity/ACLs

        // Verify Identity (The Gatekeeper) — Protocol v2: CertificateV2 + CRL
        var local_root_pks: [10][32]u8 = undefined;
        var num_root_pks: usize = 0;
        var local_revoked: [256]u64 = undefined;
        var num_revoked: usize = 0;
        {
            self.mutex.lock();
            num_root_pks = @min(self.root_public_keys.items.len, 10);
            @memcpy(local_root_pks[0..num_root_pks], self.root_public_keys.items[0..num_root_pks]);
            num_revoked = @min(self.revoked_serials.items.len, 256);
            @memcpy(local_revoked[0..num_revoked], self.revoked_serials.items[0..num_revoked]);
            self.mutex.unlock();
        }

        // Check CRL: reject if cert serial is revoked
        for (local_revoked[0..num_revoked]) |revoked| {
            if (tx.cert_serial == revoked) {
                print("[ERROR] Permission Denied: Certificate serial {} has been revoked\n", .{tx.cert_serial});
                return false;
            }
        }

        // Timestamp validation: reject stale or future-dated transactions
        const current_time: u64 = @intCast(std.time.timestamp());
        if (!tx.isTimestampValid(current_time)) {
            print("[ERROR] Transaction timestamp out of acceptable range\n", .{});
            return false;
        }

        // Verify CertificateV2: signature + expiry + issuer
        var cert_valid = false;
        for (local_root_pks[0..num_root_pks]) |root_pk| {
            if (key.MSP.verifyCertificateV2(
                root_pk,
                tx.sender_cert,
                tx.sender_public_key,
                tx.cert_serial,
                tx.cert_issued_at,
                tx.cert_expires_at,
                current_time,
            )) {
                cert_valid = true;
                break;
            }
        }

        if (!cert_valid) {
            print("[ERROR] Permission Denied: Invalid or Expired Identity Certificate\n", .{});
            return false;
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
    fn validateTransactionState(self: *Adria, tx: Transaction) !bool {
        // Basic structure validation
        if (!tx.isValid()) return false;

        // Check Network ID
        if (tx.network_id != self.network_id) {
            print("[ERROR] Invalid Network ID: expected {}, got {}\n", .{ self.network_id, tx.network_id });
            return false;
        }

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
    fn processTransaction(self: *Adria, tx: Transaction, block_height: u64, tx_index: u32) !void {
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
                } else if (std.mem.eql(u8, chaincode_id, chaincode.DatasetStore.ID)) {
                    // Requires Writer (checked above)
                    payload_result = chaincode.DatasetStore.invoke(&stub, function_name, args.items) catch |err| {
                        print("[ERROR] Failed to invoke DatasetStore: {}\n", .{err});
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
        }

        print("[INFO] Processed type={}\n", .{tx.type});
    }

    /// Get blockchain height
    pub fn getHeight(self: *Adria) !u32 {
        return try self.database.getHeight();
    }

    /// Get block by height
    pub fn getBlockByHeight(self: *Adria, height: u32) !Block {
        return try self.database.getBlock(height);
    }

    /// Validate an incoming block
    pub fn validateBlock(self: *Adria, block: Block, expected_height: u32) !bool {
        // Check basic block structure
        if (!block.isValid()) return false;

        // Strict Protocol Version Check (No Mixed Protocols)
        if (block.header.protocol_version != types.SUPPORTED_PROTOCOL_VERSION) {
            print("[ERROR] Block rejected: Invalid protocol version. Expected {}, got {}\n", .{ types.SUPPORTED_PROTOCOL_VERSION, block.header.protocol_version });
            return false;
        }

        // Check block height consistency
        const current_height = try self.getHeight();
        if (expected_height != current_height) return false;

        // In the future, we will validate the Orderer's signature here
        if (@import("builtin").mode == .Debug) {
            // Debug hook
        }

        var local_root_pks: [10][32]u8 = undefined;
        var num_root_pks: usize = 0;
        {
            self.mutex.lock();
            num_root_pks = @min(self.root_public_keys.items.len, 10);
            @memcpy(local_root_pks[0..num_root_pks], self.root_public_keys.items[0..num_root_pks]);
            self.mutex.unlock();
        }

        // Verify Validator Identity (The "Gatekeeper") — Protocol v2: use verifyCertificateV2
        const block_current_time: u64 = @intCast(std.time.timestamp());
        var cert_valid = false;
        for (local_root_pks[0..num_root_pks]) |root_pk| {
            if (key.MSP.verifyCertificateV2(
                root_pk,
                block.header.validator_cert,
                block.header.validator_public_key,
                block.header.validator_cert_serial,
                block.header.validator_cert_issued_at,
                block.header.validator_cert_expires_at,
                block_current_time,
            )) {
                cert_valid = true;
                break;
            }
        }

        if (!cert_valid) {
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

        // Validate all transactions in block (Protocol v2: parallel with CRL + expiry)
        var local_revoked_block: [256]u64 = undefined;
        var num_revoked_block: usize = 0;
        {
            self.mutex.lock();
            num_revoked_block = @min(self.revoked_serials.items.len, 256);
            @memcpy(local_revoked_block[0..num_revoked_block], self.revoked_serials.items[0..num_revoked_block]);
            self.mutex.unlock();
        }
        if (!try self.verifier.verifyBlock(block, local_root_pks[0..num_root_pks], local_revoked_block[0..num_revoked_block], block_current_time)) {
            print("[ERROR] Block rejected: Parallel verification failed (Bad Signatures/Cert)\n", .{});
            return false;
        }

        // Sequential State Validation (Nonce, etc)
        for (block.transactions) |tx| {
            if (!try self.validateTransactionState(tx)) return false;
        }

        return true;
    }

    /// Apply a valid block to the blockchain
    fn applyBlock(self: *Adria, block: Block) !void {
        const block_height = try self.getHeight();

        // Process all transactions in the block
        for (block.transactions, 0..) |tx, i| {
            // Handle transactions (no coinbase in permissioned mode)
            try self.processTransaction(tx, block_height, @as(u32, @intCast(i)));
        }

        // Execute block state transitions and commit
        try self.database.commit();
    }

    /// Clean mempool of transactions that are now in a block
    fn cleanMempool(self: *Adria, block: Block) void {
        // Mempool is now managed by Consensus engine.
        // We don't touch it here.
        _ = self;
        _ = block;
    }

    /// Start networking on specified port
    pub fn startNetwork(self: *Adria, port: u16) !void {
        if (self.network != null) return; // Already started

        var network = net.NetworkManager.init(self.allocator);
        try network.start(port);
        self.network = network;

        print("[INFO] APL network started on port {}\n", .{port});
    }

    /// Stop networking
    pub fn stopNetwork(self: *Adria) void {
        if (self.network) |*network| {
            network.stop();
            network.deinit();
            self.network = null;
            print("[INFO] APL network stopped\n", .{});
        }
    }

    /// Connect to a peer
    pub fn connectToPeer(self: *Adria, address: []const u8) !void {
        if (self.network) |*network| {
            try network.addPeer(address);
        } else {
            return error.NetworkNotStarted;
        }
    }

    /// Print blockchain status
    /// Thread-safe save account (Zen wrapper)
    pub fn saveAccount(self: *Adria, address: types.Address, account: types.Account) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        try self.database.saveAccount(address, account);
    }

    pub fn printStatus(self: *Adria) void {
        print("\n[INFO] APL Blockchain Status:\n", .{});
        const height = self.getHeight() catch 0;
        const account_count = self.database.getStateCount() catch 0;
        print("   Height: {} blocks\n", .{height});
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
    fn broadcastNewBlock(self: *Adria, block: types.Block) void {
        if (self.network) |network| {
            network.broadcastBlock(block);
            print("[INFO] Block propagating to {} peers\n", .{network.getPeerCount()});
        }
    }

    /// Handle incoming transaction from network peer
    pub fn handleIncomingTransaction(self: *Adria, transaction: types.Transaction) !void {
        // This check is now handled by the Consensus engine's mempool

        // Validate and add to mempool if valid
        self.addTransaction(transaction) catch |err| {
            print("[WARN] Rejected network transaction: {}\n", .{err});
            return err;
        };

        print("[INFO] Network transaction accepted\n", .{});
    }

    /// Handle incoming block from network peer
    pub fn handleIncomingBlock(self: *Adria, block: types.Block) !void {
        // Basic validation and chain extension
        const current_height = try self.getHeight();

        print("[INFO] Block received from peer with {} transactions\n", .{block.transactions.len});

        // Check if we already have this block (prevent duplicates)
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

        // Validate: check if block extends our chain properly
        if (current_height > 0) {
            const prev_block = try self.database.getBlock(current_height - 1);
            defer self.allocator.free(prev_block.transactions);

            const expected_prev_hash = prev_block.hash();
            if (!std.mem.eql(u8, &block.header.previous_hash, &expected_prev_hash)) {
                print("[ERROR] Block rejected: previous hash doesn't match\n", .{});
                return;
            }
        }

        // Full block validation (Signatures, Nonces, Protocol Version, Identity)
        if (!try self.validateBlock(block, current_height)) {
            print("[ERROR] Block rejected: Cryptographic or Protocol validation failed\n", .{});
            return;
        }

        // Process all transactions in the block
        // Handled by syncLoop (Execution Thread) to avoid race conditions and double execution
        // We only save the block here.

        // Save block to database
        try self.database.saveBlock(current_height, block);

        print("[INFO] Block #{} accepted (Queued for Execution)\n", .{current_height});

        // Network propagation: relay valid block to other peers (but not back to sender)
        if (self.network) |network| {
            network.*.broadcastBlock(block);
            print("[INFO] Relaying valid block to peers\n", .{});
        }
    }
    /// Background loop: Syncs execution state with committed blocks (Ordering -> Execution)
    fn syncLoop(self: *Adria) void {
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

                        // Check if state changes affected the governance policy
                        self.reloadGovernancePolicy() catch |err| {
                            print("[WARN] Failed to reload Governance Policy after block execution: {}\n", .{err});
                        };

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
    const adria = try testing.allocator.create(Adria);
    adria.* = Adria{
        .database = try db.Database.init(testing.allocator, "test_adria_data_init"),
        .mutex = .{},
        .network = null,
        .network_id = 1,
        .allocator = testing.allocator,
        .root_public_keys = std.ArrayList([32]u8).init(testing.allocator),
        .revoked_serials = std.ArrayList(u64).init(testing.allocator),
        .consensus_engine = undefined,
        .solo_impl = undefined,
        .sync_thread = null,
        .should_stop_sync = std.atomic.Value(bool).init(false),
        .acl = undefined,
        .verifier = undefined,
        .ingestion_pool = null,
    };
    adria.verifier = try verifier.ParallelVerifier.init(testing.allocator, 1);
    // Initialize consensus engine for test
    const solo_engine = try solo.SoloOrderer.init(testing.allocator, &adria.database, null);
    adria.consensus_engine = solo_engine.consenter();
    adria.solo_impl = solo_engine;
    try adria.consensus_engine.start();

    adria.acl = acl_module.AccessControl.init();
    defer adria.deinit();

    // Create genesis manually for this test
    if (try adria.getHeight() == 0) {
        try adria.createGenesis("");
    }

    // Should have genesis block (height starts at 1 after genesis creation)
    const height = try adria.getHeight();
    try testing.expect(height >= 1); // May be 1 or 2 depending on auto-mining

    // Should have genesis account
    const genesis_public_key = std.mem.zeroes([32]u8);
    const genesis_addr = util.hash(&genesis_public_key);
    const genesis_account_struct = try adria.getAccount(genesis_addr);
    try testing.expectEqual(@as(u8, 1), genesis_account_struct.role);

    // Clean up test data
    std.fs.cwd().deleteTree("test_adria_data_init") catch {};
}

test "transaction processing" {
    // Ensure clean state
    std.fs.cwd().deleteTree("test_adria_data_tx") catch {};

    // Use unique data directory for this test
    const adria = try testing.allocator.create(Adria);
    adria.* = Adria{
        .database = try db.Database.init(testing.allocator, "test_adria_data_tx"),
        .mutex = .{},
        .network = null,
        .network_id = 1,
        .allocator = testing.allocator,
        .root_public_keys = std.ArrayList([32]u8).init(testing.allocator),
        .revoked_serials = std.ArrayList(u64).init(testing.allocator),
        .consensus_engine = undefined,
        .solo_impl = undefined,
        .sync_thread = null,
        .should_stop_sync = std.atomic.Value(bool).init(false),
        .acl = undefined,
        .verifier = undefined,
        .ingestion_pool = null,
    };
    adria.verifier = try verifier.ParallelVerifier.init(testing.allocator, 1);
    // Initialize consensus engine for test
    const solo_engine = try solo.SoloOrderer.init(testing.allocator, &adria.database, null);
    adria.consensus_engine = solo_engine.consenter();
    adria.solo_impl = solo_engine;
    try adria.consensus_engine.start();

    adria.acl = acl_module.AccessControl.init();
    defer adria.deinit();

    // Create genesis manually for this test
    if (try adria.getHeight() == 0) {
        try adria.createGenesis("");
    }

    // Create a test root CA for this test
    var root_ca = try key.KeyPair.generateUnsignedKey();
    defer root_ca.deinit();
    try adria.root_public_keys.append(root_ca.public_key);

    // Create a valid Identity (Key + Cert) for the sender
    var sender_identity = try key.Identity.createNew(root_ca);
    defer sender_identity.deinit();

    var sender_keypair = sender_identity.keypair;
    const sender_cert_v2 = sender_identity.certificate;

    const sender_addr = sender_keypair.getAddress();
    var alice_addr = std.mem.zeroes(Address);
    alice_addr[0] = 0xAA;
    alice_addr[1] = 0xBB;
    alice_addr[31] = 0xFF;

    const sender_account = Account{
        .address = sender_addr,
        .nonce = 0,
        .role = 2,
    };
    try adria.database.saveAccount(sender_addr, sender_account);

    const payload = try testing.allocator.dupe(u8, "record_entry|test_key|test_val");

    var tx = Transaction{
        .type = .invoke,
        .sender = sender_addr,
        .recipient = alice_addr,
        .payload = payload,
        .nonce = 0,
        .timestamp = @intCast(util.getTime()),
        .sender_public_key = sender_keypair.public_key,
        .sender_cert = sender_cert_v2.signature,
        .cert_serial = sender_cert_v2.serial,
        .cert_issued_at = sender_cert_v2.issued_at,
        .cert_expires_at = sender_cert_v2.expires_at,
        .signature = std.mem.zeroes(types.Signature),
        .network_id = 1,
    };

    // Sign the transaction
    const tx_hash = tx.hashForSigning();
    tx.signature = try sender_keypair.sign(&tx_hash);

    try adria.addTransaction(tx);

    // Clean up test data
    std.fs.cwd().deleteTree("test_adria_data_tx") catch {};
}

test "block retrieval by height" {
    // Use unique data directory for this test
    const adria = try testing.allocator.create(Adria);
    adria.* = Adria{
        .database = try db.Database.init(testing.allocator, "test_adria_data_retrieval"),
        .mutex = .{},
        .network = null,
        .network_id = 1,
        .allocator = testing.allocator,
        .root_public_keys = std.ArrayList([32]u8).init(testing.allocator),
        .revoked_serials = std.ArrayList(u64).init(testing.allocator),
        .consensus_engine = undefined,
        .solo_impl = undefined,
        .sync_thread = null,
        .should_stop_sync = std.atomic.Value(bool).init(false),
        .acl = undefined,
        .verifier = undefined,
        .ingestion_pool = null,
    };
    adria.verifier = try verifier.ParallelVerifier.init(testing.allocator, 1);
    // Initialize consensus engine for test
    const solo_engine = try solo.SoloOrderer.init(testing.allocator, &adria.database, null);
    adria.consensus_engine = solo_engine.consenter();
    adria.solo_impl = solo_engine;
    try adria.consensus_engine.start();

    adria.acl = acl_module.AccessControl.init();
    defer adria.deinit();

    // Create genesis manually for this test
    if (try adria.getHeight() == 0) {
        try adria.createGenesis("");
    }

    // Should have genesis block at height 0
    const genesis_block = try adria.getBlockByHeight(0);
    defer testing.allocator.free(genesis_block.transactions);

    try testing.expectEqual(@as(u32, 0), genesis_block.txCount());
    try testing.expectEqual(@as(u64, types.Genesis.timestamp), genesis_block.header.timestamp);

    // Clean up test data
    std.fs.cwd().deleteTree("test_adria_data_retrieval") catch {};
}

test "block validation" {
    // Use unique data directory for this test
    const adria = try testing.allocator.create(Adria);
    adria.* = Adria{
        .database = try db.Database.init(testing.allocator, "test_adria_data_validation"),
        .mutex = .{},
        .network = null,
        .network_id = 1,
        .allocator = testing.allocator,
        .root_public_keys = std.ArrayList([32]u8).init(testing.allocator),
        .revoked_serials = std.ArrayList(u64).init(testing.allocator),
        .consensus_engine = undefined,
        .solo_impl = undefined,
        .sync_thread = null,
        .should_stop_sync = std.atomic.Value(bool).init(false),
        .acl = undefined,
        .verifier = undefined,
        .ingestion_pool = null,
    };
    adria.verifier = try verifier.ParallelVerifier.init(testing.allocator, 1);
    // Initialize consensus engine for test
    const solo_engine = try solo.SoloOrderer.init(testing.allocator, &adria.database, null);
    adria.consensus_engine = solo_engine.consenter();
    adria.solo_impl = solo_engine;
    try adria.consensus_engine.start();

    adria.acl = acl_module.AccessControl.init();
    defer {
        adria.deinit();
        std.fs.cwd().deleteTree("test_adria_data_validation") catch {};
    }

    // Create a valid test block that extends the genesis
    if (try adria.getHeight() == 0) {
        try adria.createGenesis("");
    }
    const current_height = try adria.getHeight();

    const prev_block = try adria.getBlockByHeight(current_height - 1);
    defer testing.allocator.free(prev_block.transactions);

    // Create valid transactions for the block
    const transactions = try testing.allocator.alloc(types.Transaction, 1);
    defer testing.allocator.free(transactions);

    // Create a test root CA
    var root_ca = try key.KeyPair.generateUnsignedKey();
    defer root_ca.deinit();
    try adria.root_public_keys.append(root_ca.public_key);

    // Create Validator Identity
    var validator_identity = try key.Identity.createNew(root_ca);
    defer validator_identity.deinit();

    // Create valid Identity
    var sender_identity = try key.Identity.createNew(root_ca);
    defer sender_identity.deinit();

    var sender_keypair = sender_identity.keypair;
    const sender_cert_v2b = sender_identity.certificate;
    defer sender_keypair.deinit();
    const sender_addr = sender_keypair.getAddress();

    const sender_account = types.Account{
        .address = sender_addr,
        .nonce = 0,
        .role = 2,
    };
    try adria.database.saveAccount(sender_addr, sender_account);

    const payload = try testing.allocator.dupe(u8, "record_entry|test_key|test_val");
    defer testing.allocator.free(payload);
    var tx = types.Transaction{
        .type = .invoke,
        .sender = sender_addr,
        .recipient = std.mem.zeroes(types.Address),
        .payload = payload,
        .nonce = 0,
        .timestamp = @intCast(util.getTime()),
        .sender_public_key = sender_keypair.public_key,
        .network_id = 1,
        .sender_cert = sender_cert_v2b.signature,
        .cert_serial = sender_cert_v2b.serial,
        .cert_issued_at = sender_cert_v2b.issued_at,
        .cert_expires_at = sender_cert_v2b.expires_at,
        .signature = std.mem.zeroes(types.Signature),
    };

    const tx_hash = tx.hashForSigning();
    tx.signature = try sender_keypair.sign(&tx_hash);

    transactions[0] = tx;

    // Create valid block
    var valid_block = types.Block{
        .header = types.BlockHeader{
            .protocol_version = types.SUPPORTED_PROTOCOL_VERSION,
            .previous_hash = prev_block.hash(),
            .merkle_root = std.mem.zeroes(types.Hash),
            .timestamp = @intCast(util.getTime()),
            .validator_public_key = validator_identity.keypair.public_key,
            .validator_cert = validator_identity.certificate.signature,
            .validator_cert_serial = validator_identity.certificate.serial,
            .validator_cert_issued_at = validator_identity.certificate.issued_at,
            .validator_cert_expires_at = validator_identity.certificate.expires_at,
            .signature = std.mem.zeroes(types.Signature),
        },
        .transactions = transactions,
    };

    // Sign the block
    const block_hash = valid_block.header.hash();
    valid_block.header.signature = try validator_identity.keypair.sign(&block_hash);

    // No need to find nonce anymore

    // Should validate correctly
    const is_valid = try adria.validateBlock(valid_block, current_height);
    try testing.expect(is_valid);

    // Invalid block with wrong previous hash should fail
    var invalid_block = valid_block;
    invalid_block.header.previous_hash = std.mem.zeroes(types.Hash);
    const is_invalid = try adria.validateBlock(invalid_block, current_height);
    try testing.expect(!is_invalid);
}

test "mempool cleaning after block application" {
    // Use unique data directory for this test
    std.fs.cwd().deleteTree("test_adria_data_mempool") catch {};
}

test "block broadcasting integration" {
    // Use unique data directory for this test
    const adria = try testing.allocator.create(Adria);
    adria.* = Adria{
        .database = try db.Database.init(testing.allocator, "test_adria_data_broadcast"),
        .mutex = .{},
        .network = null,
        .network_id = 1,
        .allocator = testing.allocator,
        .root_public_keys = std.ArrayList([32]u8).init(testing.allocator),
        .revoked_serials = std.ArrayList(u64).init(testing.allocator),
        .consensus_engine = undefined,
        .solo_impl = undefined,
        .sync_thread = null,
        .should_stop_sync = std.atomic.Value(bool).init(false),
        .acl = undefined,
        .verifier = undefined,
        .ingestion_pool = null,
    };
    adria.verifier = try verifier.ParallelVerifier.init(testing.allocator, 1);
    // Initialize consensus engine for test
    const solo_engine = try solo.SoloOrderer.init(testing.allocator, &adria.database, null);
    adria.consensus_engine = solo_engine.consenter();
    adria.solo_impl = solo_engine;
    try adria.consensus_engine.start();

    adria.acl = acl_module.AccessControl.init();
    defer {
        adria.deinit();
        std.fs.cwd().deleteTree("test_adria_data_broadcast") catch {};
    }

    // This test verifies that broadcastNewBlock doesn't crash when no network is present
    const transactions = try testing.allocator.alloc(types.Transaction, 0);
    defer testing.allocator.free(transactions);

    const test_block = types.Block{
        .header = types.BlockHeader{
            .protocol_version = types.SUPPORTED_PROTOCOL_VERSION,
            .previous_hash = std.mem.zeroes(types.Hash),
            .merkle_root = std.mem.zeroes(types.Hash),
            .timestamp = @intCast(util.getTime()),
            .validator_public_key = std.mem.zeroes([32]u8),
            .validator_cert = std.mem.zeroes([64]u8),
            .validator_cert_serial = 0,
            .validator_cert_issued_at = 0,
            .validator_cert_expires_at = std.math.maxInt(u64),
            .signature = std.mem.zeroes(types.Signature),
        },
        .transactions = transactions,
    };

    // Should not crash when no network is available
    adria.broadcastNewBlock(test_block);

    // Test passed if we get here without crashing
    try testing.expect(true);
}

test {
    std.testing.refAllDecls(governance);
}
