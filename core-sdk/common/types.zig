// types.zig - Adria Core Types
// Minimal approach
// Simple account model with nonce-based double-spend protection

const std = @import("std");
const util = @import("util.zig");

// Network constants - Bootstrap nodes for peer discovery

// Network constants - Bootstrap nodes for peer discovery
pub const BOOTSTRAP_NODES = [_][]const u8{
    "134.199.168.129:10801", // Primary bootstrap node
    "192.168.1.122:10801", // Secondary bootstrap node
    "127.0.0.1:10801", // Local fallback
};

// Protocol Versioning
pub const ENGINE_VERSION = "0.1.0"; // Binary implementation version
pub const SUPPORTED_PROTOCOL_VERSION: u32 = 2; // Consensus and state transition rules version (v2: CertificateV2 + CRL + u64 network_id)

// Network ports - Adria networking
pub const NETWORK_PORTS = struct {
    pub const P2P: u16 = 10801; // Peer-to-peer network
    pub const CLIENT_API: u16 = 10802; // Client API
    pub const DISCOVERY: u16 = 10800; // UDP discovery
};

// Address is a simple 32-byte hash
pub const Address = [32]u8;

// Transaction signature (Ed25519 signature)
pub const Signature = [64]u8;

// Hash types for various purposes
pub const Hash = [32]u8;
pub const TxHash = Hash;
pub const BlockHash = Hash;

// Transaction type
pub const TransactionType = enum(u8) {
    invoke = 1,
};

/// Timestamp clock-skew tolerance for fresh transaction validation
/// Transactions more than 5 minutes in the future are rejected.
pub const TX_FUTURE_TOLERANCE_SECS: u64 = 300;
/// Transactions older than 1 hour are rejected (replay protection window).
pub const TX_PAST_TOLERANCE_SECS: u64 = 3600;

/// Adria transaction - Protocol v2 (CertificateV2 cert fields)
pub const Transaction = struct {
    type: TransactionType,
    sender: Address,
    recipient: Address, // Optional: for direct P2P invocations or specific chaincode targeting
    payload: []const u8, // Dynamic payload for invoke
    nonce: u64, // Sender's transaction counter
    timestamp: u64, // Unix timestamp when transaction was created
    sender_public_key: [32]u8, // Public key of sender
    sender_cert: [64]u8, // CertificateV2.signature (Ed25519 sig over cert signed data)
    cert_serial: u64, // CertificateV2 serial number for CRL revocation checking
    cert_issued_at: u64, // CertificateV2 issuance timestamp (Unix seconds)
    cert_expires_at: u64, // CertificateV2 expiry timestamp (Unix seconds)
    network_id: u64, // Network ID to prevent replay attacks (u64 in protocol v2+)
    signature: Signature, // Ed25519 signature of transaction data

    /// Calculate the hash of this transaction (used as transaction ID)
    pub fn hash(self: *const Transaction) TxHash {
        return self.hashForSigning();
    }

    /// Calculate hash of transaction data for signing (excludes signature field)
    pub fn hashForSigning(self: *const Transaction) Hash {
        var hasher = std.crypto.hash.Blake3.init(.{});

        // Simple serialization for hashing (order matters!)
        const type_byte = [1]u8{@intFromEnum(self.type)};
        hasher.update(&type_byte);
        hasher.update(&self.sender);
        hasher.update(&self.recipient);

        // Hash payload: write length + bytes
        var len_buf: [4]u8 = undefined;
        std.mem.writeInt(u32, &len_buf, @intCast(self.payload.len), .little);
        hasher.update(&len_buf);
        hasher.update(self.payload);

        var u64_buf: [8]u8 = undefined;
        std.mem.writeInt(u64, &u64_buf, self.nonce, .little);
        hasher.update(&u64_buf);

        std.mem.writeInt(u64, &u64_buf, self.timestamp, .little);
        hasher.update(&u64_buf);

        var u64_buf_netid: [8]u8 = undefined;
        std.mem.writeInt(u64, &u64_buf_netid, self.network_id, .little);
        hasher.update(&u64_buf_netid);

        hasher.update(&self.sender_public_key);
        hasher.update(&self.sender_cert);

        // Protocol v2: include cert metadata in signing hash (prevents tampering)
        var cert_buf: [8]u8 = undefined;
        std.mem.writeInt(u64, &cert_buf, self.cert_serial, .little);
        hasher.update(&cert_buf);
        std.mem.writeInt(u64, &cert_buf, self.cert_issued_at, .little);
        hasher.update(&cert_buf);
        std.mem.writeInt(u64, &cert_buf, self.cert_expires_at, .little);
        hasher.update(&cert_buf);

        var result: Hash = undefined;
        hasher.final(&result);
        return result;
    }

    /// Check if transaction has valid basic structure (time-independent, safe for replay).
    pub fn isValid(self: *const Transaction) bool {
        if (self.timestamp == 0) return false;
        if (std.mem.eql(u8, &self.sender, &self.recipient) and self.recipient[0] != 0) return false;

        // Verify that sender address matches the hash of provided public key
        const derived_address = util.hash(&self.sender_public_key);
        if (!std.mem.eql(u8, &self.sender, &derived_address)) return false;

        return true;
    }

    /// Check if transaction timestamp is within an acceptable clock-skew window.
    /// Use this for fresh transaction validation (NOT during hydrate/replay).
    pub fn isTimestampValid(self: *const Transaction, current_time: u64) bool {
        // Reject transactions too far in the future (clock skew tolerance: 5 min)
        if (self.timestamp > current_time + TX_FUTURE_TOLERANCE_SECS) return false;
        // Reject old transactions outside replay-protection window (1 hour)
        if (self.timestamp + TX_PAST_TOLERANCE_SECS < current_time) return false;
        return true;
    }
};

/// Account state in Adria network
pub const Account = struct {
    address: Address,
    nonce: u64, // Next expected transaction nonce
    role: u8, // 0=None, 1=Admin, 2=Writer, 3=Reader (Phase 5 ACL)

    /// Check if account has permission (Placeholder)
    pub fn hasPermission(self: *const Account, role_required: u8) bool {
        return self.role <= role_required;
    }

    /// Get expected nonce for next transaction
    pub fn nextNonce(self: *const Account) u64 {
        return self.nonce;
    }
};

/// Block header containing essential block information
pub const BlockHeader = struct {
    protocol_version: u32,
    previous_hash: BlockHash,
    merkle_root: Hash, // Root of transaction merkle tree
    timestamp: u64, // Unix timestamp when block was created
    validator_public_key: [32]u8, // Public key of block producer (Orderer)
    validator_cert: [64]u8, // CertificateV2 signature from Root CA (Protocol v2)
    validator_cert_serial: u64, // Certificate serial number (Protocol v2)
    validator_cert_issued_at: u64, // Certificate issue time (Protocol v2)
    validator_cert_expires_at: u64, // Certificate expiry time (Protocol v2)
    signature: Signature, // Ed25519 signature of block header

    /// Serialize block header to bytes (for hashing/signing)
    pub fn serialize(self: *const BlockHeader, writer: anytype) !void {
        try writer.writeInt(u32, self.protocol_version, .little);
        try writer.writeAll(&self.previous_hash);
        try writer.writeAll(&self.merkle_root);
        try writer.writeInt(u64, self.timestamp, .little);
        try writer.writeAll(&self.validator_public_key);
        try writer.writeAll(&self.validator_cert);
        try writer.writeInt(u64, self.validator_cert_serial, .little);
        try writer.writeInt(u64, self.validator_cert_issued_at, .little);
        try writer.writeInt(u64, self.validator_cert_expires_at, .little);
        // Signature is excluded from serialization for hashing
    }

    /// Calculate hash of this block header (excluding signature)
    pub fn hash(self: *const BlockHeader) BlockHash {
        // Serialize the block header to bytes
        var buffer: [1024]u8 = undefined;
        var stream = std.io.fixedBufferStream(&buffer);
        const writer = stream.writer();

        // Simple serialization for hashing
        self.serialize(writer) catch unreachable;

        const data = stream.getWritten();
        return util.hash(data);
    }
};

/// Complete block with header and transactions
pub const Block = struct {
    header: BlockHeader,
    transactions: []Transaction,

    /// Get the hash of this block
    pub fn hash(self: *const Block) BlockHash {
        return self.header.hash();
    }

    /// Get number of transactions in this block
    pub fn txCount(self: *const Block) u32 {
        return @intCast(self.transactions.len);
    }

    /// Check if block structure is valid
    pub fn isValid(self: *const Block) bool {
        // Basic validation
        if (self.transactions.len == 0) return false;

        // All transactions must be valid
        for (self.transactions) |tx| {
            if (!tx.isValid()) return false;
        }

        return true;
    }
};

/// Genesis block configuration
pub const Genesis = struct {
    pub const protocol_version: u32 = 2; // Protocol v2 with u64 network_id
    pub const timestamp: u64 = 1704067200; // January 1, 2024 00:00:00 UTC
    pub const message: []const u8 = "Adria Genesis Block";
};

/// Network configuration - TestNet vs MainNet
pub const NetworkType = enum {
    testnet,
    mainnet,
};

/// Current network configuration
pub const CURRENT_NETWORK: NetworkType = .testnet; // Change to .mainnet for production

/// Network-specific configurations
pub const NetworkConfig = struct {
    target_block_time: u64, // seconds

    pub fn current() NetworkConfig {
        return switch (CURRENT_NETWORK) {
            .testnet => NetworkConfig{
                .target_block_time = 10, // 10 seconds
            },
            .mainnet => NetworkConfig{
                .target_block_time = 600, // 10 minutes (Bitcoin-like)
            },
        };
    }

    pub fn networkName() []const u8 {
        return switch (CURRENT_NETWORK) {
            .testnet => "TestNet",
            .mainnet => "MainNet",
        };
    }

    pub fn displayInfo() void {
        const config = current();
        std.debug.print("[INFO] Network: {s}\n", .{networkName()});
        std.debug.print("[INFO] Block Time: {}s\n", .{config.target_block_time});
    }
};

// Tests
const testing = std.testing;

test "transaction validation" {
    // Create a test public key and derive address from it
    const alice_public_key = std.mem.zeroes([32]u8);
    const alice_addr = util.hash(&alice_public_key);
    var bob_addr = std.mem.zeroes(Address);
    bob_addr[0] = 1; // Make it different from alice

    const tx = Transaction{
        .type = .invoke,
        .sender = alice_addr,
        .recipient = bob_addr,
        .payload = "test_payload",
        .nonce = 1,
        .timestamp = 1704067200,
        .sender_public_key = alice_public_key,
        .sender_cert = std.mem.zeroes([64]u8),
        .cert_serial = 0,
        .cert_issued_at = 0,
        .cert_expires_at = std.math.maxInt(u64),
        .network_id = 1,
        .signature = std.mem.zeroes(Signature),
    };

    try testing.expect(tx.isValid());
}

test "transaction timestamp validation" {
    const public_key = std.mem.zeroes([32]u8);
    const sender_addr = util.hash(&public_key);
    var bob_addr = std.mem.zeroes(Address);
    bob_addr[0] = 1;

    const base_tx = Transaction{
        .type = .invoke,
        .sender = sender_addr,
        .recipient = bob_addr,
        .payload = "test",
        .nonce = 1,
        .timestamp = 1000000,
        .sender_public_key = public_key,
        .sender_cert = std.mem.zeroes([64]u8),
        .cert_serial = 0,
        .cert_issued_at = 0,
        .cert_expires_at = std.math.maxInt(u64),
        .network_id = 1,
        .signature = std.mem.zeroes(Signature),
    };

    const current_time: u64 = 1000000;

    // Valid: timestamp == current_time
    try testing.expect(base_tx.isTimestampValid(current_time));

    // Valid: timestamp slightly in past
    var past_tx = base_tx;
    past_tx.timestamp = current_time - 100;
    try testing.expect(past_tx.isTimestampValid(current_time));

    // Invalid: timestamp too far in past (>1 hour)
    var old_tx = base_tx;
    old_tx.timestamp = current_time - TX_PAST_TOLERANCE_SECS - 1;
    try testing.expect(!old_tx.isTimestampValid(current_time));

    // Valid: timestamp slightly in future (within 5 min)
    var future_tx = base_tx;
    future_tx.timestamp = current_time + TX_FUTURE_TOLERANCE_SECS - 1;
    try testing.expect(future_tx.isTimestampValid(current_time));

    // Invalid: timestamp too far in future (>5 min)
    var far_future_tx = base_tx;
    far_future_tx.timestamp = current_time + TX_FUTURE_TOLERANCE_SECS + 1;
    try testing.expect(!far_future_tx.isTimestampValid(current_time));
}

test "block validation" {
    const alice_public_key = std.mem.zeroes([32]u8);
    const alice_addr = util.hash(&alice_public_key);
    var bob_addr = std.mem.zeroes(Address);
    bob_addr[0] = 1;

    const tx = Transaction{
        .type = .invoke,
        .sender = alice_addr,
        .recipient = bob_addr,
        .payload = "",
        .nonce = 1,
        .timestamp = 1704067200,
        .sender_public_key = alice_public_key,
        .sender_cert = std.mem.zeroes([64]u8),
        .cert_serial = 0,
        .cert_issued_at = 0,
        .cert_expires_at = std.math.maxInt(u64),
        .network_id = 1,
        .signature = std.mem.zeroes(Signature),
    };

    var transactions = [_]Transaction{tx};

    const block = Block{
        .header = BlockHeader{
            .protocol_version = SUPPORTED_PROTOCOL_VERSION,
            .previous_hash = std.mem.zeroes(BlockHash),
            .merkle_root = std.mem.zeroes(Hash),
            .timestamp = 1704067200,
            .validator_public_key = std.mem.zeroes([32]u8),
            .validator_cert = std.mem.zeroes([64]u8),
            .validator_cert_serial = 0,
            .validator_cert_issued_at = 0,
            .validator_cert_expires_at = std.math.maxInt(u64),
            .signature = std.mem.zeroes(Signature),
        },
        .transactions = &transactions,
    };

    try testing.expect(block.isValid());
    try testing.expectEqual(@as(u32, 1), block.txCount());
}

test "transaction hash" {
    // Create test public key and address
    const public_key = std.mem.zeroes([32]u8);
    const sender_addr = util.hash(&public_key);

    // Create test transaction
    const tx1 = Transaction{
        .type = .invoke,
        .sender = sender_addr,
        .recipient = [_]u8{1} ++ std.mem.zeroes([31]u8),
        .payload = "payload",
        .nonce = 0,
        .timestamp = 1234567890,
        .sender_public_key = public_key,
        .sender_cert = std.mem.zeroes([64]u8),
        .cert_serial = 0,
        .cert_issued_at = 0,
        .cert_expires_at = std.math.maxInt(u64),
        .network_id = 1,
        .signature = std.mem.zeroes(Signature),
    };

    // Create identical transaction
    const tx2 = Transaction{
        .type = .invoke,
        .sender = sender_addr,
        .recipient = [_]u8{1} ++ std.mem.zeroes([31]u8),
        .payload = "payload",
        .nonce = 0,
        .timestamp = 1234567890,
        .sender_public_key = public_key,
        .sender_cert = std.mem.zeroes([64]u8),
        .cert_serial = 0,
        .cert_issued_at = 0,
        .cert_expires_at = std.math.maxInt(u64),
        .network_id = 1,
        .signature = std.mem.zeroes(Signature),
    };

    // Identical transactions should have same hash
    const hash1 = tx1.hash();
    const hash2 = tx2.hash();
    try testing.expectEqualSlices(u8, &hash1, &hash2);

    // Different transactions should have different hashes
    const tx3 = Transaction{
        .type = .invoke,
        .sender = sender_addr,
        .recipient = [_]u8{1} ++ std.mem.zeroes([31]u8),
        .payload = "different_payload",
        .nonce = 0,
        .timestamp = 1234567890,
        .sender_public_key = public_key,
        .sender_cert = std.mem.zeroes([64]u8),
        .cert_serial = 0,
        .cert_issued_at = 0,
        .cert_expires_at = std.math.maxInt(u64),
        .network_id = 1,
        .signature = std.mem.zeroes(Signature),
    };

    const hash3 = tx3.hash();
    try testing.expect(!std.mem.eql(u8, &hash1, &hash3));
}

test "block header hash consistency" {
    // Create test block header
    const header1 = BlockHeader{
        .protocol_version = SUPPORTED_PROTOCOL_VERSION,
        .previous_hash = std.mem.zeroes(Hash),
        .merkle_root = [_]u8{1} ++ std.mem.zeroes([31]u8),
        .timestamp = 1704067200,
        .validator_public_key = std.mem.zeroes([32]u8),
        .validator_cert = std.mem.zeroes([64]u8),
        .validator_cert_serial = 0,
        .validator_cert_issued_at = 0,
        .validator_cert_expires_at = std.math.maxInt(u64),
        .signature = std.mem.zeroes(Signature),
    };

    // Create identical header
    const header2 = BlockHeader{
        .protocol_version = SUPPORTED_PROTOCOL_VERSION,
        .previous_hash = std.mem.zeroes(Hash),
        .merkle_root = [_]u8{1} ++ std.mem.zeroes([31]u8),
        .timestamp = 1704067200,
        .validator_public_key = std.mem.zeroes([32]u8),
        .validator_cert = std.mem.zeroes([64]u8),
        .validator_cert_serial = 0,
        .validator_cert_issued_at = 0,
        .validator_cert_expires_at = std.math.maxInt(u64),
        .signature = std.mem.zeroes(Signature),
    };

    // Identical headers should have same hash
    const hash1 = header1.hash();
    const hash2 = header2.hash();
    try testing.expectEqualSlices(u8, &hash1, &hash2);

    // Hash should not be all zeros
    const zero_hash = std.mem.zeroes(Hash);
    try testing.expect(!std.mem.eql(u8, &hash1, &zero_hash));
}

test "block header hash uniqueness" {
    const base_header = BlockHeader{
        .protocol_version = SUPPORTED_PROTOCOL_VERSION,
        .previous_hash = std.mem.zeroes(Hash),
        .merkle_root = std.mem.zeroes(Hash),
        .timestamp = 1704067200,
        .validator_public_key = std.mem.zeroes([32]u8),
        .validator_cert = std.mem.zeroes([64]u8),
        .validator_cert_serial = 0,
        .validator_cert_issued_at = 0,
        .validator_cert_expires_at = std.math.maxInt(u64),
        .signature = std.mem.zeroes(Signature),
    };

    // Different timestamp should produce different hash
    var header_time1 = base_header;
    header_time1.timestamp = 1704067200;
    var header_time2 = base_header;
    header_time2.timestamp = 1704067300;

    const hash_time1 = header_time1.hash();
    const hash_time2 = header_time2.hash();
    try testing.expect(!std.mem.eql(u8, &hash_time1, &hash_time2));
}

test "block hash delegated to header hash" {
    const alice_public_key = std.mem.zeroes([32]u8);
    const alice_addr = util.hash(&alice_public_key);
    var bob_addr = std.mem.zeroes(Address);
    bob_addr[0] = 1;

    const tx = Transaction{
        .type = .invoke,
        .sender = alice_addr,
        .recipient = bob_addr,
        .payload = "",
        .nonce = 1,
        .timestamp = 1704067200,
        .sender_public_key = alice_public_key,
        .sender_cert = std.mem.zeroes([64]u8),
        .cert_serial = 0,
        .cert_issued_at = 0,
        .cert_expires_at = std.math.maxInt(u64),
        .network_id = 1,
        .signature = std.mem.zeroes(Signature),
    };

    var transactions = [_]Transaction{tx};

    const block = Block{
        .header = BlockHeader{
            .protocol_version = SUPPORTED_PROTOCOL_VERSION,
            .previous_hash = std.mem.zeroes(BlockHash),
            .merkle_root = std.mem.zeroes(Hash),
            .timestamp = 1704067200,
            .validator_public_key = std.mem.zeroes([32]u8),
            .validator_cert = std.mem.zeroes([64]u8),
            .validator_cert_serial = 0,
            .validator_cert_issued_at = 0,
            .validator_cert_expires_at = std.math.maxInt(u64),
            .signature = std.mem.zeroes(Signature),
        },
        .transactions = &transactions,
    };

    // Block hash should equal header hash
    const block_hash = block.hash();
    const header_hash = block.header.hash();
    try testing.expectEqualSlices(u8, &block_hash, &header_hash);
}

test "transaction network isolation" {
    const public_key = std.mem.zeroes([32]u8);
    const sender_addr = util.hash(&public_key);

    var tx1 = Transaction{
        .type = .invoke,
        .sender = sender_addr,
        .recipient = [_]u8{1} ++ std.mem.zeroes([31]u8),
        .payload = "payload",
        .nonce = 1,
        .timestamp = 1704067200,
        .sender_public_key = public_key,
        .sender_cert = std.mem.zeroes([64]u8),
        .cert_serial = 0,
        .cert_issued_at = 0,
        .cert_expires_at = std.math.maxInt(u64),
        .network_id = 1,
        .signature = std.mem.zeroes(Signature),
    };

    var tx2 = tx1;
    tx2.network_id = 2;

    const hash1 = tx1.hash();
    const hash2 = tx2.hash();
    try testing.expect(!std.mem.eql(u8, &hash1, &hash2));
}

test "network_id u64 full range support" {
    const public_key = std.mem.zeroes([32]u8);
    const sender_addr = util.hash(&public_key);

    var tx1 = Transaction{
        .type = .invoke,
        .sender = sender_addr,
        .recipient = [_]u8{1} ++ std.mem.zeroes([31]u8),
        .payload = "payload",
        .nonce = 1,
        .timestamp = 1704067200,
        .sender_public_key = public_key,
        .sender_cert = std.mem.zeroes([64]u8),
        .cert_serial = 0,
        .cert_issued_at = 0,
        .cert_expires_at = std.math.maxInt(u64),
        .network_id = 0xFFFFFFFF00000001,
        .signature = std.mem.zeroes(Signature),
    };

    var tx2 = tx1;
    tx2.network_id = 0xFFFFFFFF00000002;

    const hash1 = tx1.hash();
    const hash2 = tx2.hash();
    try testing.expect(!std.mem.eql(u8, &hash1, &hash2));

    var tx3 = tx1;
    tx3.network_id = 1;
    var tx4 = tx1;
    tx4.network_id = 2;

    const hash3 = tx3.hash();
    const hash4 = tx4.hash();
    try testing.expect(!std.mem.eql(u8, &hash3, &hash4));
}
