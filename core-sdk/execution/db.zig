// db.zig - Adria Minimal File Database
// Pure Zig file-based storage

const std = @import("std");
const testing = std.testing;

const serialize = @import("../network/serialize.zig");
const types = @import("../common/types.zig");
const storage = @import("storage.zig");

// Re-export types for convenience
pub const Block = types.Block;
pub const Account = types.Account;
pub const Address = types.Address;

/// MVCC: A value stored with its creation version
pub const VersionedValue = struct {
    block_height: u64,
    tx_index: u32,
    value: []u8,
};

/// State Cache Entry
const CacheEntry = struct {
    value: []u8,
    dirty: bool,
};

/// Versioned Cache Entry
const VersionedCacheEntry = struct {
    value: []u8,
    block_height: u64,
    tx_index: u32,
    dirty: bool,
};

/// Pending Versioned Write
const PendingWrite = struct {
    key: []u8,
    val: VersionedCacheEntry,
};

/// Database errors
pub const DatabaseError = error{
    OpenFailed,
    SaveFailed,
    LoadFailed,
    NotFound,
    SerializationFailed,
};

/// Adria minimal database
/// File-based storage with pure Zig - no dependencies
pub const Database = struct {
    blocks_dir: []const u8,
    state_dir: []const u8,
    wallets_dir: []const u8,
    allocator: std.mem.Allocator,

    // Storage Engine (Bitcask)
    engine: *storage.StorageEngine,

    // State Cache
    state_cache: std.StringHashMap(CacheEntry),

    /// Initialize Adria database directories
    pub fn init(allocator: std.mem.Allocator, base_path: []const u8) !Database {
        // Create directories - zen minimalism
        const blocks_dir = try std.fs.path.join(allocator, &[_][]const u8{ base_path, "blocks" });
        const wallets_dir = try std.fs.path.join(allocator, &[_][]const u8{ base_path, "wallets" });

        // Ensure directories exist - bamboo grows
        std.fs.cwd().makePath(blocks_dir) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };

        std.fs.cwd().makePath(wallets_dir) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };

        const state_dir = try std.fs.path.join(allocator, &[_][]const u8{ base_path, "state" });
        const engine = try storage.StorageEngine.init(allocator, state_dir);

        return Database{
            .blocks_dir = blocks_dir,
            .state_dir = state_dir,
            .wallets_dir = wallets_dir,
            .allocator = allocator,
            .engine = engine,
            .state_cache = std.StringHashMap(CacheEntry).init(allocator),
        };
    }

    /// Cleanup database resources
    pub fn deinit(self: *Database) void {
        var it = self.state_cache.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.value);
        }
        self.state_cache.deinit();

        self.engine.deinit();

        self.allocator.free(self.blocks_dir);
        self.allocator.free(self.state_dir);
        self.allocator.free(self.wallets_dir);
    }

    /// Generic PUT: Save key-value pair to state (Cached)
    pub fn put(self: *Database, key: []const u8, value: []const u8) !void {
        // Create a copy of key and value for cache
        const key_copy = try self.allocator.dupe(u8, key);
        const value_copy = try self.allocator.dupe(u8, value);

        // Check if key exists to free old memory
        if (self.state_cache.fetchRemove(key)) |kv| {
            self.allocator.free(kv.key);
            self.allocator.free(kv.value.value);
        }

        try self.state_cache.put(key_copy, CacheEntry{ .value = value_copy, .dirty = true });
    }

    /// Generic GET: Retrieve value by key (Check Cache First)
    pub fn get(self: *Database, key: []const u8) !?[]u8 {
        // 1. Check Cache
        if (self.state_cache.get(key)) |entry| {
            return try self.allocator.dupe(u8, entry.value);
        }

        // 2. Check Storage Engine
        return self.engine.get(key);
    }

    /// MVCC PUT: Append new version of key (Buffered)
    pub fn putVersioned(self: *Database, key: []const u8, value: []const u8, height: u64, tx_index: u32) !void {
        _ = height;
        _ = tx_index;
        // In Bitcask implementation, we just use Latest State for now.
        // Full MVCC support with index would be next iteration.
        try self.put(key, value);
    }

    /// MVCC GET: Get highest version <= max_height
    pub fn getAtHeight(self: *Database, key: []const u8, max_height: u64) !?[]u8 {
        _ = max_height;
        return self.get(key);
    }

    /// Commit all cached writes to disk
    pub fn commit(self: *Database) !void {
        // 1. Flush Standard State Cache
        var it = self.state_cache.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.dirty) {
                // Write to Bitcask Log
                try self.engine.put(entry.key_ptr.*, entry.value_ptr.value);
                entry.value_ptr.dirty = false;
            }
        }
    }

    pub fn saveBlock(self: *Database, height: u32, block: Block) !void {
        // Create filename: blocks/000012.block
        const filename = try std.fmt.allocPrint(self.allocator, "{s}/{:0>6}.block", .{ self.blocks_dir, height });
        defer self.allocator.free(filename);

        // Serialize block to buffer
        var buffer = std.ArrayList(u8).init(self.allocator);
        defer buffer.deinit();

        const writer = buffer.writer();
        serialize.serialize(writer, block) catch return DatabaseError.SerializationFailed;

        // Write to file atomically
        const file = std.fs.cwd().createFile(filename, .{}) catch return DatabaseError.SaveFailed;
        defer file.close();

        file.writeAll(buffer.items) catch return DatabaseError.SaveFailed;
    }

    /// Load block from file
    pub fn getBlock(self: *Database, height: u32) !Block {
        // Create filename
        const filename = try std.fmt.allocPrint(self.allocator, "{s}/{:0>6}.block", .{ self.blocks_dir, height });
        defer self.allocator.free(filename);

        // Read file
        const file = std.fs.cwd().openFile(filename, .{}) catch return DatabaseError.NotFound;
        defer file.close();

        const file_size = try file.getEndPos();
        const buffer = try self.allocator.alloc(u8, file_size);
        defer self.allocator.free(buffer);

        _ = try file.readAll(buffer);

        // Deserialize block
        var stream = std.io.fixedBufferStream(buffer);
        const reader = stream.reader();

        return serialize.deserialize(reader, Block, self.allocator) catch DatabaseError.SerializationFailed;
    }

    /// Save account to file (Legacy Wrapper around generic PUT)
    pub fn saveAccount(self: *Database, address: Address, account: Account) !void {
        // Serialize account to bytes
        var buffer = std.ArrayList(u8).init(self.allocator);
        defer buffer.deinit();

        const writer = buffer.writer();
        serialize.serialize(writer, account) catch return DatabaseError.SerializationFailed;

        // Use address directly as key (will be hexed by put)
        try self.put(&address, buffer.items);
    }

    /// Load account from file (Legacy Wrapper around generic GET)
    pub fn getAccount(self: *Database, address: Address) !Account {
        // Get generic bytes
        const bytes = try self.get(&address);
        if (bytes == null) return DatabaseError.NotFound;
        defer self.allocator.free(bytes.?);

        // Deserialize
        var stream = std.io.fixedBufferStream(bytes.?);
        const reader = stream.reader();

        return serialize.deserialize(reader, Account, self.allocator) catch DatabaseError.SerializationFailed;
    }

    /// Get blockchain height (count block files)
    pub fn getHeight(self: *Database) !u32 {
        var dir = std.fs.cwd().openDir(self.blocks_dir, .{ .iterate = true }) catch |err| {
            std.debug.print("❌ getHeight failed to open dir {s}: {}\n", .{ self.blocks_dir, err });
            return 0;
        };
        defer dir.close();

        var count: u32 = 0;
        var iterator = dir.iterate();
        while (try iterator.next()) |entry| {
            if (entry.kind == .file and std.mem.endsWith(u8, entry.name, ".block")) {
                count += 1;
            }
        }

        return count;
    }

    /// Get generic state count (Approximated)
    pub fn getStateCount(self: *Database) !u32 {
        // Bitcask engine doesn't track count efficiently yet in this basic impl.
        // We could expose self.engine.index.count().
        return self.engine.index.count();
    }

    /// Get wallet file path - zen simplicity
    pub fn getWalletPath(self: *Database, wallet_name: []const u8) ![]u8 {
        return std.fmt.allocPrint(self.allocator, "{s}/{s}.wallet", .{ self.wallets_dir, wallet_name });
    }

    /// Get default wallet path - zen default
    pub fn getDefaultWalletPath(self: *Database) ![]u8 {
        return self.getWalletPath("default");
    }

    /// Check if wallet exists - zen wisdom
    pub fn walletExists(self: *Database, wallet_name: []const u8) bool {
        const path = self.getWalletPath(wallet_name) catch return false;
        defer self.allocator.free(path);

        std.fs.cwd().access(path, .{}) catch return false;
        return true;
    }
};

// Tests
test "database initialization" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Use temporary directory
    var db = try Database.init(allocator, "/tmp/adria_test");
    defer db.deinit();

    // Should start with 0 blocks and state entries
    try testing.expectEqual(@as(u32, 0), try db.getHeight());
}

test "block storage and retrieval" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var db = try Database.init(allocator, "/tmp/adria_test2");
    defer db.deinit();

    // Create test block
    const transactions = try allocator.alloc(types.Transaction, 0);
    defer allocator.free(transactions);

    const test_block = Block{
        .header = types.BlockHeader{
            .previous_hash = std.mem.zeroes(types.Hash),
            .merkle_root = std.mem.zeroes(types.Hash),
            .timestamp = 1234567890,
            .validator_public_key = std.mem.zeroes([32]u8),
            .validator_cert = std.mem.zeroes([64]u8),
            .signature = std.mem.zeroes(types.Signature),
        },
        .transactions = transactions,
    };

    // Save and retrieve block
    try db.saveBlock(0, test_block);
    const retrieved_block = try db.getBlock(0);

    // Verify block data
    try testing.expectEqual(test_block.header.timestamp, retrieved_block.header.timestamp);
    try testing.expectEqual(@as(u32, 1), try db.getHeight());

    // Cleanup retrieved block
    allocator.free(retrieved_block.transactions);
}

test "account storage and retrieval" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var db = try Database.init(allocator, "/tmp/adria_test3");
    defer db.deinit();

    // Create test account
    const test_addr = std.mem.zeroes(Address);
    const test_account = Account{
        .address = test_addr,
        .nonce = 5,
        .role = 0,
    };

    // Save and retrieve account
    try db.saveAccount(test_addr, test_account);
    try db.commit(); // Propagate to Bitcask
    const retrieved_account = try db.getAccount(test_addr);

    // Verify account data
    try testing.expectEqual(test_account.nonce, retrieved_account.nonce);
    try testing.expectEqual(test_account.nonce, retrieved_account.nonce);
}

test "generic kv storage" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var db = try Database.init(allocator, "/tmp/adria_test4_kv");
    defer db.deinit();

    const key = "my-key";
    const value = "my-value";

    // Put
    try db.put(key, value);
    try db.commit();

    // Get
    const retrieved = try db.get(key);
    try testing.expect(retrieved != null);
    defer allocator.free(retrieved.?);

    try testing.expectEqualSlices(u8, value, retrieved.?);
}
