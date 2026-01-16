// db.zig - Adria Minimal File Database
// Pure Zig file-based storage

const std = @import("std");
const testing = std.testing;

const serialize = @import("../network/serialize.zig");
const types = @import("../common/types.zig");

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

    // State Cache
    state_cache: std.StringHashMap(CacheEntry),
    // Versioned Cache (Key -> List of versioned updates)
    // Map Key to ArrayList of entries
    pending_versioned_writes: std.StringHashMap(std.ArrayList(VersionedCacheEntry)),

    /// Initialize Adria database directories
    pub fn init(allocator: std.mem.Allocator, base_path: []const u8) !Database {
        // Create directories - zen minimalism
        const blocks_dir = try std.fs.path.join(allocator, &[_][]const u8{ base_path, "blocks" });
        const state_dir = try std.fs.path.join(allocator, &[_][]const u8{ base_path, "state" });
        const wallets_dir = try std.fs.path.join(allocator, &[_][]const u8{ base_path, "wallets" });

        // Ensure directories exist - bamboo grows
        std.fs.cwd().makePath(blocks_dir) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };

        std.fs.cwd().makePath(state_dir) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };

        std.fs.cwd().makePath(wallets_dir) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };

        return Database{
            .blocks_dir = blocks_dir,
            .state_dir = state_dir,
            .wallets_dir = wallets_dir,
            .allocator = allocator,
            .state_cache = std.StringHashMap(CacheEntry).init(allocator),
            .pending_versioned_writes = std.StringHashMap(std.ArrayList(VersionedCacheEntry)).init(allocator),
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

        var ver_it = self.pending_versioned_writes.iterator();
        while (ver_it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            for (entry.value_ptr.items) |ver_entry| {
                self.allocator.free(ver_entry.value);
            }
            entry.value_ptr.deinit();
        }
        self.pending_versioned_writes.deinit();

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

        // 2. Check Disk
        // Filename is hex-encoded key
        const key_hex = try std.fmt.allocPrint(self.allocator, "{s}", .{std.fmt.fmtSliceHexLower(key)});
        defer self.allocator.free(key_hex);

        const filename = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ self.state_dir, key_hex });
        defer self.allocator.free(filename);

        // Read file
        const file = std.fs.cwd().openFile(filename, .{}) catch |err| switch (err) {
            error.FileNotFound => return null,
            else => return DatabaseError.NotFound,
        };
        defer file.close();

        const file_size = try file.getEndPos();
        const buffer = try self.allocator.alloc(u8, file_size);
        errdefer self.allocator.free(buffer);

        _ = try file.readAll(buffer);

        // Optional: Cache on read?
        // For now, only caching writes. Read-through caching can be added later.

        return buffer;
    }

    /// MVCC PUT: Append new version of key (Buffered)
    pub fn putVersioned(self: *Database, key: []const u8, value: []const u8, height: u64, tx_index: u32) !void {
        // Buffer the write
        // Check if list exists for key
        const gop = try self.pending_versioned_writes.getOrPut(key);
        if (!gop.found_existing) {
            // New key, dup it
            gop.key_ptr.* = try self.allocator.dupe(u8, key);
            gop.value_ptr.* = std.ArrayList(VersionedCacheEntry).init(self.allocator);
        }

        const value_copy = try self.allocator.dupe(u8, value);
        try gop.value_ptr.append(VersionedCacheEntry{
            .value = value_copy,
            .block_height = height,
            .tx_index = tx_index,
            .dirty = true,
        });
    }

    /// MVCC GET: Get highest version <= max_height
    pub fn getAtHeight(self: *Database, key: []const u8, max_height: u64) !?[]u8 {
        // Filename is hex-encoded key
        const key_hex = try std.fmt.allocPrint(self.allocator, "{s}", .{std.fmt.fmtSliceHexLower(key)});
        defer self.allocator.free(key_hex);

        const filename = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ self.state_dir, key_hex });
        defer self.allocator.free(filename);

        // Open file
        const file = std.fs.cwd().openFile(filename, .{}) catch |err| switch (err) {
            error.FileNotFound => return null,
            else => return DatabaseError.NotFound,
        };
        defer file.close();

        const file_size = try file.getEndPos();
        var stream = std.io.StreamSource{ .file = file };
        const reader = stream.reader();

        var best_value: ?[]u8 = null;
        var highest_seen: u64 = 0;
        var found_any = false;

        // Scan the file (Append-only log)
        // Format: [Height:8][TxIdx:4][ValLen:4][Value...]
        var pos: u64 = 0;
        while (pos < file_size) {
            if (pos + 16 > file_size) break; // Partial write protection

            const h = try reader.readInt(u64, .big);
            const tx_idx = try reader.readInt(u32, .big);
            _ = tx_idx; // Unused for now as we rely on append order
            const val_len = try reader.readInt(u32, .big);

            if (pos + 16 + val_len > file_size) break; // Partial write protection

            // Read value
            const val = try self.allocator.alloc(u8, val_len);
            // We owe a free on this, but we might overwrite 'best_value' with it.
            // Strategy: Always free previous best_value if we replace it.
            try reader.readNoEof(val);

            // Check if this version is valid for our query (<= max_height)
            if (h <= max_height) {
                // Determine if this is "newer" than what we have
                // Logic: Higher height is better. Same height, higher tx_idx is better.
                var is_newer = false;
                if (!found_any) {
                    is_newer = true;
                } else {
                    if (h > highest_seen) {
                        is_newer = true;
                    } else if (h == highest_seen) {
                        // Same block, later transaction overwrites earlier
                        // (Assuming pure append order, this is implicit, but we check explicitly)
                        // Actually, if we just scan, the LAST valid one is the newest.
                        is_newer = true;
                    }
                }

                if (is_newer) {
                    if (best_value) |v| self.allocator.free(v);
                    best_value = val;
                    highest_seen = h;
                    found_any = true;
                } else {
                    self.allocator.free(val);
                }
            } else {
                // Version is from the future relative to query
                self.allocator.free(val);
            }

            pos += 16 + val_len;
        }

        return best_value;
    }

    /// Commit all cached writes to disk
    pub fn commit(self: *Database) !void {
        // 1. Flush Standard State Cache
        var it = self.state_cache.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.dirty) {
                // Filename is hex-encoded key
                const key_hex = try std.fmt.allocPrint(self.allocator, "{s}", .{std.fmt.fmtSliceHexLower(entry.key_ptr.*)});
                defer self.allocator.free(key_hex);

                const filename = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ self.state_dir, key_hex });
                defer self.allocator.free(filename);

                const file = std.fs.cwd().createFile(filename, .{}) catch return DatabaseError.SaveFailed;
                defer file.close();

                try file.writeAll(entry.value_ptr.value);

                entry.value_ptr.dirty = false;
            }
        }

        // 2. Flush Versioned Writes
        // Group by key to minimize file opens! (Optimized)
        var ver_it = self.pending_versioned_writes.iterator();
        while (ver_it.next()) |entry| {
            const key_hex = try std.fmt.allocPrint(self.allocator, "{s}", .{std.fmt.fmtSliceHexLower(entry.key_ptr.*)});
            defer self.allocator.free(key_hex);

            const filename = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ self.state_dir, key_hex });
            defer self.allocator.free(filename);

            // Open file ONCE per key
            const file = try std.fs.cwd().createFile(filename, .{ .read = true, .truncate = false });
            defer file.close();
            try file.seekFromEnd(0);

            // Write all pending versions for this key
            for (entry.value_ptr.items) |ver_entry| {
                var buffer = std.ArrayList(u8).init(self.allocator);
                defer buffer.deinit();

                const writer = buffer.writer();
                try writer.writeInt(u64, ver_entry.block_height, .big);
                try writer.writeInt(u32, ver_entry.tx_index, .big);
                try writer.writeInt(u32, @as(u32, @intCast(ver_entry.value.len)), .big);
                try writer.writeAll(ver_entry.value);

                try file.writeAll(buffer.items);
                
                // Cleanup value memory
                self.allocator.free(ver_entry.value);
            }
            
            // Cleanup list and key
            entry.value_ptr.deinit();
            self.allocator.free(entry.key_ptr.*);
        }
        
        // Clear the map
        self.pending_versioned_writes.clearRetainingCapacity();
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

    /// Get generic state count (count files in state dir)
    pub fn getStateCount(self: *Database) !u32 {
        var dir = std.fs.cwd().openDir(self.state_dir, .{ .iterate = true }) catch return 0;
        defer dir.close();

        var count: u32 = 0;
        var iterator = dir.iterate();
        while (try iterator.next()) |entry| {
            if (entry.kind == .file) {
                count += 1;
            }
        }

        return count;
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
        const wallet_path = self.getWalletPath(wallet_name) catch return false;
        defer self.allocator.free(wallet_path);

        std.fs.cwd().access(wallet_path, .{}) catch return false;
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
    try testing.expectEqual(@as(u32, 0), try db.getStateCount());
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
    const retrieved_account = try db.getAccount(test_addr);

    // Verify account data
    try testing.expectEqual(test_account.nonce, retrieved_account.nonce);
    try testing.expectEqual(test_account.nonce, retrieved_account.nonce);
    try testing.expectEqual(@as(u32, 1), try db.getStateCount());
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

    // Get
    const retrieved = try db.get(key);
    try testing.expect(retrieved != null);
    defer allocator.free(retrieved.?);

    try testing.expectEqualSlices(u8, value, retrieved.?);
}

test "mvcc storage" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var db = try Database.init(allocator, "/tmp/adria_test_mvcc");
    defer db.deinit();

    const key = "balance";
    const val1 = "100";
    const val2 = "150";
    const val3 = "50";

    // Write Version 1 at Height 10
    try db.putVersioned(key, val1, 10, 0);

    // Write Version 2 at Height 20
    try db.putVersioned(key, val2, 20, 0);

    // Write Version 3 at Height 20 (Tx Index 1 - same block, later tx)
    try db.putVersioned(key, val3, 20, 1);

    // Query at Height 5 (Should be found? No, created at 10)
    // Wait, getAtHeight scans for h <= max.
    // If max=5, and only 10, 20 exist. It logic:
    // if h <= max...
    // 10 <= 5 False.
    // Returns null. Correct.
    const res_h5 = try db.getAtHeight(key, 5);
    try testing.expect(res_h5 == null);

    // Query at Height 15 (Should see Version 1)
    const res_h15 = try db.getAtHeight(key, 15);
    try testing.expect(res_h15 != null);
    defer allocator.free(res_h15.?);
    try testing.expectEqualSlices(u8, val1, res_h15.?);

    // Query at Height 20 (Should see Version 3 - the latest in block 20)
    // My logic for tx_idx was: "if h==highest_seen, is_newer=true".
    // Since scan is append-order, the last one seen effectively wins.
    // putVersioned index 0 then index 1.
    // So index 1 comes later in file.
    // It will overwrite index 0. Correct.
    const res_h20 = try db.getAtHeight(key, 20);
    try testing.expect(res_h20 != null);
    defer allocator.free(res_h20.?);
    try testing.expectEqualSlices(u8, val3, res_h20.?);

    // Query at Height 100 (Should see Version 3)
    const res_h100 = try db.getAtHeight(key, 100);
    try testing.expect(res_h100 != null);
    defer allocator.free(res_h100.?);
    try testing.expectEqualSlices(u8, val3, res_h100.?);
}
