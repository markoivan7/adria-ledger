// chaincode.zig - Smart Contract Interface & System Chaincodes
// Defines how logic interacts with the ledger (Execute-Order-Validate paradigm foundation)

const std = @import("std");
const db = @import("db.zig");

/// Stub provides API for Chaincode to interact with the Ledger
pub const Stub = struct {
    database: *db.Database,
    allocator: std.mem.Allocator,
    write_set: std.StringHashMap([]const u8),

    pub fn init(allocator: std.mem.Allocator, database: *db.Database) Stub {
        return Stub{
            .database = database,
            .allocator = allocator,
            .write_set = std.StringHashMap([]const u8).init(allocator),
        };
    }

    pub fn deinit(self: *Stub) void {
        var it = self.write_set.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.write_set.deinit();
    }

    /// Put state (Key -> Value) - Buffers to Write Set
    pub fn putState(self: *Stub, key: []const u8, value: []const u8) !void {
        // We must dupe strings because they might be freed by caller or logic
        const key_dupe = try self.allocator.dupe(u8, key);
        const val_dupe = try self.allocator.dupe(u8, value);

        // If we overwrite a key in the same tx, free the old valid/key
        if (self.write_set.fetchRemove(key)) |kv| {
            self.allocator.free(kv.key);
            self.allocator.free(kv.value);
        }

        try self.write_set.put(key_dupe, val_dupe);
    }

    /// Get state (Key -> Value) - Checks Write Set then DB
    pub fn getState(self: *Stub, key: []const u8) !?[]u8 {
        // Check local write set first (Read-Your-Writes)
        if (self.write_set.get(key)) |val| {
            return try self.allocator.dupe(u8, val);
        }
        // Read latest committed version (MVCC)
        return self.database.getAtHeight(key, std.math.maxInt(u64));
    }

    /// Format composite key (helper)
    pub fn createCompositeKey(self: *Stub, object_type: []const u8, attributes: []const []const u8) ![]u8 {
        // Simple composite key: "type:attr1:attr2"
        var list = std.ArrayList(u8).init(self.allocator);
        defer list.deinit();

        try list.appendSlice(object_type);
        for (attributes) |attr| {
            try list.append(':');
            try list.appendSlice(attr);
        }
        return list.toOwnedSlice();
    }
};

/// Common interface for all Chaincodes
pub const ChaincodeError = error{
    InvalidFunction,
    InvalidArguments,
    InternalError,
    NotFound,
};

/// System Chaincode: General Ledger
/// Allows storing arbitrary JSON data (Journal Entries)
pub const GeneralLedger = struct {
    pub const ID = "general_ledger";

    /// Invoke function: router for chaincode methods
    pub fn invoke(stub: *Stub, function: []const u8, args: [][]const u8) ![]u8 {
        if (std.mem.eql(u8, function, "record_entry")) {
            return recordEntry(stub, args);
        } else if (std.mem.eql(u8, function, "get_entry")) {
            return getEntry(stub, args);
        } else {
            return ChaincodeError.InvalidFunction;
        }
    }

    /// Record a journal entry
    /// Args: [key, value]
    fn recordEntry(stub: *Stub, args: [][]const u8) ![]u8 {
        if (args.len != 2) return ChaincodeError.InvalidArguments;
        const key = args[0];
        const value = args[1];

        // Store directly
        try stub.putState(key, value);

        return stub.allocator.dupe(u8, "OK");
    }

    /// Get a journal entry
    /// Args: [key]
    fn getEntry(stub: *Stub, args: [][]const u8) ![]u8 {
        if (args.len != 1) return ChaincodeError.InvalidArguments;
        const key = args[0];

        const value = try stub.getState(key);
        if (value) |v| {
            defer stub.allocator.free(v);
            return stub.allocator.dupe(u8, v);
        } else {
            return ChaincodeError.NotFound;
        }
    }
};

/// System Chaincode: Asset Ledger (Phase 6)
/// Manages ownership of unique assets
pub const AssetLedger = struct {
    pub const ID = "asset_ledger";

    const Asset = struct {
        owner: []const u8, // Hex address
        meta: []const u8, // Metadata
    };

    /// Invoke router
    pub fn invoke(stub: *Stub, function: []const u8, args: [][]const u8, sender: []const u8) ![]u8 {
        if (std.mem.eql(u8, function, "mint")) {
            return mint(stub, args);
        } else if (std.mem.eql(u8, function, "transfer")) {
            return transfer(stub, args, sender);
        } else if (std.mem.eql(u8, function, "query")) {
            return query(stub, args);
        } else {
            return ChaincodeError.InvalidFunction;
        }
    }

    /// Mint a new asset
    /// Args: [id, owner, meta]
    fn mint(stub: *Stub, args: [][]const u8) ![]u8 {
        if (args.len != 3) return ChaincodeError.InvalidArguments;
        const id = args[0];
        const owner = args[1];
        const meta = args[2];

        // Key: "ASSET_<ID>"
        const key = try std.fmt.allocPrint(stub.allocator, "ASSET_{s}", .{id});
        defer stub.allocator.free(key);

        // Check exist
        const existing = try stub.getState(key);
        if (existing != null) {
            stub.allocator.free(existing.?);
            return ChaincodeError.InternalError; // Already exists
        }

        // Create JSON
        // Cheap JSON serialization for PoC
        const json = try std.fmt.allocPrint(stub.allocator, "{{\"owner\":\"{s}\",\"meta\":\"{s}\"}}", .{ owner, meta });
        defer stub.allocator.free(json);

        try stub.putState(key, json);
        return stub.allocator.dupe(u8, "OK");
    }

    /// Transfer asset
    /// Args: [id, new_owner]
    fn transfer(stub: *Stub, args: [][]const u8, sender: []const u8) ![]u8 {
        if (args.len != 2) return ChaincodeError.InvalidArguments;
        const id = args[0];
        const new_owner = args[1];

        const key = try std.fmt.allocPrint(stub.allocator, "ASSET_{s}", .{id});
        defer stub.allocator.free(key);

        // Get Asset
        const state = try stub.getState(key);
        if (state == null) return ChaincodeError.NotFound;
        defer stub.allocator.free(state.?);

        // Check Ownership (very naive string parsing for PoC)
        // Expected: {"owner":"<sender_hex>",...}
        const expected_prefix = try std.fmt.allocPrint(stub.allocator, "{{\"owner\":\"{s}\"", .{sender});
        defer stub.allocator.free(expected_prefix);

        if (!std.mem.startsWith(u8, state.?, expected_prefix)) {
            return error.PermissionDenied;
        }

        // Re-serialize with new owner
        const json = try std.fmt.allocPrint(stub.allocator, "{{\"owner\":\"{s}\",\"meta\":\"Transferred\"}}", .{new_owner});
        defer stub.allocator.free(json);

        try stub.putState(key, json);
        return stub.allocator.dupe(u8, "OK");
    }

    /// Query asset
    /// Args: [id]
    fn query(stub: *Stub, args: [][]const u8) ![]u8 {
        if (args.len != 1) return ChaincodeError.InvalidArguments;
        const id = args[0];

        const key = try std.fmt.allocPrint(stub.allocator, "ASSET_{s}", .{id});
        defer stub.allocator.free(key);

        const val = try stub.getState(key);
        if (val) |v| {
            defer stub.allocator.free(v);
            return stub.allocator.dupe(u8, v);
        }
        return ChaincodeError.NotFound;
    }
};

/// System Chaincode: Document Store (Phase 8)
/// Generic document storage with collections
pub const DocumentStore = struct {
    pub const ID = "document_store";

    /// Invoke router
    pub fn invoke(stub: *Stub, function: []const u8, args: [][]const u8) ![]u8 {
        if (std.mem.eql(u8, function, "store")) {
            return store(stub, args);
        } else if (std.mem.eql(u8, function, "retrieve")) {
            return retrieve(stub, args);
        } else {
            return ChaincodeError.InvalidFunction;
        }
    }

    /// Store a document
    /// Args: [collection, id, document_json]
    fn store(stub: *Stub, args: [][]const u8) ![]u8 {
        if (args.len != 3) return ChaincodeError.InvalidArguments;
        const collection = args[0];
        const id = args[1];
        const document = args[2];

        // Key: "DOC_{collection}_{id}"
        const key = try std.fmt.allocPrint(stub.allocator, "DOC_{s}_{s}", .{ collection, id });
        defer stub.allocator.free(key);

        try stub.putState(key, document);
        return stub.allocator.dupe(u8, "OK");
    }

    /// Retrieve a document
    /// Args: [collection, id]
    fn retrieve(stub: *Stub, args: [][]const u8) ![]u8 {
        if (args.len != 2) return ChaincodeError.InvalidArguments;
        const collection = args[0];
        const id = args[1];

        const key = try std.fmt.allocPrint(stub.allocator, "DOC_{s}_{s}", .{ collection, id });
        defer stub.allocator.free(key);

        const val = try stub.getState(key);
        if (val) |v| {
            defer stub.allocator.free(v);
            return stub.allocator.dupe(u8, v);
        }
        return ChaincodeError.NotFound;
    }
};

/// System Chaincode: Governance
pub const Governance = @import("system/governance.zig").GovernanceSystem;
