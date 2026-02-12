// storage.zig - Pure Zig Bitcask Engine (Append-Only Log)
// Implements a high-performance, single-file Key-Value store.
// Format: [CRC:4][TS:8][KSz:4][VSz:4][Key...][Value...]

const std = @import("std");

pub const StorageError = error{
    LogReadError,
    LogWriteError,
    ChecksumMismatch,
    IndexError,
};

/// The Bitcask-style storage engine
pub const StorageEngine = struct {
    allocator: std.mem.Allocator,
    index: std.StringHashMap(u64), // Key -> File Offset
    log_file: std.fs.File,
    current_offset: u64,
    data_dir: []const u8,

    /// Initialize the storage engine (Create/Open log + Rebuild Index)
    pub fn init(allocator: std.mem.Allocator, data_dir: []const u8) !*StorageEngine {
        const self = try allocator.create(StorageEngine);
        self.allocator = allocator;
        self.data_dir = try allocator.dupe(u8, data_dir);
        self.index = std.StringHashMap(u64).init(allocator);

        // Ensure directory exists
        try std.fs.cwd().makePath(data_dir);

        // Open or Create the Append-Only Log
        const log_path = try std.fmt.allocPrint(allocator, "{s}/state.data", .{data_dir});
        defer allocator.free(log_path);

        self.log_file = try std.fs.cwd().createFile(log_path, .{ .read = true, .truncate = false });

        // Seek to end to get current Write Offset
        self.current_offset = try self.log_file.getEndPos();

        // If file exists and has data, rebuild the index!
        if (self.current_offset > 0) {
            std.debug.print("[STORAGE] Rebuilding index from {d} bytes...\n", .{self.current_offset});
            try self.rebuildIndex();
        }

        return self;
    }

    pub fn deinit(self: *StorageEngine) void {
        self.log_file.close();

        // Free keys in index (they are duped)
        var it = self.index.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.index.deinit();
        self.allocator.free(self.data_dir);
        self.allocator.destroy(self);
    }

    /// Write Key-Value pair to Log
    pub fn put(self: *StorageEngine, key: []const u8, value: []const u8) !void {
        // 1. Prepare Header
        // [CRC:4][TS:8][KSz:4][VSz:4] = 20 bytes
        var header: [20]u8 = undefined;
        const timestamp = std.time.milliTimestamp();

        // Calculate Checksum (Payload only for speed: Key + Value)
        var crc = std.hash.Crc32.init();
        crc.update(key);
        crc.update(value);
        const checksum = crc.final();

        std.mem.writeInt(u32, header[0..4], checksum, .little);
        std.mem.writeInt(u64, header[4..12], @intCast(timestamp), .little);
        std.mem.writeInt(u32, header[12..16], @intCast(key.len), .little);
        std.mem.writeInt(u32, header[16..20], @intCast(value.len), .little);

        // 2. Write to Log (Header + Key + Value)
        // Ideally we use pwrite or a distinct Writer but appending is fine if we track offset
        // We use a mutex in higher layers, DB is single-threaded writer
        try self.log_file.seekTo(self.current_offset);

        const writer = self.log_file.writer();
        try writer.writeAll(&header);
        try writer.writeAll(key);
        try writer.writeAll(value);

        // 3. Update Index
        // NOTE: We point to the HEADER start, so we can read metadata if needed
        const new_offset = self.current_offset;

        // Update HashMap
        // If key exists, free old key string to prevent leak
        if (self.index.fetchRemove(key)) |k| {
            self.allocator.free(k.key);
        }
        const key_dupe = try self.allocator.dupe(u8, key);
        try self.index.put(key_dupe, new_offset);

        // 4. Advance Offset
        self.current_offset += 20 + key.len + value.len;
    }

    /// Read Value by Key
    pub fn get(self: *StorageEngine, key: []const u8) !?[]u8 {
        const offset = self.index.get(key) orelse return null;

        // 1. Seek to Entry
        try self.log_file.seekTo(offset);
        var reader = self.log_file.reader();

        // 2. Read Header
        var header: [20]u8 = undefined;
        const bytes_read = try reader.readAll(&header);
        if (bytes_read != 20) return StorageError.LogReadError;

        const stored_checksum = std.mem.readInt(u32, header[0..4], .little);
        const key_len = std.mem.readInt(u32, header[12..16], .little);
        const val_len = std.mem.readInt(u32, header[16..20], .little);

        // 3. Skip Key (we already know it, but strictly we should verify it matches)
        // For speed, let's verify key matches what we asked for
        const key_buf = try self.allocator.alloc(u8, key_len);
        defer self.allocator.free(key_buf);
        if (try reader.readAll(key_buf) != key_len) return StorageError.LogReadError;

        if (!std.mem.eql(u8, key, key_buf)) {
            return StorageError.IndexError; // File corruption or index drift
        }

        // 4. Read Value
        const val_buf = try self.allocator.alloc(u8, val_len);
        // On error, free val_buf
        errdefer self.allocator.free(val_buf);

        if (try reader.readAll(val_buf) != val_len) return StorageError.LogReadError;

        // 5. Verify Checksum
        var crc = std.hash.Crc32.init();
        crc.update(key_buf);
        crc.update(val_buf);
        if (crc.final() != stored_checksum) {
            return StorageError.ChecksumMismatch;
        }

        return val_buf;
    }

    /// Rebuild Index from Linear Scan
    fn rebuildIndex(self: *StorageEngine) !void {
        try self.log_file.seekTo(0);
        var reader = self.log_file.reader();

        var scan_offset: u64 = 0;
        var count: usize = 0;

        while (true) {
            var header: [20]u8 = undefined;
            const amt = try reader.readAll(&header);
            if (amt == 0) break; // EOF
            if (amt != 20) return StorageError.LogReadError; // Truncated entry

            const key_len = std.mem.readInt(u32, header[12..16], .little);
            const val_len = std.mem.readInt(u32, header[16..20], .little);

            // Read Key
            const key_buf = try self.allocator.alloc(u8, key_len);
            if (try reader.readAll(key_buf) != key_len) {
                self.allocator.free(key_buf);
                return StorageError.LogReadError;
            }

            // Skip Value (Seek forward)
            try self.log_file.seekBy(@intCast(val_len));

            // Update Index
            if (self.index.fetchRemove(key_buf)) |k| {
                self.allocator.free(k.key);
            }
            try self.index.put(key_buf, scan_offset);

            // Advance
            const entry_size = 20 + key_len + val_len;
            scan_offset += entry_size;
            count += 1;
        }
        self.current_offset = scan_offset;
        std.debug.print("[STORAGE] Index Rebuilt: {d} items\n", .{count});
    }
};
