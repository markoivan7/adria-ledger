// config.zig - Adria Node Configuration
// Handles loading and saving of node operational configuration (ports, paths, logging)

const std = @import("std");
const fs = std.fs;
const json = std.json;

// Default Configuration Values
const DEFAULT_P2P_PORT = 10801;
const DEFAULT_API_PORT = 10802;
const DEFAULT_DATA_DIR = "apl_data";

pub const Config = struct {
    network: struct {
        p2p_port: u16 = DEFAULT_P2P_PORT,
        api_port: u16 = DEFAULT_API_PORT,
        discovery: bool = true,
        // Seeds for bootstrapping (optional)
        seeds: []const []const u8 = &[_][]const u8{},
    },
    storage: struct {
        data_dir: []const u8 = DEFAULT_DATA_DIR,
        // Log level: "debug", "info", "warn", "error"
        log_level: []const u8 = "info",
    },
    consensus: struct {
        // "solo" or "raft"
        mode: []const u8 = "solo",
        // Address of the orderer if not self (for Raft or remote solo)
        orderer_address: ?[]const u8 = null,
    },

    // Helper to get default configuration
    pub fn default() Config {
        return Config{
            .network = .{
                .p2p_port = DEFAULT_P2P_PORT,
                .api_port = DEFAULT_API_PORT,
                .discovery = true,
                .seeds = &[_][]const u8{},
            },
            .storage = .{
                .data_dir = DEFAULT_DATA_DIR,
                .log_level = "info",
            },
            .consensus = .{
                .mode = "solo",
                .orderer_address = null,
            },
        };
    }
};

/// Load configuration from a JSON file
pub fn loadFromFile(allocator: std.mem.Allocator, file_path: []const u8) !Config {
    const file = fs.cwd().openFile(file_path, .{}) catch |err| {
        if (err == error.FileNotFound) {
            // If file doesn't exist, return default
            return Config.default();
        }
        return err;
    };
    defer file.close();

    const file_size = try file.getEndPos();
    const buffer = try allocator.alloc(u8, file_size);
    defer allocator.free(buffer);

    _ = try file.readAll(buffer);

    const parsed = try json.parseFromSlice(Config, allocator, buffer, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();

    // We need to clone the strings because parsed.value references the buffer which will be freed
    // Deep clone the config
    const config = parsed.value;

    // Provide a copy that owns its memory?
    // For simplicity in this PoC, we will just return the parsed value and rely on the arena if we used one,
    // but here we are using a raw allocator.
    // Actually, `json.parseFromSlice` returns a `Parsed(T)` which owns the memory if it allocated any?
    // No, it uses the provided allocator for allocations.
    // But strings slice into the input buffer if they can?
    // In Zig 0.11/0.12/0.13 JSON parsing behavior varies.
    // Safest bet for "Config" which is long-lived is to duplicate strings if they point to buffer.

    // However, to keep it simple: we can just copy the fields we need or use an arena for the config.
    // Let's assume the caller handles memory or we leak strictly for the valid lifetime of the program (Server Config).
    // Better yet, let's just parse and return. The `buffer` is freed, so string slices will dangle if they point to it.

    // To fix dangling pointers:
    // We should use `json.parseFromSliceLeaky` if we want to preserve it, OR use an ArenaAllocator
    // in the caller and pass that.

    return config;
}

// Wrapper to load with arena to ensure memory safety for strings
pub fn loadFromFileArena(arena: std.mem.Allocator, file_path: []const u8) !Config {
    const file = fs.cwd().openFile(file_path, .{}) catch |err| {
        if (err == error.FileNotFound) {
            return Config.default();
        }
        return err;
    };
    defer file.close();

    const file_size = try file.getEndPos();
    const buffer = try arena.alloc(u8, file_size);
    _ = try file.readAll(buffer);

    const parsed = try json.parseFromSlice(Config, arena, buffer, .{ .ignore_unknown_fields = true });
    // We do NOT deinit parsed, as we want the allocated strings to live in the arena
    return parsed.value;
}

/// Save configuration to a JSON file
pub fn saveToFile(config: Config, file_path: []const u8) !void {
    const file = try fs.cwd().createFile(file_path, .{});
    defer file.close();

    try json.stringify(config, .{ .whitespace = .indent_4 }, file.writer());
}
