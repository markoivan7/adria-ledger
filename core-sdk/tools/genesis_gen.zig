const std = @import("std");
const json = std.json;
const types = @import("common").types;
const util = @import("common").util;
const key = @import("crypto").key;
const gov = @import("execution").system.governance;

// Genesis Generator Tool
// Usage: genesis_gen <output_file> [options]

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) {
        std.debug.print("Usage: genesis_gen <output_file> [--admin <pubkey>] [--validators <count>] [--block-time <seconds>]\n", .{});
        return;
    }

    const output_file = args[1];
    var admin_keys = std.ArrayList([]const u8).init(allocator);
    defer admin_keys.deinit();

    var min_validators: u32 = 1;
    var block_time: u64 = 10;

    // Parse args
    var i: usize = 2;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--admin")) {
            if (i + 1 < args.len) {
                try admin_keys.append(args[i + 1]);
                i += 1;
            }
        } else if (std.mem.eql(u8, arg, "--validators")) {
            if (i + 1 < args.len) {
                min_validators = try std.fmt.parseInt(u32, args[i + 1], 10);
                i += 1;
            }
        } else if (std.mem.eql(u8, arg, "--block-time")) {
            if (i + 1 < args.len) {
                block_time = try std.fmt.parseInt(u64, args[i + 1], 10);
                i += 1;
            }
        }
    }

    // Default admin if none provided (Development Key)
    if (admin_keys.items.len == 0) {
        // Use the hardcoded dev key from main.zig or a zero key
        try admin_keys.append("0000000000000000000000000000000000000000000000000000000000000000");
    }

    // Create Policy
    const policy = gov.GovernancePolicy{
        .protocol_version = types.SUPPORTED_PROTOCOL_VERSION,
        .root_cas = admin_keys.items,
        .min_validator_count = min_validators,
        .block_creation_interval = block_time,
    };

    // Serialize Policy
    const policy_json = try policy.toJson(allocator);
    defer allocator.free(policy_json);

    // Create Genesis Block Payload (JSON Config)
    const file = try std.fs.cwd().createFile(output_file, .{});
    defer file.close();

    try file.writeAll(policy_json);

    std.debug.print("Genesis configuration written to {s}\n", .{output_file});
}
