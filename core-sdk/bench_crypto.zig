const std = @import("std");
const key = @import("crypto/key.zig");
const types = @import("common/types.zig");
const util = @import("common/util.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    std.debug.print("==================================================\n", .{});
    std.debug.print("BENCHMARK: Crypto (Ed25519 Sign/Verify)\n", .{});
    std.debug.print("==================================================\n", .{});

    // Setup Key
    const keypair = try key.KeyPair.generateUnsignedKey();

    const msg = "benchmark_message_payload";
    const msg_hash = util.hash(msg);

    const num_ops = 5000;

    // 1. Benchmark Signing
    std.debug.print("Benchmarking {} signatures...\n", .{num_ops});
    var start = std.time.milliTimestamp();
    var i: usize = 0;
    var last_sig: types.Signature = undefined;
    while (i < num_ops) : (i += 1) {
        last_sig = try keypair.sign(&msg_hash);
    }
    var end = std.time.milliTimestamp();
    var time_ms = end - start;
    var ops_sec = @as(f64, @floatFromInt(num_ops)) / (@as(f64, @floatFromInt(time_ms)) / 1000.0);
    std.debug.print("Signing:      {d:.2} ops/sec\n", .{ops_sec});

    // 2. Benchmark Verification
    std.debug.print("Benchmarking {} verifications...\n", .{num_ops});
    start = std.time.milliTimestamp();
    i = 0;
    while (i < num_ops) : (i += 1) {
        if (!key.verify(keypair.public_key, &msg_hash, last_sig)) {
            std.debug.print("Verification failed!\n", .{});
            return;
        }
    }
    end = std.time.milliTimestamp();
    time_ms = end - start;
    ops_sec = @as(f64, @floatFromInt(num_ops)) / (@as(f64, @floatFromInt(time_ms)) / 1000.0);
    std.debug.print("Verification: {d:.2} ops/sec\n", .{ops_sec});
}
