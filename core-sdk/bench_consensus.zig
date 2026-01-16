const std = @import("std");
const types = @import("common/types.zig");
const solo = @import("consensus/solo.zig");
const db = @import("execution/db.zig");
const key = @import("crypto/key.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("==================================================\n", .{});
    std.debug.print("BENCHMARK: Consensus Ingestion (SoloOrderer)\n", .{});
    std.debug.print("==================================================\n", .{});

    // Setup DB
    const tmp_dir = "bench_data_consensus";
    std.fs.cwd().deleteTree(tmp_dir) catch {};
    var database = try db.Database.init(allocator, tmp_dir);
    defer {
        database.deinit();
        std.fs.cwd().deleteTree(tmp_dir) catch {};
    }

    // Setup Orderer
    const keypair = try key.KeyPair.generateUnsignedKey();
    const identity = key.Identity{
        .keypair = keypair,
        .certificate = [_]u8{0} ** 64,
    };

    var orderer = try solo.SoloOrderer.init(allocator, &database, identity);
    defer orderer.deinit();

    const consenter = orderer.consenter();

    // Prepare Transaction
    const tx = types.Transaction{
        .type = .invoke,
        .sender = [_]u8{0} ** 32,
        .recipient = [_]u8{1} ** 32,
        .payload = "bench_mark_transaction_payload",
        .nonce = 1,
        .timestamp = 12345,
        .sender_public_key = [_]u8{0} ** 32,
        .sender_cert = [_]u8{0} ** 64,
        .signature = [_]u8{0} ** 64,
    };

    const num_tx = 100000;
    std.debug.print("Ingesting {} transactions...\n", .{num_tx});

    const start = std.time.milliTimestamp();

    var i: usize = 0;
    while (i < num_tx) : (i += 1) {
        try consenter.recvTransaction(tx);
    }

    const end = std.time.milliTimestamp();
    const total_time = end - start;

    const tps = @as(f64, @floatFromInt(num_tx)) / (@as(f64, @floatFromInt(total_time)) / 1000.0);

    std.debug.print("Total Time: {} ms\n", .{total_time});
    std.debug.print("Throughput: {d:.2} Tx/sec (Ingestion Only)\n", .{tps});
}
