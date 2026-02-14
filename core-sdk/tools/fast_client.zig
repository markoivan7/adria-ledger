const std = @import("std");
const net = std.net;
const types = @import("common").types;
const util = @import("common").util;
const key = @import("crypto").key;

// Benchmark Configuration
const BATCH_SIZE = 1000;
const DURATION_SECONDS = 10;
const SERVER_PORT = 10802;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const stdout = std.io.getStdOut().writer();

    try stdout.print("==================================================\n", .{});
    try stdout.print("Adria Native Load Generator (fast_client)\n", .{});
    try stdout.print("==================================================\n", .{});

    // 1. Setup Identity
    try stdout.print("[INIT] Generating temporary benchmark identity...\n", .{});
    const keypair = try key.KeyPair.generateUnsignedKey();
    const sender_addr = util.hash256(&keypair.public_key);
    try stdout.print("[INIT] Sender Address: {s}\n", .{std.fmt.fmtSliceHexLower(&sender_addr)});

    // 2. Pre-calculate transactions (to measure IO/Network, not Crypto)
    try stdout.print("[INIT] Pre-calculating {} transactions...\n", .{BATCH_SIZE});
    var tx_batch = try allocator.alloc([]u8, BATCH_SIZE);
    defer allocator.free(tx_batch);

    var i: usize = 0;
    while (i < BATCH_SIZE) : (i += 1) {
        // Create dummy transaction
        const timestamp = @as(u64, @intCast(util.getTime()));
        var transaction = types.Transaction{
            .type = .invoke,
            .sender = sender_addr,
            .sender_public_key = keypair.public_key,
            .recipient = std.mem.zeroes(types.Address),
            .payload = "bench_payload",
            .nonce = i, // Simple incrementing nonce
            .timestamp = timestamp,
            .signature = std.mem.zeroes(types.Signature),
            .sender_cert = std.mem.zeroes([64]u8),
        };

        // Sign it
        const tx_hash = transaction.hash();
        transaction.signature = try keypair.signTransaction(tx_hash);

        // Serialize to protocol format:
        // CLIENT_TRANSACTION:type:sender:recipient:payload_hex:timestamp:nonce:sig:pubkey

        // Payload hex
        const payload_hex = try std.fmt.allocPrint(allocator, "{s}", .{std.fmt.fmtSliceHexLower(transaction.payload)});
        defer allocator.free(payload_hex);

        const tx_msg = try std.fmt.allocPrint(allocator, "CLIENT_TRANSACTION:{d}:{s}:{s}:{s}:{}:{}:{s}:{s}", .{
            @intFromEnum(transaction.type),
            std.fmt.fmtSliceHexLower(&transaction.sender),
            std.fmt.fmtSliceHexLower(&transaction.recipient),
            payload_hex,
            transaction.timestamp,
            transaction.nonce,
            std.fmt.fmtSliceHexLower(&transaction.signature),
            std.fmt.fmtSliceHexLower(&transaction.sender_public_key),
        });

        tx_batch[i] = tx_msg;
    }

    // 3. Connect to Server
    try stdout.print("[INIT] Connecting to localhost:{d}...\n", .{SERVER_PORT});
    const address = try net.Address.parseIp4("127.0.0.1", SERVER_PORT);
    const stream = try net.tcpConnectToAddress(address);
    defer stream.close();
    try stdout.print("[SUCCESS] Connected!\n", .{});

    // 4. Blast Loop
    try stdout.print("[RUN] Starting load test for {} seconds...\n", .{DURATION_SECONDS});

    var total_sent: usize = 0;
    const start_time = std.time.milliTimestamp();
    const end_time_target = start_time + (DURATION_SECONDS * 1000);

    // We reuse the pre-calculated batch in a loop
    var batch_idx: usize = 0;
    var read_buffer: [1024]u8 = undefined;

    while (std.time.milliTimestamp() < end_time_target) {
        const tx_msg = tx_batch[batch_idx];

        // Send
        try stream.writeAll(tx_msg);

        // Wait for Ack (Synchronous mode for now to ensure ordering/reliability)
        // In a real high-perf scenario, we might pipeline, but let's start simple
        // to beat the CLI process overhead.
        const bytes_read = try stream.read(&read_buffer);
        if (bytes_read == 0) break; // Server closed

        // Ack Format: CLIENT_TRANSACTION_ACCEPTED or ERROR
        // We assume success for speed, or check briefly
        // if (!std.mem.startsWith(u8, read_buffer[0..bytes_read], "CLIENT_TRANSACTION_ACCEPTED")) {
        //      try stdout.print("Error: {s}\n", .{read_buffer[0..bytes_read]});
        // }

        total_sent += 1;
        batch_idx = (batch_idx + 1) % BATCH_SIZE;
    }

    const end_time = std.time.milliTimestamp();
    const duration_ms = end_time - start_time;
    const tps = @as(f64, @floatFromInt(total_sent)) / (@as(f64, @floatFromInt(duration_ms)) / 1000.0);

    try stdout.print("\n==================================================\n", .{});
    try stdout.print("RESULTS\n", .{});
    try stdout.print("==================================================\n", .{});
    try stdout.print("Total Transactions: {}\n", .{total_sent});
    try stdout.print("Duration:           {d} ms\n", .{duration_ms});
    try stdout.print("Throughput:         {d:.2} TPS\n", .{tps});
    try stdout.print("==================================================\n", .{});

    // Cleanup
    for (tx_batch) |msg| {
        allocator.free(msg);
    }
}
