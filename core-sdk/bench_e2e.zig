const std = @import("std");
const net = std.net;
const types = @import("common/types.zig");
const util = @import("common/util.zig");
const key = @import("crypto/key.zig");

// Benchmark Configuration
const BATCH_SIZE = 2000; // Enough to fill exactly 2 blocks (default 1000/block)
const SERVER_PORT = 10802;
// Wait timeout for finality (seconds)
const MAX_WAIT_SECONDS = 30;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const stdout = std.io.getStdOut().writer();

    try stdout.print("==================================================\n", .{});
    try stdout.print("A D R I A   E N D - T O - E N D   B E N C H M A R K\n", .{});
    try stdout.print("==================================================\n", .{});
    try stdout.print("Target: Ingestion + Consensus + Execution + Persistence\n", .{});
    try stdout.print("Batch Size: {} Transactions\n", .{BATCH_SIZE});

    // 1. Setup Identity
    const keypair = try key.KeyPair.generateUnsignedKey();
    const sender_addr = util.hash256(&keypair.public_key);
    const sender_addr_hex = try std.fmt.allocPrint(allocator, "{s}", .{std.fmt.fmtSliceHexLower(&sender_addr)});
    defer allocator.free(sender_addr_hex);

    try stdout.print("[INIT] Identity: {s}\n", .{sender_addr_hex});

    // 2. Connect to Server
    try stdout.print("[INIT] Connecting to 127.0.0.1:{d}...\n", .{SERVER_PORT});
    const address = try net.Address.parseIp4("127.0.0.1", SERVER_PORT);
    const stream = try net.tcpConnectToAddress(address);
    defer stream.close();

    // 3. Get Initial Nonce & Height
    try stdout.print("[STEP 1] Fetching Initial State...\n", .{});

    // Get Height
    const status_request = "BLOCKCHAIN_STATUS";
    try stream.writeAll(status_request);
    var buffer: [1024]u8 = undefined;
    const status_len = try stream.read(&buffer);
    const status_res = buffer[0..status_len];

    var start_height: u64 = 0;
    if (std.mem.startsWith(u8, status_res, "STATUS:HEIGHT=")) {
        // Parse STATUS:HEIGHT=123,PENDING=...
        var it = std.mem.splitScalar(u8, status_res, ',');
        const height_part = it.next() orelse "";
        if (std.mem.startsWith(u8, height_part, "STATUS:HEIGHT=")) {
            const h_str = height_part["STATUS:HEIGHT=".len..];
            start_height = try std.fmt.parseInt(u64, h_str, 10);
        }
    }
    try stdout.print("   -> Start Height: {}\n", .{start_height});

    // Get Nonce
    const nonce_request = try std.fmt.allocPrint(allocator, "GET_NONCE:{s}", .{sender_addr_hex});
    defer allocator.free(nonce_request);

    try stream.writeAll(nonce_request);
    const bytes = try stream.read(&buffer);
    const initial_res = buffer[0..bytes];

    // Parse "NONCE:x"
    var start_nonce: u64 = 0;
    if (std.mem.startsWith(u8, initial_res, "NONCE:")) {
        const nonce_str = std.mem.trim(u8, initial_res[6..], "\x00\n\r ");
        start_nonce = try std.fmt.parseInt(u64, nonce_str, 10);
    }
    try stdout.print("   -> Start Nonce: {}\n", .{start_nonce});

    // 4. Generate Transactions
    try stdout.print("[STEP 2] Generating {} signed transactions (offline)...\n", .{BATCH_SIZE});
    var tx_batch = try allocator.alloc([]u8, BATCH_SIZE);
    defer allocator.free(tx_batch);

    var i: usize = 0;
    while (i < BATCH_SIZE) : (i += 1) {
        // Increment nonce correctly
        const tx_nonce = start_nonce + i;
        const timestamp = @as(u64, @intCast(util.getTime()));

        var transaction = types.Transaction{
            .type = .invoke,
            .sender = sender_addr,
            .sender_public_key = keypair.public_key,
            .recipient = std.mem.zeroes(types.Address),
            // Use valid payload: chaincode|function|args
            .payload = "general_ledger|record_entry|bench_key|bench_val",
            .nonce = tx_nonce,
            .timestamp = timestamp,
            .signature = std.mem.zeroes(types.Signature),
            .sender_cert = std.mem.zeroes([64]u8),
        };

        const tx_hash = transaction.hash();
        transaction.signature = try keypair.signTransaction(tx_hash);

        const payload_hex = try std.fmt.allocPrint(allocator, "{s}", .{std.fmt.fmtSliceHexLower(transaction.payload)});
        defer allocator.free(payload_hex);

        tx_batch[i] = try std.fmt.allocPrint(allocator, "CLIENT_TRANSACTION:{d}:{s}:{s}:{s}:{}:{}:{s}:{s}", .{
            @intFromEnum(transaction.type),
            std.fmt.fmtSliceHexLower(&transaction.sender),
            std.fmt.fmtSliceHexLower(&transaction.recipient),
            payload_hex,
            transaction.timestamp,
            transaction.nonce,
            std.fmt.fmtSliceHexLower(&transaction.signature),
            std.fmt.fmtSliceHexLower(&transaction.sender_public_key),
        });
    }

    // 5. Blast Phase
    try stdout.print("[STEP 3] Blasting transactions to Ingestion Layer...\n", .{});
    const start_time = std.time.milliTimestamp();

    for (tx_batch) |msg| {
        try stream.writeAll(msg);
        // We wait for ack effectively making this "Ingestion Latency" per tx
        // Ideally we would pipeline, but synchronous is a stricter test for the server logic
        const ack_bytes = try stream.read(&buffer);
        if (ack_bytes == 0) return error.ServerDisconnected;
    }

    const ingest_end_time = std.time.milliTimestamp();
    const ingest_time_ms = ingest_end_time - start_time;
    const ingest_tps = @as(f64, @floatFromInt(BATCH_SIZE)) / (@as(f64, @floatFromInt(ingest_time_ms)) / 1000.0);

    try stdout.print("   -> Ingestion Complete!\n", .{});
    try stdout.print("   -> Time: {} ms\n", .{ingest_time_ms});
    try stdout.print("   -> Rate: {d:.2} TPS (Into Mempool)\n", .{ingest_tps});

    // 6. Verification Phase (Wait for Finality)
    try stdout.print("[STEP 4] Polling for Finality (Consensus + Execution)...\n", .{});

    const target_nonce = start_nonce + BATCH_SIZE;
    var current_nonce: u64 = start_nonce;
    const poll_start = std.time.milliTimestamp();

    while (current_nonce < target_nonce) {
        // Sleep a bit (simulate block time waiting)
        std.time.sleep(100 * std.time.ns_per_ms);

        // Check timeout
        if ((std.time.milliTimestamp() - poll_start) > (MAX_WAIT_SECONDS * 1000)) {
            try stdout.print("\n[TIMEOUT] Waited {}s for finality. Last Nonce: {}\n", .{ MAX_WAIT_SECONDS, current_nonce });
            break;
        }

        // Poll Nonce
        try stream.writeAll(nonce_request);
        const read_len = try stream.read(&buffer);
        if (read_len == 0) break;

        const resp = buffer[0..read_len];
        if (std.mem.startsWith(u8, resp, "NONCE:")) {
            const n_str = std.mem.trim(u8, resp[6..], "\x00\n\r ");
            current_nonce = std.fmt.parseInt(u64, n_str, 10) catch current_nonce;

            // Progress bar
            try stdout.print("\r   -> Confirmed: {}/{} ({d}%)", .{ current_nonce - start_nonce, BATCH_SIZE, (current_nonce - start_nonce) * 100 / BATCH_SIZE });
        }
    }
    try stdout.print("\n", .{});

    const final_end_time = std.time.milliTimestamp();
    const total_e2e_time_ms = final_end_time - start_time;
    const final_tps = @as(f64, @floatFromInt(BATCH_SIZE)) / (@as(f64, @floatFromInt(total_e2e_time_ms)) / 1000.0);

    // Get Final Height
    try stream.writeAll(status_request);
    const final_status_len = try stream.read(&buffer);
    const final_status_res = buffer[0..final_status_len];

    var final_height: u64 = 0;
    if (std.mem.startsWith(u8, final_status_res, "STATUS:HEIGHT=")) {
        var it = std.mem.splitScalar(u8, final_status_res, ',');
        const height_part = it.next() orelse "";
        if (std.mem.startsWith(u8, height_part, "STATUS:HEIGHT=")) {
            const h_str = height_part["STATUS:HEIGHT=".len..];
            final_height = try std.fmt.parseInt(u64, h_str, 10);
        }
    }

    const total_blocks = if (final_height > start_height) final_height - start_height else 1;
    const avg_tx_block = @as(f64, @floatFromInt(BATCH_SIZE)) / @as(f64, @floatFromInt(total_blocks));

    try stdout.print("==================================================\n", .{});
    try stdout.print("FINAL RESULTS\n", .{});
    try stdout.print("==================================================\n", .{});
    try stdout.print("Transactions:     {}\n", .{BATCH_SIZE});
    try stdout.print("Blocks Produced:  {}\n", .{total_blocks});
    try stdout.print("Avg Tx/Block:     {d:.2}\n", .{avg_tx_block});
    try stdout.print("Ingestion TPS:    {d:.2} (Fast)\n", .{ingest_tps});
    try stdout.print("End-to-End TPS:   {d:.2} (Real)\n", .{final_tps});
    try stdout.print("==================================================\n", .{});

    // Cleanup
    for (tx_batch) |msg| {
        allocator.free(msg);
    }
}
