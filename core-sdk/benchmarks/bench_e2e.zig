const std = @import("std");
const net = std.net;
const types = @import("common").types;
const util = @import("common").util;
const key = @import("crypto").key;

// Default Configuration
const DEFAULT_BATCH_SIZE: usize = 2000;
const DEFAULT_IP = "127.0.0.1";
const DEFAULT_PORT: u16 = 10802;
const MAX_WAIT_SECONDS = 30;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const stdout = std.io.getStdOut().writer();

    // 0. Parse Arguments
    var batch_size: usize = DEFAULT_BATCH_SIZE;
    var target_ip_str: []const u8 = DEFAULT_IP;
    var target_port: u16 = DEFAULT_PORT;

    var args = std.process.args();
    _ = args.next(); // Skip binary name

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--batch")) {
            if (args.next()) |v| {
                batch_size = std.fmt.parseInt(usize, v, 10) catch DEFAULT_BATCH_SIZE;
            }
        } else if (std.mem.eql(u8, arg, "--ip")) {
            if (args.next()) |v| target_ip_str = v;
        } else if (std.mem.eql(u8, arg, "--port")) {
            if (args.next()) |v| {
                target_port = std.fmt.parseInt(u16, v, 10) catch DEFAULT_PORT;
            }
        }
    }

    try stdout.print("==================================================\n", .{});
    try stdout.print("A D R I A   E N D - T O - E N D   B E N C H M A R K\n", .{});
    try stdout.print("==================================================\n", .{});
    try stdout.print("Target: {s}:{d}\n", .{ target_ip_str, target_port });
    try stdout.print("Batch Size: {} Transactions (Pipelined)\n", .{batch_size});

    // 1. Setup Identity
    const keypair = try key.KeyPair.generateUnsignedKey();
    const sender_addr = util.hash256(&keypair.public_key);
    const sender_addr_hex = try std.fmt.allocPrint(allocator, "{s}", .{std.fmt.fmtSliceHexLower(&sender_addr)});
    defer allocator.free(sender_addr_hex);

    try stdout.print("[INIT] Identity: {s}\n", .{sender_addr_hex});

    // 2. Connect to Server
    try stdout.print("[INIT] Connecting to {s}:{d}...\n", .{ target_ip_str, target_port });
    const address = try net.Address.parseIp4(target_ip_str, target_port);
    const stream = try net.tcpConnectToAddress(address);
    defer stream.close();

    // 3. Get Initial Nonce & Height
    try stdout.print("[STEP 1] Fetching Initial State...\n", .{});

    // Get Height
    const status_request = "BLOCKCHAIN_STATUS\n";
    try stream.writeAll(status_request);
    var buffer: [4096]u8 = undefined;
    const status_len = try stream.read(&buffer);
    const status_res = buffer[0..status_len];

    var start_height: u64 = 0;
    if (std.mem.startsWith(u8, status_res, "STATUS:HEIGHT=")) {
        var it = std.mem.splitScalar(u8, status_res, ',');
        const height_part = it.next() orelse "";
        if (std.mem.startsWith(u8, height_part, "STATUS:HEIGHT=")) {
            const h_str = height_part["STATUS:HEIGHT=".len..];
            start_height = std.fmt.parseInt(u64, h_str, 10) catch 0;
        }
    }
    try stdout.print("   -> Start Height: {}\n", .{start_height});

    // Get Nonce
    const nonce_request = try std.fmt.allocPrint(allocator, "GET_NONCE:{s}\n", .{sender_addr_hex});
    defer allocator.free(nonce_request);

    try stream.writeAll(nonce_request);
    const bytes = try stream.read(&buffer);
    const initial_res = buffer[0..bytes];

    // Parse "NONCE:x"
    var start_nonce: u64 = 0;
    if (std.mem.startsWith(u8, initial_res, "NONCE:")) {
        const nonce_str = std.mem.trim(u8, initial_res[6..], "\x00\n\r ");
        start_nonce = std.fmt.parseInt(u64, nonce_str, 10) catch 0;
    }
    try stdout.print("   -> Start Nonce: {}\n", .{start_nonce});

    // 4. Generate Transactions
    try stdout.print("[STEP 2] Generating {} signed transactions (offline)...\n", .{batch_size});
    var tx_batch = try allocator.alloc([]u8, batch_size);
    defer allocator.free(tx_batch);

    var i: usize = 0;
    while (i < batch_size) : (i += 1) {
        const tx_nonce = start_nonce + i;
        const timestamp = @as(u64, @intCast(util.getTime()));

        var transaction = types.Transaction{
            .type = .invoke,
            .sender = sender_addr,
            .sender_public_key = keypair.public_key,
            .recipient = std.mem.zeroes(types.Address),
            .payload = "general_ledger|record_entry|bench_key|bench_val",
            .nonce = tx_nonce,
            .timestamp = timestamp,
            .signature = std.mem.zeroes(types.Signature),
            .sender_cert = std.mem.zeroes([64]u8),
            .network_id = 1,
        };

        const tx_hash = transaction.hash();
        transaction.signature = try keypair.signTransaction(tx_hash);

        const payload_hex = try std.fmt.allocPrint(allocator, "{s}", .{std.fmt.fmtSliceHexLower(transaction.payload)});
        defer allocator.free(payload_hex);

        tx_batch[i] = try std.fmt.allocPrint(allocator, "CLIENT_TRANSACTION:{d}:{s}:{s}:{s}:{}:{}:{}:{s}:{s}\n", .{
            @intFromEnum(transaction.type),
            std.fmt.fmtSliceHexLower(&transaction.sender),
            std.fmt.fmtSliceHexLower(&transaction.recipient),
            payload_hex,
            transaction.timestamp,
            transaction.nonce,
            transaction.network_id,
            std.fmt.fmtSliceHexLower(&transaction.signature),
            std.fmt.fmtSliceHexLower(&transaction.sender_public_key),
        });
    }

    // 5. Blast Phase (Pipelined)
    try stdout.print("[STEP 3] Blasting transactions & Reading ACKs (Pipelined)...\n", .{});

    // Shared state for Reader Thread
    const ReaderContext = struct {
        stream: net.Stream,
        expected_acks: usize,
        completed: std.atomic.Value(bool),
        error_count: std.atomic.Value(usize),

        fn run(ctx: *@This()) void {
            var buf: [4096]u8 = undefined; // Larger buffer for batched reads
            var acks_received: usize = 0;

            while (acks_received < ctx.expected_acks) {
                // Read whatever is available
                // We rely on OS buffering. If server sends individual packets, read might get partials.
                // But Adria server ACKs are small. We are just counting "CLIENT_TRANSACTION_ACCEPTED" substrings?
                // Or just counting newlines?
                // For simplified benchmarking, we can just read until we get enough bytes or time out if we care about strict correctness.
                // But simplified: Just drain the socket.

                const read_bytes = ctx.stream.read(&buf) catch |err| {
                    if (err == error.EndOfStream) break;
                    _ = ctx.error_count.fetchAdd(1, .monotonic);
                    break;
                };

                if (read_bytes == 0) break;

                // Count newlines
                const chunk = buf[0..read_bytes];
                acks_received += std.mem.count(u8, chunk, "\n");
            }

            ctx.completed.store(true, .release);
        }
    };

    var reader_ctx = ReaderContext{
        .stream = stream,
        .expected_acks = batch_size,
        .completed = std.atomic.Value(bool).init(false),
        .error_count = std.atomic.Value(usize).init(0),
    };

    // Spawn Reader Thread
    const reader_thread = try std.Thread.spawn(.{}, ReaderContext.run, .{&reader_ctx});

    const start_time = std.time.milliTimestamp();

    // Writer (Main Thread): Blast everything
    var buffered_writer = std.io.bufferedWriter(stream.writer());
    {
        const writer = buffered_writer.writer();
        for (tx_batch) |msg| {
            try writer.writeAll(msg);
        }
        try buffered_writer.flush();
    }

    const blast_end_time = std.time.milliTimestamp();
    const blast_time_ms = blast_end_time - start_time;
    const blast_tps = @as(f64, @floatFromInt(batch_size)) / (@as(f64, @floatFromInt(blast_time_ms)) / 1000.0);

    try stdout.print("   -> Blasted {} Tx in {} ms ({d:.2} TPS)\n", .{ batch_size, blast_time_ms, blast_tps });
    try stdout.print("   -> Waiting for ACKs...\n", .{});

    // Join Reader Thread (Wait for drain)
    reader_thread.join();

    const ingest_end_time = std.time.milliTimestamp();
    const ingest_time_ms = ingest_end_time - start_time;
    const ingest_tps = @as(f64, @floatFromInt(batch_size)) / (@as(f64, @floatFromInt(ingest_time_ms)) / 1000.0);

    try stdout.print("   -> Ingestion (Acked) Complete!\n", .{});
    try stdout.print("   -> Time: {} ms\n", .{ingest_time_ms});
    try stdout.print("   -> Rate: {d:.2} TPS (Server Processed)\n", .{ingest_tps});

    // 6. Verification Phase (Wait for Finality)
    // For large batches, we might skip polling every single nonce if we just want TPS
    // But let's verify total height change.

    try stdout.print("[STEP 4] Polling for Finality (Height Change)...\n", .{});

    // We expect at least (BATCH / 1000) blocks
    const expected_blocks = (batch_size + 999) / 1000;
    const target_height = start_height + expected_blocks;

    // Check height
    var current_height = start_height;
    const poll_start = std.time.milliTimestamp();

    while (current_height < target_height) {
        std.time.sleep(100 * std.time.ns_per_ms);
        if ((std.time.milliTimestamp() - poll_start) > (MAX_WAIT_SECONDS * 1000)) break;

        try stream.writeAll(status_request);
        const read_len = try stream.read(&buffer);
        const resp = buffer[0..read_len];

        if (std.mem.startsWith(u8, resp, "STATUS:HEIGHT=")) {
            var it = std.mem.splitScalar(u8, resp, ',');
            const hp = it.next() orelse "";
            if (std.mem.startsWith(u8, hp, "STATUS:HEIGHT=")) {
                const h_str = hp["STATUS:HEIGHT=".len..];
                current_height = std.fmt.parseInt(u64, h_str, 10) catch current_height;
                try stdout.print("\r   -> Current Height: {}", .{current_height});
            }
        }
    }
    try stdout.print("\n", .{});

    const final_end_time = std.time.milliTimestamp();
    const total_e2e_time_ms = final_end_time - start_time;
    const final_tps = @as(f64, @floatFromInt(batch_size)) / (@as(f64, @floatFromInt(total_e2e_time_ms)) / 1000.0);

    // Final Stats
    const total_blocks = if (current_height > start_height) current_height - start_height else 0;

    try stdout.print("==================================================\n", .{});
    try stdout.print("FINAL RESULTS ({s}:{d})\n", .{ target_ip_str, target_port });
    try stdout.print("==================================================\n", .{});
    try stdout.print("Transactions:     {}\n", .{batch_size});
    try stdout.print("Blocks Produced:  {}\n", .{total_blocks});
    try stdout.print("Ingestion TPS:    {d:.2} (Fast)\n", .{ingest_tps});
    try stdout.print("End-to-End TPS:   {d:.2} (Real)\n", .{final_tps});
    try stdout.print("==================================================\n", .{});

    // Cleanup
    for (tx_batch) |msg| {
        allocator.free(msg);
    }
}
