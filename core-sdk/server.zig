// server.zig - Adria Permissioned Ledger (APL) Server
// Minimalist blockchain node: P2P networking + client API server
// Ports:10800 (UDP Discovery) 10801 (P2P), 10802 (Client API)
// Features: Auto-mining, peer discovery, transaction broadcasting

const std = @import("std");
const net = std.net;
const print = std.debug.print;

const zeicoin_main = @import("main.zig");
const zen_net = @import("network/net.zig");
const types = @import("common/types.zig");
const key = @import("crypto/key.zig");
const util = @import("common/util.zig");
const db = @import("execution/db.zig");

// Global log file
var log_file: ?std.fs.File = null;

fn logMessage(comptime fmt: []const u8, args: anytype) void {
    const timestamp = std.time.timestamp();
    if (log_file) |file| {
        file.writer().print("[{}] ", .{timestamp}) catch {};
        file.writer().print(fmt, args) catch {};
        file.writer().print("\n", .{}) catch {};
    }
    print(fmt, args);
}

// Compact banner for server startup

fn printCompactBanner() void {
    print("\n", .{});
    print("╔══════════════════════════════════════════════════════════════════════╗\n", .{});
    print("║                                                                      ║\n", .{});
    print("║               █████╗ ██████╗ ██████╗ ██╗ █████╗                      ║\n", .{});
    print("║              ██╔══██╗██╔══██╗██╔══██╗██║██╔══██╗                     ║\n", .{});
    print("║              ███████║██║  ██║██████╔╝██║███████║                     ║\n", .{});
    print("║              ██╔══██║██║  ██║██╔══██╗██║██╔══██║                     ║\n", .{});
    print("║              ██║  ██║██████╔╝██║  ██║██║██║  ██║                     ║\n", .{});
    print("║              ╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝                     ║\n", .{});
    print("║                                                                      ║\n", .{});
    print("║            Adria Permissioned Ledger (APL) Node v0.4.0               ║\n", .{});
    print("║                                                                      ║\n", .{});
    print("╚══════════════════════════════════════════════════════════════════════╝\n", .{});
    print("\n", .{});
}

// formatZEI removed in Phase 5

// Orderer Configuration
const BATCH_SIZE_LIMIT: usize = 1000;
const BATCH_TIMEOUT_NS: u64 = 500 * std.time.ns_per_ms; // 500ms

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Initialize logging
    log_file = std.fs.cwd().createFile("logs/server.log", .{}) catch null;
    defer if (log_file) |file| file.close();

    // Check args for configuration
    var is_orderer = false;
    var p2p_port: u16 = 10801;
    var client_port: u16 = 10802;
    var enable_discovery = true;

    var args = std.process.args();
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--orderer")) {
            is_orderer = true;
        } else if (std.mem.eql(u8, arg, "--no-discovery")) {
            enable_discovery = false;
        } else if (std.mem.startsWith(u8, arg, "--p2p-port=")) {
            const port_str = arg["--p2p-port=".len..];
            p2p_port = std.fmt.parseInt(u16, port_str, 10) catch 10801;
        } else if (std.mem.startsWith(u8, arg, "--api-port=")) {
            const port_str = arg["--api-port=".len..];
            client_port = std.fmt.parseInt(u16, port_str, 10) catch 10802;
        }
    }

    // Show compact banner
    printCompactBanner();

    // Initialize APL blockchain with networking
    print("Initializing Adria Ledger...\n", .{});
    var zeicoin = try zeicoin_main.ZeiCoin.init(allocator);
    defer zeicoin.deinit();

    // Initialize network manager (Adria flow)
    print("Creating network flow...\n", .{});
    var network = zen_net.NetworkManager.init(allocator);
    defer network.deinit();

    // Connect blockchain to network (Adria unity - bidirectional flow)
    zeicoin.network = &network;
    network.blockchain = zeicoin;

    print("[INFO] APL blockchain loaded!\n", .{});
    print("\n[INFO] Network Configuration:\n", .{});
    print("   P2P Port: {}\n", .{p2p_port});
    print("   API Port: {}\n", .{client_port});
    print("   Discovery: {s}\n", .{if (enable_discovery) "ENABLED" else "DISABLED"});
    types.NetworkConfig.displayInfo();
    zeicoin.printStatus();

    if (is_orderer) {
        print("\n[INFO] STARTING IN ORDERER MODE\n", .{});
        print("[INFO] Batch Strategy: Size={}, Timeout=500ms\n", .{BATCH_SIZE_LIMIT});

        // Setup temporary Orderer Identity for PoC
        // In production, this would load from files: validation.key and validation.crt
        // And Root CA would be fixed.
        print("[INFO] Generating temporary Orderer Identity...\n", .{});

        // 1. Generate a Root CA for this session (simulated)
        const root_ca = try key.KeyPair.generateUnsignedKey(); // Use generateUnsignedKey as helper if available, or just KeyPair logic
        // Need a method to generate fresh key. KeyPair.generateUnsignedKey() exists in server usage earlier.

        // Override blockchain root key so it accepts our blocks
        zeicoin.root_public_key = root_ca.public_key;

        // 2. Issue Validator Identity
        // We need to construct an Identity. key.Identity.createNew(root_ca) is used in tests.
        const validator_id = try key.Identity.createNew(root_ca);
        // We transfer ownership to zeicoin struct via helper
        zeicoin.setValidator(validator_id);

        print("[INFO] Orderer Identity Active: {s}\n", .{std.fmt.fmtSliceHexLower(validator_id.keypair.public_key[0..8])});
    } else {
        print("\n[INFO] STARTING IN PEER MODE (Validating Only - No Block Production)\n", .{});
        print("[INFO] Use --orderer to enable block production\n", .{});
    }

    // Start background sync loop
    try zeicoin.start();

    // Create TCP server for client connections (separate from P2P)
    const address = net.Address.parseIp4("0.0.0.0", client_port) catch |err| {
        print("[ERROR] Failed to parse client address: {}\n", .{err});
        return;
    };

    print("[INFO] Starting APL multi-peer network on port {}...\n", .{p2p_port});

    // Start P2P networking for peer connections
    try network.start(p2p_port);

    if (enable_discovery) {
        print("[INFO] Discovering peers in the network (background thread)...\n", .{});
        // Start peer discovery in background thread
        const DiscoveryTask = struct {
            fn run(n: *zen_net.NetworkManager, p: u16) void {
                n.discoverPeers(p) catch |err| {
                    print("[WARN] Discovery thread error: {}\n", .{err});
                };
            }
        };

        const thread = std.Thread.spawn(.{}, DiscoveryTask.run, .{ &network, p2p_port }) catch |err| {
            print("[ERROR] Failed to spawn discovery thread: {}\n", .{err});
            // Continue execution without autodiscovery
            return;
        };
        thread.detach();
    } else {
        print("[INFO] Peer discovery disabled (Manual peer add or bootstrap required)\n", .{});
        // Still connect to bootstrap nodes if env var set
        try network.connectToBootstrapNodes();
    }

    // Create TCP server for client API connections (separate port)
    var server = address.listen(.{ .reuse_address = true }) catch |err| {
        print("[ERROR] Failed to create client TCP server: {}\n", .{err});
        std.process.exit(1);
    };
    defer server.deinit();

    print("[INFO] APL Server ready!\n", .{});
    print("[INFO] P2P Network: Port {} ACTIVE\n", .{p2p_port});
    print("[INFO] Client API: Port {} ACCEPTING\n", .{client_port});
    print("[INFO] Auto-discovery: ENABLED\n", .{});

    if (network.peers.items.len == 0) {
        print("\n[INFO] Network Status: Standalone Mode (0 Peers Connected)\n", .{});
    } else {
        network.printStatus();
    }

    print("\n[INFO] The network is running...\n", .{});
    print("[INFO] Press Ctrl+C to stop\n\n", .{});

    // Statistics
    var connection_count: u32 = 0;
    var transaction_count = std.atomic.Value(u32).init(0);

    // Main loop - network handles P2P, we handle clients
    while (true) {
        // Orderer Logic handled in background

        // Handle client connections
        if (server.accept()) |connection| {
            connection_count += 1;
            print("[INFO] APL client #{} connected (Spawning Thread)\n", .{connection_count});

            const ThreadContext = struct {
                allocator: std.mem.Allocator,
                conn: net.Server.Connection,
                zeicoin: *zeicoin_main.ZeiCoin,
                tx_count: *std.atomic.Value(u32),

                fn run(ctx: @This()) void {
                    defer ctx.conn.stream.close();
                    handleZeiCoinClient(ctx.allocator, ctx.conn, ctx.zeicoin, ctx.tx_count) catch |err| {
                        print("[ERROR] Client handling error: {}\n", .{err});
                    };
                }
            };

            const ctx = ThreadContext{
                .allocator = allocator,
                .conn = connection,
                .zeicoin = zeicoin,
                .tx_count = &transaction_count,
            };

            const thread = std.Thread.spawn(.{}, ThreadContext.run, .{ctx}) catch |err| {
                print("[ERROR] Failed to spawn client thread: {}\n", .{err});
                connection.stream.close();
                continue;
            };
            thread.detach();
        } else |err| switch (err) {
            error.WouldBlock => {
                // No client connection, continue with flow
            },
            else => {
                print("[WARN] Accept error: {}\n", .{err});
            },
        }

        // Reduced sleep as blocking accept handles pacing mostly,
        // but if non-blocking, this sleep prevents CPU burn.
        // If accept IS blocking, this sleep logic is less relevant for the main loop iteration
        // but important if we use WouldBlock.
        // Standard Zig accept blocks. So we won't loop tight.
    }
}

fn handleZeiCoinClient(allocator: std.mem.Allocator, connection: net.Server.Connection, zeicoin: *zeicoin_main.ZeiCoin, transaction_count: *std.atomic.Value(u32)) !void {
    var buffer: [262144]u8 = undefined;
    var stream = connection.stream;
    var reader = stream.reader();

    while (true) {
        // Read message from client (Line based)
        const message_opt = reader.readUntilDelimiterOrEof(&buffer, '\n') catch |err| {
            if (err == error.StreamTooLong) {
                print("[ERROR] Message too long\n", .{});
                break;
            }
            print("[ERROR] Read error: {}\n", .{err});
            break;
        };

        const message = message_opt orelse {
            print("[INFO] Client closed connection\n", .{});
            break;
        };

        // Trim carriage return if present (Windows/Telnet)
        const trimmed_msg = std.mem.trimRight(u8, message, "\r");
        print("[INFO] Received: '{s}' ({} bytes)\n", .{ trimmed_msg, trimmed_msg.len });

        // Parse APL protocol messages
        if (std.mem.eql(u8, trimmed_msg, "BLOCKCHAIN_STATUS")) {
            print("[INFO] Processing BLOCKCHAIN_STATUS command\n", .{});
            try sendBlockchainStatus(connection, zeicoin);
        } else if (std.mem.startsWith(u8, trimmed_msg, "GET_NONCE:")) {
            try handleNonceCheck(allocator, connection, zeicoin, trimmed_msg);
        } else if (std.mem.startsWith(u8, trimmed_msg, "CLIENT_TRANSACTION:")) {
            try handleClientTransaction(allocator, connection, zeicoin, trimmed_msg, transaction_count);
        } else if (std.mem.startsWith(u8, trimmed_msg, "SEND_TRANSACTION:")) {
            try handleTransaction(allocator, connection, zeicoin, trimmed_msg, transaction_count);
        } else if (std.mem.eql(u8, trimmed_msg, "PING")) {
            const response = "PONG from APL Bootstrap";
            try connection.stream.writeAll(response);
            print("[INFO] Responded to PING\n", .{});
        } else {
            // Default response for unknown messages
            const response = "APL Bootstrap Server Ready";
            try connection.stream.writeAll(response);
            print("[INFO] Sent default response for unknown command: {s}\n", .{trimmed_msg});
        }

        // Check for pending transactions and auto-mining removed
        // TODO: Notify Orderer if we are a client submitting tx

    }
}

fn sendBlockchainStatus(connection: net.Server.Connection, zeicoin: *zeicoin_main.ZeiCoin) !void {
    const height = zeicoin.getHeight() catch 0;
    const pending = 0; // zeicoin.mempool.items.len; // Mempool hidden in consensus

    // Create status message
    var status_buffer: [256]u8 = undefined;
    const status_msg = try std.fmt.bufPrint(&status_buffer, "STATUS:HEIGHT={},PENDING={},READY=true", .{ height, pending });

    print("[INFO] Preparing to send blockchain status: {s}\n", .{status_msg});
    try connection.stream.writeAll(status_msg);
    print("[INFO] Sent blockchain status successfully: {s}\n", .{status_msg});
}

fn handleTransaction(allocator: std.mem.Allocator, connection: net.Server.Connection, zeicoin: *zeicoin_main.ZeiCoin, message: []const u8, transaction_count: *std.atomic.Value(u32)) !void {
    _ = allocator;
    _ = message;

    print("[INFO] Creating valid test invocation...\n", .{});

    // Create a sender wallet
    var test_sender_wallet = try key.KeyPair.generateUnsignedKey();
    const sender_address = test_sender_wallet.getAddress();

    // Create sender account if not exists
    const sender_account = types.Account{
        .address = sender_address,
        .nonce = 0,
        .role = 2, // Writer role
    };
    try zeicoin.saveAccount(sender_address, sender_account);

    // Create test invocation
    var test_tx = types.Transaction{
        .type = .invoke,
        .sender = sender_address,
        .sender_public_key = test_sender_wallet.public_key,
        .recipient = std.mem.zeroes(types.Address),
        .payload = "test_invocation",
        .nonce = sender_account.nonce,
        .timestamp = @intCast(util.getTime()),
        .signature = std.mem.zeroes(types.Signature),
        .sender_cert = std.mem.zeroes([64]u8),
    };

    // Sign
    const tx_hash = test_tx.hash();
    test_tx.signature = try test_sender_wallet.signTransaction(tx_hash);

    // Add to mempool
    zeicoin.addTransaction(test_tx) catch |err| {
        print("[ERROR] Failed to add transaction: {}\n", .{err});
        const error_msg = "ERROR: Transaction validation failed";
        try connection.stream.writeAll(error_msg);
        return;
    };

    _ = transaction_count.fetchAdd(1, .monotonic);
    print("[SUCCESS] Valid transaction #{} added to mempool successfully!\n", .{transaction_count.load(.monotonic)});

    const success_msg = "TRANSACTION_ACCEPTED_AND_VALID";
    try connection.stream.writeAll(success_msg);
}

// handleWalletFunding removed in Phase 5
// handleBalanceCheck removed in Phase 5

fn handleNonceCheck(allocator: std.mem.Allocator, connection: net.Server.Connection, zeicoin: *zeicoin_main.ZeiCoin, message: []const u8) !void {
    // Parse GET_NONCE:address message
    const prefix = "GET_NONCE:";
    if (!std.mem.startsWith(u8, message, prefix)) return;

    const address_hex = message[prefix.len..];
    print("[INFO] Nonce check for address: {s}\n", .{address_hex});

    // Parse hex address
    var client_address: types.Address = undefined;
    _ = std.fmt.hexToBytes(&client_address, address_hex) catch |err| {
        print("[ERROR] Failed to parse hex address: {}\n", .{err});
        const error_msg = "ERROR: Invalid address format";
        try connection.stream.writeAll(error_msg);
        return;
    };

    // Get account nonce (via ZeiCoin wrapper)
    const account = zeicoin.getAccount(client_address) catch |err| {
        print("[WARN] Account not found: {}, returning nonce 0\n", .{err});
        const error_msg = "NONCE:0";
        try connection.stream.writeAll(error_msg);
        return;
    };

    const current_nonce = account.nextNonce();
    const response = try std.fmt.allocPrint(allocator, "NONCE:{}", .{current_nonce});
    defer allocator.free(response);

    try connection.stream.writeAll(response);
    print("[INFO] Sent nonce: {} for {s}\n", .{ current_nonce, address_hex[0..16] });
}

fn handleClientTransaction(allocator: std.mem.Allocator, connection: net.Server.Connection, zeicoin: *zeicoin_main.ZeiCoin, message: []const u8, transaction_count: *std.atomic.Value(u32)) !void {
    _ = allocator; // Unused for now
    // Parse CLIENT_TRANSACTION:type:sender:recipient:payload_hex:timestamp:nonce:sig:pubkey:public_key
    const prefix = "CLIENT_TRANSACTION:";
    if (!std.mem.startsWith(u8, message, prefix)) return;

    const data = message[prefix.len..];
    logMessage("[INFO] Processing client transaction: {s}", .{data});

    // Parse CLIENT_TRANSACTION:type:sender:recipient:amount:fee:payload_hex:timestamp:nonce:sig:pubkey
    var parts = std.mem.splitScalar(u8, data, ':');

    // 1. Type
    const type_str = parts.next() orelse {
        const error_msg = "ERROR: Missing transaction type";
        try connection.stream.writeAll(error_msg);
        return;
    };

    // 2. Sender
    const sender_hex = parts.next() orelse {
        const error_msg = "ERROR: Missing sender address";
        try connection.stream.writeAll(error_msg);
        return;
    };

    // 3. Recipient
    const recipient_hex = parts.next() orelse {
        const error_msg = "ERROR: Missing recipient address";
        try connection.stream.writeAll(error_msg);
        return;
    };

    // 4. Payload (Hex)
    const payload_hex = parts.next() orelse {
        const error_msg = "ERROR: Missing payload";
        try connection.stream.writeAll(error_msg);
        return;
    };

    // 5. Timestamp
    const timestamp_str = parts.next() orelse {
        const error_msg = "ERROR: Missing timestamp";
        try connection.stream.writeAll(error_msg);
        return;
    };

    // 6. Nonce
    const nonce_str = parts.next() orelse {
        const error_msg = "ERROR: Missing nonce";
        try connection.stream.writeAll(error_msg);
        return;
    };

    // 7. Signature
    const signature_hex = parts.next() orelse {
        const error_msg = "ERROR: Missing signature";
        try connection.stream.writeAll(error_msg);
        return;
    };

    // 8. Public Key
    const public_key_hex = parts.next() orelse {
        const error_msg = "ERROR: Missing public key";
        try connection.stream.writeAll(error_msg);
        return;
    };

    // Parse Type
    const tx_type_int = std.fmt.parseInt(u8, type_str, 10) catch {
        const error_msg = "ERROR: Invalid transaction type format";
        try connection.stream.writeAll(error_msg);
        return;
    };
    const tx_type: types.TransactionType = @enumFromInt(tx_type_int);

    // Parse sender address
    var sender_address: types.Address = undefined;
    _ = std.fmt.hexToBytes(&sender_address, sender_hex) catch {
        const error_msg = "ERROR: Invalid sender address format";
        try connection.stream.writeAll(error_msg);
        return;
    };

    // Parse recipient address
    var recipient_address: types.Address = undefined;
    _ = std.fmt.hexToBytes(&recipient_address, recipient_hex) catch {
        const error_msg = "ERROR: Invalid recipient address format";
        try connection.stream.writeAll(error_msg);
        return;
    };

    // Parse timestamp and nonce
    const timestamp = std.fmt.parseInt(u64, timestamp_str, 10) catch {
        const error_msg = "ERROR: Invalid timestamp format";
        try connection.stream.writeAll(error_msg);
        return;
    };
    const nonce = std.fmt.parseInt(u64, nonce_str, 10) catch {
        const error_msg = "ERROR: Invalid nonce format";
        try connection.stream.writeAll(error_msg);
        return;
    };

    // Parse Payload
    // Allocating payload on heap - TODO: manage lifetime better (mempool/block cleanup)
    // For now, we rely on OS reclaiming memory on exit or leaky behavior for PoC
    const payload_bytes = zeicoin.allocator.alloc(u8, payload_hex.len / 2) catch {
        const error_msg = "ERROR: Server Out of Memory";
        try connection.stream.writeAll(error_msg);
        return;
    };
    _ = std.fmt.hexToBytes(payload_bytes, payload_hex) catch {
        const error_msg = "ERROR: Invalid payload hex";
        try connection.stream.writeAll(error_msg);
        return;
    };

    // Parse signature
    var signature: types.Signature = undefined;
    _ = std.fmt.hexToBytes(&signature, signature_hex) catch {
        const error_msg = "ERROR: Invalid signature format";
        try connection.stream.writeAll(error_msg);
        return;
    };

    // Parse public key
    var public_key: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&public_key, public_key_hex) catch {
        const error_msg = "ERROR: Invalid public key format";
        try connection.stream.writeAll(error_msg);
        return;
    };

    // Get sender account (via MPL wrapper to handle auto-creation)
    const sender_account = zeicoin.getAccount(sender_address) catch |err| {
        print("[ERROR] Sender account not found: {}\n", .{err});
        const error_msg = "ERROR: Sender account not found";
        try connection.stream.writeAll(error_msg);
        return;
    };

    // Check nonce - Loose check for Mempool (allow pending transactions)
    if (nonce < sender_account.nextNonce()) {
        logMessage("[ERROR] Invalid nonce: expected >= {}, got {}", .{ sender_account.nextNonce(), nonce });
        const error_msg = "ERROR: Invalid nonce (replay)";
        try connection.stream.writeAll(error_msg);
        return;
    }

    const client_tx = types.Transaction{
        .type = tx_type,
        .sender = sender_address,
        .sender_public_key = public_key,
        .recipient = recipient_address,
        .payload = payload_bytes,
        .nonce = nonce,
        .timestamp = timestamp,
        .signature = signature,
        .sender_cert = std.mem.zeroes([64]u8), // TODO: Client protocol needs to send this
    };

    logMessage("[INFO] Client transaction from {s} to {s}", .{ std.fmt.fmtSliceHexLower(sender_address[0..8]), std.fmt.fmtSliceHexLower(recipient_address[0..8]) });

    // Add to mempool (Parallel or Sync)
    if (zeicoin.ingestion_pool) |pool| {
        logMessage("[INFO] Submitting to Ingestion Pool...", .{});

        const task = @import("ingestion/pool.zig").VerificationTask{
            .raw_tx = client_tx,
            .connection = connection,
        };

        pool.submit(task) catch |err| {
            logMessage("[ERROR] Ingestion Pool Queue Full: {}", .{err});
            const error_msg = "ERROR: Server Busy (Queue Full)";
            try connection.stream.writeAll(error_msg);
            return;
        };

        // We don't send success message here, worker sends it.
        // We don't increment transaction_count here, worker should?
        // Or we just increment it here as "received"?
        // Let's increment here.
        _ = transaction_count.fetchAdd(1, .monotonic);
    } else {
        // Fallback to Sync
        zeicoin.addTransaction(client_tx) catch |err| {
            logMessage("[ERROR] Failed to add client transaction: {}", .{err});
            const error_msg = "ERROR: Client transaction rejected";
            try connection.stream.writeAll(error_msg);
            return;
        };

        _ = transaction_count.fetchAdd(1, .monotonic);
        print("[INFO] Client transaction #{} added to mempool\n", .{transaction_count.load(.monotonic)});

        logMessage("[INFO] About to send success response to client", .{});
        const success_msg = "CLIENT_TRANSACTION_ACCEPTED";
        try connection.stream.writeAll(success_msg);
        logMessage("[INFO] Sent CLIENT_TRANSACTION_ACCEPTED to client", .{});
    }

    // Zen broadcasting: transaction flows to all connected peers like ripples
    if (zeicoin.network) |network| {
        network.*.broadcastTransaction(client_tx);
        const peer_count = network.*.peers.items.len;
        print("[INFO] Transaction flows to {} peers\n", .{peer_count});
    }
}

fn sendNewBlockNotification(connection: net.Server.Connection, zeicoin: *zeicoin_main.ZeiCoin) !void {
    const height = zeicoin.getHeight() catch 0;

    var block_buffer: [256]u8 = undefined;
    const block_msg = try std.fmt.bufPrint(&block_buffer, "NEW_BLOCK:HEIGHT={},MINED=true", .{height});

    try connection.stream.writeAll(block_msg);
    print("[INFO] Broadcasted new block notification: {s}\n", .{block_msg});
}

// --- Raft Handlers (Stubs) ---

fn handleRaftVote(connection: net.Server.Connection, zeicoin: *zeicoin_main.ZeiCoin, message: []const u8) !void {
    _ = connection;
    _ = zeicoin;
    _ = message;
    // TODO: Parse and forward to raft_impl.handleRequestVote
    print("[INFO] Received Raft Vote Request (Not Implemented)\n", .{});
}

fn handleRaftAppend(connection: net.Server.Connection, zeicoin: *zeicoin_main.ZeiCoin, message: []const u8) !void {
    _ = connection;
    _ = zeicoin;
    _ = message;
    // TODO: Parse and forward to raft_impl.handleAppendEntries
    print("[INFO] Received Raft Append Request (Not Implemented)\n", .{});
}
