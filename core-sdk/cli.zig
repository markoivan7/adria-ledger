// cli.zig - Adria Permissioned Ledger (MPL) CLI
// Simple CLI tool for everyday MPL operations

const std = @import("std");
const print = std.debug.print;
const net = std.net;
const Thread = std.Thread;

const types = @import("common/types.zig");
const wallet = @import("crypto/wallet.zig");
const db = @import("execution/db.zig");
const util = @import("common/util.zig");
const hydrate = @import("tools/hydrate.zig");

// Helper function to format Adria amounts with proper decimal places
// Helper function to format ZEI amounts removed in Phase 5

const CLIError = error{
    InvalidCommand,
    InvalidArguments,
    WalletNotFound,
    NetworkError,
    InsufficientArguments,
    ConnectionTimeout,
    ConnectionFailed,
    ThreadSpawnFailed,
    ReadTimeout,
    ReadFailed,
};

// Auto-detect server IP by checking common interfaces
fn autoDetectServerIP(allocator: std.mem.Allocator) ?[]const u8 {
    // Try to get local IP from hostname command
    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{ "hostname", "-I" },
    }) catch return null;

    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    if (result.term.Exited == 0 and result.stdout.len > 0) {
        // Parse first IP from output
        var it = std.mem.splitScalar(u8, result.stdout, ' ');
        if (it.next()) |first_ip| {
            const trimmed = std.mem.trim(u8, first_ip, " \t\n");
            if (trimmed.len > 0) {
                return allocator.dupe(u8, trimmed) catch null;
            }
        }
    }

    return null;
}

fn getServerIP(allocator: std.mem.Allocator) ![]const u8 {
    // 1. Try environment variable first
    if (std.process.getEnvVarOwned(allocator, "ADRIA_SERVER")) |server_ip| {
        return server_ip;
    } else |_| {}

    // 2. Try localhost explicitly (Optimized for Local Dev)
    // Check if local server is running before trying network auto-detection
    if (testServerConnection("127.0.0.1")) {
        print("[INFO] Found local APL server at 127.0.0.1\n", .{});
        return allocator.dupe(u8, "127.0.0.1");
    }

    // 3. Try auto-detection with connection test
    if (autoDetectServerIP(allocator)) |detected_ip| {
        defer allocator.free(detected_ip);

        // Test if detected IP actually has an Adria server
        if (testServerConnection(detected_ip)) {
            print("[INFO] Auto-detected server IP: {s}\n", .{detected_ip});
            return allocator.dupe(u8, detected_ip);
        } else {
            print("[INFO] Auto-detected {s} but no APL server found\n", .{detected_ip});
        }
    }

    // 4. Try bootstrap servers from types.zig
    for (types.BOOTSTRAP_NODES) |bootstrap_addr| {
        // Parse IP from "ip:port" format
        var it = std.mem.splitScalar(u8, bootstrap_addr, ':');
        if (it.next()) |ip_str| {
            if (testServerConnection(ip_str)) {
                print("[INFO] Found APL server at bootstrap node: {s}\n", .{ip_str});
                return allocator.dupe(u8, ip_str);
            }
        }
    }

    // 5. Final fallback (return localhost even if test failed, to show proper error later)
    print("[INFO] Using localhost fallback (set ADRIA_SERVER to override)\n", .{});
    return allocator.dupe(u8, "127.0.0.1");
}

// Connect with 5 second timeout using thread-based approach
fn connectWithTimeout(address: net.Address) !net.Stream {
    const ConnectResult = struct {
        result: ?net.Stream = null,
        error_occurred: bool = false,
        completed: bool = false,
    };

    var connect_result = ConnectResult{};

    // Spawn thread for connection attempt
    const connect_thread = std.Thread.spawn(.{}, struct {
        fn connectWorker(addr: net.Address, result: *ConnectResult) void {
            result.result = net.tcpConnectToAddress(addr) catch {
                result.error_occurred = true;
                result.completed = true;
                return;
            };
            result.completed = true;
        }
    }.connectWorker, .{ address, &connect_result }) catch {
        return error.ThreadSpawnFailed;
    };

    // Wait for completion or timeout (5 seconds)
    const timeout_ns = 5 * std.time.ns_per_s;
    const start_time = std.time.nanoTimestamp();

    while (!connect_result.completed) {
        const elapsed = std.time.nanoTimestamp() - start_time;
        if (elapsed > timeout_ns) {
            // Timeout - the thread will continue but we abandon it
            return error.ConnectionTimeout;
        }
        std.time.sleep(10 * std.time.ns_per_ms); // Check every 10ms
    }

    connect_thread.join();

    if (connect_result.error_occurred) {
        return error.ConnectionFailed;
    }

    return connect_result.result orelse error.ConnectionFailed;
}

// Read with 5 second timeout using thread-based approach
fn readWithTimeout(stream: net.Stream, buffer: []u8) !usize {
    const ReadResult = struct {
        bytes_read: usize = 0,
        error_occurred: bool = false,
        completed: bool = false,
    };

    var read_result = ReadResult{};

    // Spawn thread for read attempt
    const read_thread = std.Thread.spawn(.{}, struct {
        fn readWorker(s: net.Stream, buf: []u8, result: *ReadResult) void {
            result.bytes_read = s.read(buf) catch {
                result.error_occurred = true;
                result.completed = true;
                return;
            };
            result.completed = true;
        }
    }.readWorker, .{ stream, buffer, &read_result }) catch {
        return error.ThreadSpawnFailed;
    };

    // Wait for completion or timeout (5 seconds)
    const timeout_ns = 5 * std.time.ns_per_s;
    const start_time = std.time.nanoTimestamp();

    while (!read_result.completed) {
        const elapsed = std.time.nanoTimestamp() - start_time;
        if (elapsed > timeout_ns) {
            // Timeout - the thread will continue but we abandon it
            return error.ReadTimeout;
        }
        std.time.sleep(10 * std.time.ns_per_ms); // Check every 10ms
    }

    read_thread.join();

    if (read_result.error_occurred) {
        return error.ReadFailed;
    }

    return read_result.bytes_read;
}

// Test if a server IP actually has Adria running on port 10802
fn testServerConnection(ip: []const u8) bool {
    const address = net.Address.parseIp4(ip, 10802) catch return false;

    // Quick connection test
    var stream = connectWithTimeout(address) catch return false;
    defer stream.close();

    return true;
}

const Command = enum {
    wallet,
    status,
    address,
    ledger,
    document,
    invoke,
    hydrate,
    help,
};

const DocumentSubcommand = enum {
    store,
    retrieve,
};

const LedgerSubcommand = enum {
    record,
    query,
};

const WalletSubcommand = enum {
    create,
    load,
    list,
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) {
        printHelp();
        return;
    }

    const command_str = args[1];
    const command = std.meta.stringToEnum(Command, command_str) orelse {
        print("[ERROR] Unknown command: {s}\n", .{command_str});
        print("[INFO] Use 'apl help' to see available commands\n", .{});
        printHelp();
        return;
    };

    switch (command) {
        .wallet => try handleWalletCommand(allocator, args[2..]),
        .status => try handleStatusCommand(allocator, args[2..]),
        .address => try handleAddressCommand(allocator, args[2..]),
        .ledger => try handleLedgerCommand(allocator, args[2..]),
        .document => try handleDocumentCommand(allocator, args[2..]),
        .invoke => try handleInvokeCommand(allocator, args[2..]),
        .hydrate => try handleHydrateCommand(allocator, args[2..]),
        .help => printHelp(),
    }
}

fn handleWalletCommand(allocator: std.mem.Allocator, args: [][:0]u8) !void {
    if (args.len < 1) {
        print("[ERROR] Wallet subcommand required\n", .{});
        print("Usage: apl wallet <create|load|list> [name]\n", .{});
        return;
    }

    const subcommand_str = args[0];
    const subcommand = std.meta.stringToEnum(WalletSubcommand, subcommand_str) orelse {
        print("[ERROR] Unknown wallet subcommand: {s}\n", .{subcommand_str});
        return;
    };

    switch (subcommand) {
        .create => try createWallet(allocator, args[1..]),
        .load => try loadWallet(allocator, args[1..]),
        .list => try listWallets(allocator),
    }
}

fn createWallet(allocator: std.mem.Allocator, args: [][:0]u8) !void {
    const wallet_name = if (args.len > 0) args[0] else "default";

    print("[INFO] Creating new APL wallet: {s}\n", .{wallet_name});

    // Initialize database
    var database = try db.Database.init(allocator, "apl_data");
    defer database.deinit();

    // Check if wallet already exists
    if (database.walletExists(wallet_name)) {
        print("[ERROR] Wallet '{s}' already exists\n", .{wallet_name});
        return;
    }

    // Create new wallet
    var zen_wallet = wallet.Wallet.init(allocator);
    defer zen_wallet.deinit();

    try zen_wallet.createNew();

    // Get wallet path and save
    const wallet_path = try database.getWalletPath(wallet_name);
    defer allocator.free(wallet_path);

    const password = "zen"; // Simple password for demo - could be made configurable
    try zen_wallet.saveToFile(wallet_path, password);

    const address = zen_wallet.getAddress() orelse return error.WalletCreationFailed;
    print("[SUCCESS] Wallet '{s}' created successfully!\n", .{wallet_name});
    print("[INFO] Address: {s}\n", .{std.fmt.fmtSliceHexLower(&address)});
}

fn loadWallet(allocator: std.mem.Allocator, args: [][:0]u8) !void {
    const wallet_name = if (args.len > 0) args[0] else "default";

    print("[INFO] Loading APL wallet: {s}\n", .{wallet_name});

    // Initialize database
    var database = try db.Database.init(allocator, "apl_data");
    defer database.deinit();

    if (!database.walletExists(wallet_name)) {
        print("[ERROR] Wallet '{s}' not found\n", .{wallet_name});
        print("[INFO] Use 'apl wallet create {s}' to create it\n", .{wallet_name});
        return;
    }

    // Load wallet
    var zen_wallet = wallet.Wallet.init(allocator);
    defer zen_wallet.deinit();

    const wallet_path = try database.getWalletPath(wallet_name);
    defer allocator.free(wallet_path);

    const password = "zen";
    try zen_wallet.loadFromFile(wallet_path, password);

    const address = zen_wallet.getAddress() orelse return error.WalletLoadFailed;
    print("[SUCCESS] Wallet '{s}' loaded successfully!\n", .{wallet_name});
    print("[INFO] Address: {s}\n", .{std.fmt.fmtSliceHexLower(&address)});
}

fn listWallets(allocator: std.mem.Allocator) !void {
    _ = allocator;
    print("[INFO] Available APL wallets:\n", .{});

    var wallets_dir = std.fs.cwd().openDir("apl_data/wallets", .{ .iterate = true }) catch |err| {
        if (err == error.FileNotFound) {
            print("   No wallets found. Use 'apl wallet create' to create one.\n", .{});
            return;
        }
        return err;
    };
    defer wallets_dir.close();

    var iterator = wallets_dir.iterate();
    var wallet_count: u32 = 0;

    while (try iterator.next()) |entry| {
        if (entry.kind == .file and std.mem.endsWith(u8, entry.name, ".wallet")) {
            const wallet_name = entry.name[0 .. entry.name.len - 7]; // Remove .wallet extension
            print("   - {s}\n", .{wallet_name});
            wallet_count += 1;
        }
    }

    if (wallet_count == 0) {
        print("   No wallets found. Use 'apl wallet create' to create one.\n", .{});
    } else {
        print("[INFO] Use 'apl wallet load <name>' to load a wallet\n", .{});
    }
}

// handleBalanceCommand removed in Phase 5
// handleSendCommand removed in Phase 5

fn handleStatusCommand(allocator: std.mem.Allocator, args: [][:0]u8) !void {
    _ = args;

    print("[INFO] APL Network Status:\n", .{});

    // Connect to server
    const server_ip = try getServerIP(allocator);
    defer allocator.free(server_ip);

    const address = net.Address.parseIp4(server_ip, 10802) catch {
        print("[ERROR] Invalid server address\n", .{});
        return;
    };

    const connection = connectWithTimeout(address) catch |err| {
        switch (err) {
            error.ConnectionTimeout => {
                print("[ERROR] Connection timeout to APL server at {s}:10802 (5s)\n", .{server_ip});
                return;
            },
            else => {
                print("[ERROR] Cannot connect to APL server at {s}:10802\n", .{server_ip});
                print("[INFO] Make sure the server is running\n", .{});
                return;
            },
        }
    };
    defer connection.close();

    // Send status request
    try connection.writeAll("BLOCKCHAIN_STATUS\n");

    // Read response with timeout
    var buffer: [1024]u8 = undefined;
    const bytes_read = readWithTimeout(connection, &buffer) catch |err| {
        switch (err) {
            error.ReadTimeout => {
                print("[ERROR] Server response timeout (5s)\n", .{});
                return;
            },
            else => {
                print("[ERROR] Failed to read server response\n", .{});
                return;
            },
        }
    };
    const response = buffer[0..bytes_read];

    print("[INFO] Server: {s}:10802\n", .{server_ip});
    print("[INFO] Status: {s}\n", .{response});
}

fn handleAddressCommand(allocator: std.mem.Allocator, args: [][:0]u8) !void {
    const wallet_name = if (args.len > 0) args[0] else "default";

    // Load wallet
    const zen_wallet = loadWalletForOperation(allocator, wallet_name) catch |err| {
        switch (err) {
            error.WalletNotFound => {
                // Error message already printed in loadWalletForOperation
                return;
            },
            else => return err,
        }
    };
    defer {
        zen_wallet.deinit();
        allocator.destroy(zen_wallet);
    }

    const address = zen_wallet.getAddress() orelse return error.WalletNotLoaded;

    print("[INFO] Wallet '{s}' address:\n", .{wallet_name});
    print("   {s}\n", .{std.fmt.fmtSliceHexLower(&address)});
    print("[INFO] Short address: {s}\n", .{std.fmt.fmtSliceHexLower(address[0..16])});
}

// handleFundCommand removed in Phase 5

fn handleLedgerCommand(allocator: std.mem.Allocator, args: [][:0]u8) !void {
    if (args.len < 1) {
        print("[ERROR] Ledger subcommand required\n", .{});
        print("Usage: apl ledger <record|query> [args...]\n", .{});
        return;
    }

    const subcommand_str = args[0];
    const subcommand = std.meta.stringToEnum(LedgerSubcommand, subcommand_str) orelse {
        print("[ERROR] Unknown ledger subcommand: {s}\n", .{subcommand_str});
        return;
    };

    switch (subcommand) {
        .record => {
            // Usage: record key value [wallet_name]
            if (args.len < 3) {
                print("Usage: apl ledger record <key> <value> [wallet_name]\n", .{});
                return;
            }
            const key_str = args[1];
            const value_str = args[2];
            const wallet_name = if (args.len > 3) args[3] else "default";

            // Load wallet
            const zen_wallet = loadWalletForOperation(allocator, wallet_name) catch |err| {
                if (err == error.WalletNotFound) return;
                return err;
            };
            defer {
                zen_wallet.deinit();
                allocator.destroy(zen_wallet);
            }

            const sender_address = zen_wallet.getAddress() orelse return error.WalletNotLoaded;
            const sender_public_key = zen_wallet.public_key.?; // Wallet loaded means public key is present

            // Prepare payload: "general_ledger|record_entry|key|value"
            const payload = try std.fmt.allocPrint(allocator, "general_ledger|record_entry|{s}|{s}", .{ key_str, value_str });
            defer allocator.free(payload);

            print("[INFO] Recording entry: {s} -> {s}\n", .{ key_str, value_str });

            invokeChaincode(allocator, zen_wallet, sender_address, sender_public_key, payload) catch |err| {
                print("[ERROR] Failed to invoke chaincode: {}\n", .{err});
            };
        },
        .query => {
            // Usage: query key [data_dir]
            if (args.len < 2) {
                print("Usage: apl ledger query <key> [data_dir]\n", .{});
                return;
            }
            const key_str = args[1];
            const data_dir = if (args.len > 2) args[2] else "apl_data";

            // Initialize DB (ReadOnly-ish)
            var database = db.Database.init(allocator, data_dir) catch |err| {
                print("[ERROR] Failed to open database at '{s}': {}\n", .{ data_dir, err });
                return;
            };
            defer database.deinit();

            if (try database.get(key_str)) |val| {
                defer allocator.free(val);
                std.io.getStdOut().writer().print("{s}\n", .{val}) catch {};
            } else {
                print("[ERROR] Key not found: {s}\n", .{key_str});
                // We return success exit code but print Error?
                // Scripts might grep output.
            }
        },
    }
}

fn handleDocumentCommand(allocator: std.mem.Allocator, args: [][:0]u8) !void {
    if (args.len < 1) {
        print("[ERROR] Document subcommand required\n", .{});
        print("Usage: apl document <store|retrieve> [args...]\n", .{});
        return;
    }

    const subcommand_str = args[0];
    const subcommand = std.meta.stringToEnum(DocumentSubcommand, subcommand_str) orelse {
        print("[ERROR] Unknown document subcommand: {s}\n", .{subcommand_str});
        return;
    };

    switch (subcommand) {
        .store => {
            // Usage: apl document store <collection> <id> <filename> [wallet]
            if (args.len < 4) {
                print("Usage: apl document store <collection> <id> <filename> [wallet]\n", .{});
                return;
            }
            const collection = args[1];
            const id = args[2];
            const filename = args[3];
            const wallet_name = if (args.len > 4) args[4] else "default";

            // Read file
            const file = std.fs.cwd().openFile(filename, .{}) catch |err| {
                print("[ERROR] Failed to open file '{s}': {}\n", .{ filename, err });
                return;
            };
            defer file.close();

            const file_size = try file.getEndPos();
            if (file_size > 60 * 1024) {
                print("[ERROR] File too large (max 60KB)\n", .{});
                return;
            }

            const buffer = try allocator.alloc(u8, file_size);
            defer allocator.free(buffer);
            _ = try file.readAll(buffer);

            // Load wallet
            const zen_wallet = loadWalletForOperation(allocator, wallet_name) catch |err| {
                if (err == error.WalletNotFound) return;
                return err;
            };
            defer {
                zen_wallet.deinit();
                allocator.destroy(zen_wallet);
            }

            const sender_address = zen_wallet.getAddress() orelse return error.WalletNotLoaded;
            const sender_public_key = zen_wallet.public_key.?;

            // Payload: document_store|store|collection|id|content
            const payload = try std.fmt.allocPrint(allocator, "document_store|store|{s}|{s}|{s}", .{ collection, id, buffer });
            defer allocator.free(payload);

            print("[INFO] Storing document '{s}' in collection '{s}'...\n", .{ id, collection });
            invokeChaincode(allocator, zen_wallet, sender_address, sender_public_key, payload) catch |err| {
                print("[ERROR] Failed to invoke chaincode: {}\n", .{err});
            };
        },
        .retrieve => {
            if (args.len < 3) {
                print("Usage: apl document retrieve <collection> <id> [data_dir]\n", .{});
                return;
            }
            const collection = args[1];
            const id = args[2];
            const data_dir = if (args.len > 3) args[3] else "apl_data";

            // Construct Key
            const raw_key = try std.fmt.allocPrint(allocator, "DOC_{s}_{s}", .{ collection, id });
            defer allocator.free(raw_key);

            // Access DB
            var database = db.Database.init(allocator, data_dir) catch |err| {
                print("[ERROR] Failed to open database at '{s}': {}\n", .{ data_dir, err });
                return;
            };
            defer database.deinit();

            if (try database.get(raw_key)) |val| {
                defer allocator.free(val);
                std.io.getStdOut().writer().print("{s}\n", .{val}) catch {};
            } else {
                print("[ERROR] Document not found (Key: {s})\n", .{raw_key});
            }
        },
    }
}

fn handleInvokeCommand(allocator: std.mem.Allocator, args: [][:0]u8) !void {
    if (args.len < 1) {
        print("[ERROR] Payload required\n", .{});
        print("Usage: apl invoke <payload_string> [wallet_name]\n", .{});
        return;
    }

    const payload = args[0];
    const wallet_name = if (args.len > 1) args[1] else "default";

    // Load wallet
    const zen_wallet = loadWalletForOperation(allocator, wallet_name) catch |err| {
        // Propagate error to main so exit code is non-zero
        // if (err == error.WalletNotFound) return;
        return err;
    };
    defer {
        zen_wallet.deinit();
        allocator.destroy(zen_wallet);
    }

    const sender_address = zen_wallet.getAddress() orelse return error.WalletNotLoaded;
    const sender_public_key = zen_wallet.public_key.?;

    print("[INFO] Invoking Chaincode with payload: {s}\n", .{payload});

    // Propagate error to main so exit code is non-zero
    try invokeChaincode(allocator, zen_wallet, sender_address, sender_public_key, payload);
}

fn handleHydrateCommand(allocator: std.mem.Allocator, args: [][:0]u8) !void {
    var verify_all = false;
    for (args) |arg| {
        if (std.mem.eql(u8, arg, "--verify-all")) {
            verify_all = true;
        }
    }

    // Default data dir
    const data_dir = "apl_data";

    var tool = hydrate.HydrateTool.init(allocator, data_dir, verify_all);
    try tool.execute();
}

// Helper functions

fn loadWalletForOperation(allocator: std.mem.Allocator, wallet_name: []const u8) !*wallet.Wallet {
    // Initialize database
    var database = try db.Database.init(allocator, "apl_data");
    defer database.deinit();

    if (!database.walletExists(wallet_name)) {
        print("[ERROR] Wallet '{s}' not found\n", .{wallet_name});
        print("[INFO] Use 'apl wallet create {s}' to create it\n", .{wallet_name});
        return error.WalletNotFound;
    }

    // Create wallet
    const zen_wallet = try allocator.create(wallet.Wallet);
    zen_wallet.* = wallet.Wallet.init(allocator);
    errdefer {
        zen_wallet.deinit();
        allocator.destroy(zen_wallet);
    }

    // Load wallet
    const wallet_path = try database.getWalletPath(wallet_name);
    defer allocator.free(wallet_path);

    // Use appropriate password based on wallet name
    const password = if (std.mem.eql(u8, wallet_name, "server_miner")) "zen_miner" else "zen";
    zen_wallet.loadFromFile(wallet_path, password) catch {
        print("[ERROR] Failed to load wallet '{s}'\n", .{wallet_name});
        return error.WalletNotFound;
    };

    return zen_wallet;
}

fn invokeChaincode(allocator: std.mem.Allocator, zen_wallet: *wallet.Wallet, sender_address: types.Address, sender_public_key: [32]u8, payload: []const u8) !void {
    // Connect to server
    const server_ip = try getServerIP(allocator);
    defer allocator.free(server_ip);

    const server_address = net.Address.parseIp4(server_ip, 10802) catch {
        return error.NetworkError;
    };

    const connection = connectWithTimeout(server_address) catch |err| {
        switch (err) {
            error.ConnectionTimeout => {
                print("[ERROR] Connection timeout to APL server (5s)\n", .{});
                return error.NetworkError;
            },
            else => {
                return error.NetworkError;
            },
        }
    };
    defer connection.close();

    // Get current nonce
    const nonce_request = try std.fmt.allocPrint(allocator, "GET_NONCE:{s}", .{std.fmt.fmtSliceHexLower(&sender_address)});

    defer allocator.free(nonce_request);
    try connection.writeAll(nonce_request);
    try connection.writeAll("\n");

    var nonce_buffer: [1024]u8 = undefined;
    const nonce_bytes_read = readWithTimeout(connection, &nonce_buffer) catch {
        print("[ERROR] Failed to read nonce\n", .{});
        return error.NetworkError;
    };
    const nonce_response = nonce_buffer[0..nonce_bytes_read];
    const current_nonce = if (std.mem.startsWith(u8, nonce_response, "NONCE:"))
        std.fmt.parseInt(u64, nonce_response[6..], 10) catch 0
    else
        0;

    // Create transaction
    // Create transaction
    const timestamp = @as(u64, @intCast(util.getTime()));
    var transaction = types.Transaction{
        .type = .invoke,
        .sender = sender_address,
        .sender_public_key = sender_public_key,
        .recipient = std.mem.zeroes(types.Address),
        .payload = payload,
        .nonce = current_nonce,
        .timestamp = timestamp,
        .signature = std.mem.zeroes(types.Signature),
        .sender_cert = std.mem.zeroes([64]u8),
    };

    // Sign transaction
    const tx_hash = transaction.hash();
    transaction.signature = zen_wallet.signTransaction(&tx_hash) catch {
        print("[ERROR] Failed to sign transaction\n", .{});
        return error.NetworkError;
    };

    // Payload to Hex
    const payload_hex = try std.fmt.allocPrint(allocator, "{s}", .{std.fmt.fmtSliceHexLower(payload)});
    defer allocator.free(payload_hex);

    // Send transaction to server
    // Format: CLIENT_TRANSACTION:type:sender:recipient:payload_hex:timestamp:nonce:sig:pubkey
    const tx_message = try std.fmt.allocPrint(allocator, "CLIENT_TRANSACTION:{d}:{s}:{s}:{s}:{}:{}:{s}:{s}", .{
        @intFromEnum(transaction.type),
        std.fmt.fmtSliceHexLower(&sender_address),
        std.fmt.fmtSliceHexLower(&transaction.recipient),
        payload_hex,
        transaction.timestamp,
        transaction.nonce,
        std.fmt.fmtSliceHexLower(&transaction.signature),
        std.fmt.fmtSliceHexLower(&sender_public_key),
    });
    defer allocator.free(tx_message);

    try connection.writeAll(tx_message);
    try connection.writeAll("\n");

    // Read response
    var buffer: [1024]u8 = undefined;
    const bytes_read = readWithTimeout(connection, &buffer) catch {
        print("[ERROR] Failed to read response\n", .{});
        return error.TransactionFailed;
    };
    const response = buffer[0..bytes_read];

    if (!std.mem.startsWith(u8, response, "CLIENT_TRANSACTION_ACCEPTED")) {
        print("[ERROR] Invocation failed: {s}\n", .{response});
        return error.TransactionFailed;
    }

    print("[SUCCESS] Chaincode invocation submitted successfully!\n", .{});
}

fn printZeiBanner() void {
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
    print("║               Adria Permissioned Ledger (APL) CLI                    ║\n", .{});
    print("║                                                                      ║\n", .{});
    print("╚══════════════════════════════════════════════════════════════════════╝\n", .{});
    print("\n", .{});
}

fn printHelp() void {
    printZeiBanner();
    print("WALLET COMMANDS:\n", .{});
    print("  apl wallet create [name]     Create new wallet\n", .{});
    print("  apl wallet load [name]       Load existing wallet\n", .{});
    print("  apl wallet list              List all wallets\n\n", .{});
    print("LEDGER COMMANDS:\n", .{});
    print("  apl ledger record <key> <val> Record generic data\n", .{});
    print("  apl ledger query <key>       Query generic data\n\n", .{});
    print("DOCUMENT COMMANDS:\n", .{});
    print("  apl document store <col> <id> <file> Store document from file\n", .{});
    print("  apl document retrieve <col> <id>     Retrieve document\n\n", .{});
    print("AUDIT COMMANDS:\n", .{});
    print("  apl hydrate [--verify-all]   Reconstruct state from chain history\n\n", .{});
    print("NETWORK COMMANDS:\n", .{});
    print("  apl status                   Show network status\n", .{});
    print("  apl address [wallet]         Show wallet address\n\n", .{});
    print("EXAMPLES:\n", .{});
    print("  apl wallet create alice      # Create wallet named 'alice'\n", .{});
    print("  apl ledger record invoice:1 \"{{...}}\" alice\n", .{});
    print("  apl status                   # Check network status\n\n", .{});
    print("ENVIRONMENT:\n", .{});
    print("  ADRIA_SERVER=ip               Set APL server IP (default: 127.0.0.1)\n\n", .{});
    print("Default wallet is 'default' if no name specified\n", .{});
}
