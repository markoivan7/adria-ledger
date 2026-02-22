// cli.zig - Adria Permissioned Ledger (MPL) CLI
// Simple CLI tool for everyday MPL operations

const std = @import("std");
const print = std.debug.print;
const net = std.net;
const Thread = std.Thread;

const types = @import("common").types;
const wallet = @import("crypto").wallet;
const db = @import("execution").db;
const util = @import("common").util;
const hydrate = @import("tools/hydrate.zig");
const config_mod = @import("config.zig");

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
    // 1. Try environment variable first (Highest Priority)
    if (std.process.getEnvVarOwned(allocator, "ADRIA_SERVER")) |server_ip| {
        return server_ip;
    } else |_| {}

    // 2. Try loading config file
    // If adria-config.json exists, we assume we want to connect to the local node defined there
    const cfg = config_mod.loadFromFile(allocator, "adria-config.json") catch config_mod.Config.default();

    // We check if we can connect to localhost:api_port
    // We construct the IP string "127.0.0.1" (or "0.0.0.0" mapped to localhost)
    // The CLI usually runs on the same machine as the server if config is present.
    // If config says "p2p_port=X, api_port=Y", we try 127.0.0.1:Y

    // Check if local server is running on configured port
    if (testServerConnection("127.0.0.1", cfg.network.api_port)) {
        // print("[INFO] Found local APL server at 127.0.0.1:{}\n", .{cfg.network.api_port});
        return allocator.dupe(u8, "127.0.0.1");
    }

    // 3. Try auto-detection with connection test (Default Port)
    if (autoDetectServerIP(allocator)) |detected_ip| {
        defer allocator.free(detected_ip);

        // Test if detected IP actually has an Adria server
        if (testServerConnection(detected_ip, 10802)) {
            print("[INFO] Auto-detected server IP: {s}\n", .{detected_ip});
            return allocator.dupe(u8, detected_ip);
        }
    }

    // 4. Try bootstrap servers from types.zig
    for (types.BOOTSTRAP_NODES) |bootstrap_addr| {
        // Parse IP from "ip:port" format
        var it = std.mem.splitScalar(u8, bootstrap_addr, ':');
        if (it.next()) |ip_str| {
            if (testServerConnection(ip_str, 10802)) {
                print("[INFO] Found APL server at bootstrap node: {s}\n", .{ip_str});
                return allocator.dupe(u8, ip_str);
            }
        }
    }

    // 5. Final fallback
    // print("[INFO] Using localhost fallback (set ADRIA_SERVER to override)\n", .{});
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

// Test if a server IP actually has Adria running on specific port
fn testServerConnection(ip: []const u8, port: u16) bool {
    const address = net.Address.parseIp4(ip, port) catch return false;

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
    governance,
    hydrate,
    nonce,
    tx,
    cert,
    pubkey,
    version,
    protocol,
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

const TxSubcommand = enum {
    sign,
    broadcast,
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
        .governance => try handleGovernanceCommand(allocator, args[2..]),
        .hydrate => try handleHydrateCommand(allocator, args[2..]),
        .nonce => try handleNonceCommand(allocator, args[2..]),
        .tx => try handleTxCommand(allocator, args[2..]),
        .cert => try handleCertCommand(allocator, args[2..]),
        .pubkey => try handlePubkeyCommand(allocator, args[2..]),
        .version => handleVersionCommand(),
        .protocol => handleProtocolCommand(),
        .help => printHelp(),
    }
}

fn handleVersionCommand() void {
    print("Engine Version: {s}\n", .{types.ENGINE_VERSION});
    print("Supported Protocol Version: {}\n", .{types.SUPPORTED_PROTOCOL_VERSION});
}

fn handleProtocolCommand() void {
    print("Supported Protocol Version: {}\n", .{types.SUPPORTED_PROTOCOL_VERSION});
}

fn handleGovernanceCommand(allocator: std.mem.Allocator, args: [][:0]u8) !void {
    if (args.len < 1) {
        print("[ERROR] Governance subcommand required\n", .{});
        print("Usage: apl governance <update|get> [args...]\n", .{});
        return;
    }

    const subcommand_str = args[0];
    if (std.mem.eql(u8, subcommand_str, "update")) {
        // Usage: apl governance update <policy.json> [wallet]
        if (args.len < 2) {
            print("Usage: apl governance update <policy.json> [wallet]\n", .{});
            return;
        }
        const filename = args[1];
        const wallet_name = if (args.len > 2) args[2] else "default";

        // Read file
        const file = std.fs.cwd().openFile(filename, .{}) catch |err| {
            print("[ERROR] Failed to open policy file '{s}': {}\n", .{ filename, err });
            return;
        };
        defer file.close();

        const file_size = try file.getEndPos();
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

        // Payload: sys_governance|update_policy|<json>
        const payload = try std.fmt.allocPrint(allocator, "sys_governance|update_policy|{s}", .{buffer});
        defer allocator.free(payload);

        print("[INFO] Submitting governance policy update...\n", .{});
        invokeChaincode(allocator, zen_wallet, sender_address, sender_public_key, payload, wallet_name) catch |err| {
            print("[ERROR] Failed to invoke chaincode: {}\n", .{err});
        };
    } else if (std.mem.eql(u8, subcommand_str, "get")) {
        // Usage: apl governance get [data_dir]
        // This is a local query. For remote, we'd need a "query" tx type or API.
        // Assuming local query for now similar to 'ledger query'.
        const data_dir = if (args.len > 1) args[1] else "apl_data";

        var database = db.Database.init(allocator, data_dir) catch |err| {
            print("[ERROR] Failed to open database at '{s}': {}\n", .{ data_dir, err });
            return;
        };
        defer database.deinit();

        if (try database.get("sys_config")) |val| {
            defer allocator.free(val);
            // Pretty print or just raw?
            std.io.getStdOut().writer().print("{s}\n", .{val}) catch {};
        } else {
            print("[INFO] No governance policy found (using genesis defaults?)\n", .{});
        }
    } else {
        print("[ERROR] Unknown governance subcommand: {s}\n", .{subcommand_str});
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
    var is_raw = false;
    if (args.len > 0 and std.mem.eql(u8, args[0], "--raw")) {
        is_raw = true;
    }

    if (!is_raw) print("[INFO] APL Network Status:\n", .{});

    // Connect to server
    const server_ip = try getServerIP(allocator);
    defer allocator.free(server_ip);

    const cfg = config_mod.loadFromFile(allocator, "adria-config.json") catch config_mod.Config.default();
    const port = cfg.network.api_port;

    const address = net.Address.parseIp4(server_ip, port) catch {
        print("[ERROR] Invalid server address\n", .{});
        return;
    };

    const connection = connectWithTimeout(address) catch |err| {
        switch (err) {
            error.ConnectionTimeout => {
                print("[ERROR] Connection timeout to APL server at {s}:{} (5s)\n", .{ server_ip, port });
                return;
            },
            else => {
                print("[ERROR] Cannot connect to APL server at {s}:{}\n", .{ server_ip, port });
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

    if (is_raw) {
        try std.io.getStdOut().writer().print("{s}\n", .{response});
    } else {
        print("[INFO] Server: {s}:{}\n", .{ server_ip, port });
        print("[INFO] Status: {s}\n", .{response});
    }
}

fn handleAddressCommand(allocator: std.mem.Allocator, args: [][:0]u8) !void {
    var raw = false;
    var wallet_name: []const u8 = "default";

    if (args.len > 0) {
        if (std.mem.eql(u8, args[0], "--raw")) {
            raw = true;
            if (args.len > 1) {
                wallet_name = args[1];
            }
        } else if (args.len > 1 and std.mem.eql(u8, args[1], "--raw")) {
            wallet_name = args[0];
            raw = true;
        } else {
            wallet_name = args[0];
        }
    }

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

    if (raw) {
        try std.io.getStdOut().writer().print("{s}\n", .{std.fmt.fmtSliceHexLower(&address)});
    } else {
        print("[INFO] Wallet '{s}' address:\n", .{wallet_name});
        print("   {s}\n", .{std.fmt.fmtSliceHexLower(&address)});
        print("[INFO] Short address: {s}\n", .{std.fmt.fmtSliceHexLower(address[0..16])});
    }
}

fn handlePubkeyCommand(allocator: std.mem.Allocator, args: [][:0]u8) !void {
    var raw = false;
    var wallet_name: []const u8 = "default";

    if (args.len > 0) {
        if (std.mem.eql(u8, args[0], "--raw")) {
            raw = true;
            if (args.len > 1) {
                wallet_name = args[1];
            }
        } else if (args.len > 1 and std.mem.eql(u8, args[1], "--raw")) {
            wallet_name = args[0];
            raw = true;
        } else {
            wallet_name = args[0];
        }
    }

    // Load wallet
    const zen_wallet = loadWalletForOperation(allocator, wallet_name) catch |err| {
        switch (err) {
            error.WalletNotFound => {
                return;
            },
            else => return err,
        }
    };
    defer {
        zen_wallet.deinit();
        allocator.destroy(zen_wallet);
    }

    const pubkey = zen_wallet.getPublicKey() orelse return error.WalletNotLoaded;

    if (raw) {
        try std.io.getStdOut().writer().print("{s}\n", .{std.fmt.fmtSliceHexLower(&pubkey)});
    } else {
        print("[INFO] Wallet '{s}' public key:\n", .{wallet_name});
        print("   {s}\n", .{std.fmt.fmtSliceHexLower(&pubkey)});
    }
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

            invokeChaincode(allocator, zen_wallet, sender_address, sender_public_key, payload, wallet_name) catch |err| {
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
            invokeChaincode(allocator, zen_wallet, sender_address, sender_public_key, payload, wallet_name) catch |err| {
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
    try invokeChaincode(allocator, zen_wallet, sender_address, sender_public_key, payload, wallet_name);
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

fn handleCertCommand(allocator: std.mem.Allocator, args: [][:0]u8) !void {
    if (args.len < 1) {
        print("[ERROR] Cert subcommand required\n", .{});
        print("Usage: apl cert issue <issuer_wallet> <target_wallet>\n", .{});
        std.process.exit(1);
    }

    const subcommand_str = args[0];
    if (std.mem.eql(u8, subcommand_str, "issue")) {
        if (args.len < 3) {
            print("Usage: apl cert issue <issuer_wallet> <target_wallet>\n", .{});
            std.process.exit(1);
        }
        const issuer_wallet_name = args[1];
        const target_wallet_name = args[2];

        // Load Issuer Wallet (Usually Root CA)
        const issuer_wallet = loadWalletForOperation(allocator, issuer_wallet_name) catch {
            std.process.exit(1);
        };
        defer {
            issuer_wallet.deinit();
            allocator.destroy(issuer_wallet);
        }

        // Load Target Wallet just to read its public key
        const target_wallet = loadWalletForOperation(allocator, target_wallet_name) catch {
            std.process.exit(1);
        };
        defer {
            target_wallet.deinit();
            allocator.destroy(target_wallet);
        }

        const target_pubkey = target_wallet.public_key orelse {
            print("[ERROR] Target wallet has no public key.\n", .{});
            std.process.exit(1);
        };

        print("[INFO] Issuing certificate for {s} signed by {s}...\n", .{ target_wallet_name, issuer_wallet_name });

        // Form the certificate by signing the target's public key with the issuer's private key
        const issuer_keypair = issuer_wallet.getZeiCoinKeyPair() orelse {
            print("[ERROR] Issuer wallet is invalid.\n", .{});
            std.process.exit(1);
        };
        const cert_signature = issuer_keypair.sign(&target_pubkey) catch {
            print("[ERROR] Failed to sign certificate\n", .{});
            std.process.exit(1);
        };

        // Save to target_wallet_name.crt
        var database = try db.Database.init(allocator, "apl_data");
        defer database.deinit();

        var crt_path_buf: [1024]u8 = undefined;
        const crt_path = try std.fmt.bufPrint(&crt_path_buf, "{s}/wallets/{s}.crt", .{ "apl_data", target_wallet_name });

        const file = try std.fs.cwd().createFile(crt_path, .{});
        defer file.close();

        try file.writeAll(&cert_signature);

        print("[SUCCESS] Issued certificate and saved to: {s}\n", .{crt_path});
    } else {
        print("[ERROR] Unknown cert subcommand: {s}\n", .{subcommand_str});
        std.process.exit(1);
    }
}

fn handleNonceCommand(allocator: std.mem.Allocator, args: [][:0]u8) !void {
    if (args.len < 1) {
        print("[ERROR] Address required\n", .{});
        print("Usage: apl nonce <address_hex> [--raw]\n", .{});
        std.process.exit(1);
    }

    const address_hex = args[0];
    var is_raw = false;
    if (args.len > 1 and std.mem.eql(u8, args[1], "--raw")) {
        is_raw = true;
    }

    // Connect to server
    const server_ip = try getServerIP(allocator);
    defer allocator.free(server_ip);

    const cfg = config_mod.loadFromFile(allocator, "adria-config.json") catch config_mod.Config.default();
    const port = cfg.network.api_port;

    const address = net.Address.parseIp4(server_ip, port) catch {
        if (!is_raw) print("[ERROR] Invalid server address\n", .{});
        std.process.exit(1);
    };

    const connection = connectWithTimeout(address) catch |err| {
        if (!is_raw) print("[ERROR] Connection failed: {}\n", .{err});
        std.process.exit(1);
    };
    defer connection.close();

    const request = try std.fmt.allocPrint(allocator, "GET_NONCE:{s}\n", .{address_hex});
    defer allocator.free(request);

    try connection.writeAll(request);

    var buffer: [1024]u8 = undefined;
    const bytes_read = readWithTimeout(connection, &buffer) catch {
        if (!is_raw) print("[ERROR] Failed to read nonce response\n", .{});
        std.process.exit(1);
    };
    const response = buffer[0..bytes_read];

    if (std.mem.startsWith(u8, response, "NONCE:")) {
        const nonce_str = std.mem.trimRight(u8, response[6..], "\n\r \t");
        if (is_raw) {
            try std.io.getStdOut().writer().print("{s}\n", .{nonce_str});
        } else {
            print("[INFO] Nonce for {s}: {s}\n", .{ address_hex, nonce_str });
        }
    } else {
        if (!is_raw) print("[ERROR] Unexpected response: {s}\n", .{response});
        std.process.exit(1);
    }
}

fn handleTxCommand(allocator: std.mem.Allocator, args: [][:0]u8) !void {
    if (args.len < 1) {
        print("[ERROR] Tx subcommand required\n", .{});
        print("Usage: apl tx <sign|broadcast> [args...]\n", .{});
        std.process.exit(1);
    }

    const subcommand_str = args[0];
    const subcommand = std.meta.stringToEnum(TxSubcommand, subcommand_str) orelse {
        print("[ERROR] Unknown tx subcommand: {s}\n", .{subcommand_str});
        std.process.exit(1);
    };

    switch (subcommand) {
        .sign => {
            // Usage: apl tx sign <payload> <nonce> <network_id> [wallet_name]
            if (args.len < 4) {
                print("Usage: apl tx sign <payload> <nonce> <network_id> [wallet_name]\n", .{});
                std.process.exit(1);
            }
            const payload = args[1];
            const nonce = std.fmt.parseInt(u64, args[2], 10) catch {
                print("[ERROR] Invalid nonce format\n", .{});
                std.process.exit(1);
            };
            const network_id = std.fmt.parseInt(u32, args[3], 10) catch {
                print("[ERROR] Invalid network ID format\n", .{});
                std.process.exit(1);
            };
            const wallet_name = if (args.len > 4) args[4] else "default";

            // Load wallet (Offline)
            const zen_wallet = loadWalletForOperation(allocator, wallet_name) catch {
                std.process.exit(1);
            };
            defer {
                zen_wallet.deinit();
                allocator.destroy(zen_wallet);
            }

            const sender_address = zen_wallet.getAddress() orelse std.process.exit(1);
            const sender_public_key = zen_wallet.public_key.?;

            // Try to load sender certificate
            var sender_cert = std.mem.zeroes([64]u8);
            var crt_path_buf: [1024]u8 = undefined;
            const crt_path = std.fmt.bufPrint(&crt_path_buf, "{s}/wallets/{s}.crt", .{ "apl_data", wallet_name }) catch "";
            if (std.fs.cwd().openFile(crt_path, .{})) |file| {
                defer file.close();
                _ = file.readAll(&sender_cert) catch {};
            } else |_| {
                print("[WARNING] Identity certificate '{s}' not found. Transaction will likely be rejected.\n", .{crt_path});
            }

            const timestamp = @as(u64, @intCast(util.getTime()));
            var transaction = types.Transaction{
                .type = .invoke,
                .sender = sender_address,
                .sender_public_key = sender_public_key,
                .recipient = std.mem.zeroes(types.Address),
                .payload = payload,
                .nonce = nonce,
                .timestamp = timestamp,
                .network_id = network_id,
                .signature = std.mem.zeroes(types.Signature),
                .sender_cert = sender_cert,
            };

            const tx_hash = transaction.hash();
            transaction.signature = zen_wallet.signTransaction(&tx_hash) catch {
                print("[ERROR] Failed to sign transaction\n", .{});
                std.process.exit(1);
            };

            const payload_hex = try std.fmt.allocPrint(allocator, "{s}", .{std.fmt.fmtSliceHexLower(payload)});
            defer allocator.free(payload_hex);

            // Format: CLIENT_TRANSACTION:type:sender:recipient:payload_hex:timestamp:nonce:network_id:sig:pubkey:cert
            const tx_message = try std.fmt.allocPrint(allocator, "CLIENT_TRANSACTION:{d}:{s}:{s}:{s}:{}:{}:{}:{s}:{s}:{s}", .{
                @intFromEnum(transaction.type),
                std.fmt.fmtSliceHexLower(&sender_address),
                std.fmt.fmtSliceHexLower(&transaction.recipient),
                payload_hex,
                transaction.timestamp,
                transaction.nonce,
                transaction.network_id,
                std.fmt.fmtSliceHexLower(&transaction.signature),
                std.fmt.fmtSliceHexLower(&sender_public_key),
                std.fmt.fmtSliceHexLower(&sender_cert),
            });
            defer allocator.free(tx_message);

            // ALWAYS print purely raw to stdout for piping.
            try std.io.getStdOut().writer().print("{s}\n", .{tx_message});
        },
        .broadcast => {
            // Usage: apl tx broadcast <raw_tx> [--raw]
            if (args.len < 2) {
                print("Usage: apl tx broadcast <raw_tx_string> [--raw]\n", .{});
                std.process.exit(1);
            }
            const raw_tx = args[1];
            var is_raw = false;
            if (args.len > 2 and std.mem.eql(u8, args[2], "--raw")) {
                is_raw = true;
            }

            const server_ip = try getServerIP(allocator);
            defer allocator.free(server_ip);

            const cfg = config_mod.loadFromFile(allocator, "adria-config.json") catch config_mod.Config.default();
            const port = cfg.network.api_port;

            const address = net.Address.parseIp4(server_ip, port) catch {
                if (!is_raw) print("[ERROR] Invalid server address\n", .{});
                std.process.exit(1);
            };

            const connection = connectWithTimeout(address) catch |err| {
                if (!is_raw) print("[ERROR] Connection failed: {}\n", .{err});
                std.process.exit(1);
            };
            defer connection.close();

            // Allow for string missing newline if passed from bash variable
            if (!std.mem.endsWith(u8, raw_tx, "\n")) {
                try connection.writeAll(raw_tx);
                try connection.writeAll("\n");
            } else {
                try connection.writeAll(raw_tx);
            }

            var buffer: [1024]u8 = undefined;
            const bytes_read = readWithTimeout(connection, &buffer) catch {
                if (!is_raw) print("[ERROR] Failed to read response\n", .{});
                std.process.exit(1);
            };
            const response = buffer[0..bytes_read];

            if (std.mem.startsWith(u8, response, "CLIENT_TRANSACTION_ACCEPTED")) {
                if (is_raw) {
                    try std.io.getStdOut().writer().print("{s}\n", .{response});
                } else {
                    print("[SUCCESS] Broadcast successful: {s}\n", .{response});
                }
                std.process.exit(0);
            } else {
                if (is_raw) {
                    try std.io.getStdOut().writer().print("{s}\n", .{response});
                } else {
                    print("[ERROR] Broadcast failed: {s}\n", .{response});
                }
                std.process.exit(1);
            }
        },
    }
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

fn invokeChaincode(allocator: std.mem.Allocator, zen_wallet: *wallet.Wallet, sender_address: types.Address, sender_public_key: [32]u8, payload: []const u8, wallet_name: []const u8) !void {
    // Connect to server
    const server_ip = try getServerIP(allocator);
    defer allocator.free(server_ip);

    const cfg = config_mod.loadFromFile(allocator, "adria-config.json") catch config_mod.Config.default();
    const port = cfg.network.api_port;

    const server_address = net.Address.parseIp4(server_ip, port) catch {
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

    // 1. Get Network ID dynamically
    var network_id: u32 = 1; // Fallback
    {
        try connection.writeAll("BLOCKCHAIN_STATUS\n");
        var status_buf: [1024]u8 = undefined;
        if (readWithTimeout(connection, &status_buf)) |bytes| {
            const status_resp = status_buf[0..bytes];
            if (std.mem.indexOf(u8, status_resp, "NETWORK_ID=")) |idx| {
                const start = idx + "NETWORK_ID=".len;
                var end = start;
                while (end < status_resp.len and std.ascii.isDigit(status_resp[end])) : (end += 1) {}
                if (end > start) {
                    network_id = std.fmt.parseInt(u32, status_resp[start..end], 10) catch 1;
                }
            }
        } else |_| {
            // Ignore error, fallback to 1 or config
            // But we should probably fail if we can't get status?
            // For now, soft fail to 1 is okay if server is old, but server is new.
        }
    }

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
    // Try to load sender certificate
    var sender_cert = std.mem.zeroes([64]u8);
    var crt_path_buf: [1024]u8 = undefined;
    const crt_path = std.fmt.bufPrint(&crt_path_buf, "{s}/wallets/{s}.crt", .{ "apl_data", wallet_name }) catch "";
    if (std.fs.cwd().openFile(crt_path, .{})) |file| {
        defer file.close();
        _ = file.readAll(&sender_cert) catch {};
    } else |_| {
        print("[WARNING] Identity certificate '{s}' not found. Transaction will likely be rejected.\n", .{crt_path});
    }

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
        .network_id = network_id,
        .signature = std.mem.zeroes(types.Signature),
        .sender_cert = sender_cert,
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

    // Format: CLIENT_TRANSACTION:type:sender:recipient:payload_hex:timestamp:nonce:network_id:sig:pubkey:cert
    const tx_message = try std.fmt.allocPrint(allocator, "CLIENT_TRANSACTION:{d}:{s}:{s}:{s}:{}:{}:{}:{s}:{s}:{s}", .{
        @intFromEnum(transaction.type),
        std.fmt.fmtSliceHexLower(&sender_address),
        std.fmt.fmtSliceHexLower(&transaction.recipient),
        payload_hex,
        transaction.timestamp,
        transaction.nonce,
        transaction.network_id,
        std.fmt.fmtSliceHexLower(&transaction.signature),
        std.fmt.fmtSliceHexLower(&sender_public_key),
        std.fmt.fmtSliceHexLower(&sender_cert),
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
    print("INVOKE COMMANDS:\n", .{});
    print("  apl invoke <payload> [wallet]        Invoke raw chaincode payload string\n\n", .{});
    print("GOVERNANCE COMMANDS:\n", .{});
    print("  apl governance update <policy.json> [wallet] Submit governance policy\n", .{});
    print("  apl governance get [data_dir]                Query active policy\n\n", .{});
    print("AUDIT COMMANDS:\n", .{});
    print("  apl hydrate [--verify-all]   Reconstruct state from chain history\n\n", .{});
    print("NETWORK COMMANDS:\n", .{});
    print("  apl status                   Show network status\n", .{});
    print("  apl nonce <addr> [--raw]     Get current nonce for address\n", .{});
    print("  apl address [wallet]         Show wallet address\n\n", .{});
    print("OFFLINE COMMANDS:\n", .{});
    print("  apl tx sign <payload> <nonce> <net_id> [wallet] Generate offline tx string\n", .{});
    print("  apl tx broadcast <raw_tx> [--raw]               Broadcast offline tx string\n\n", .{});
    print("CERTIFICATE COMMANDS (IDENTITY):\n", .{});
    print("  apl cert issue <issuer> <target>   Issue a certificate to target wallet using issuer's key\n", .{});
    print("  apl pubkey [wallet] [--raw]        Display public key for a wallet\n\n", .{});
    print("EXAMPLES:\n", .{});
    print("  apl wallet create alice      # Create wallet named 'alice'\n", .{});
    print("  apl ledger record invoice:1 \"{{...}}\" alice\n", .{});
    print("  apl status                   # Check network status\n\n", .{});
    print("ENVIRONMENT:\n", .{});
    print("  ADRIA_SERVER=ip               Set APL server IP (default: 127.0.0.1)\n\n", .{});
    print("Default wallet is 'default' if no name specified\n", .{});
}
