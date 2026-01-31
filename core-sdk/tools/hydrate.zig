// hydrate.zig - State Reconstruction & Audit Tool
// Replays the blockchain (WAL) to rebuild the World State (View).

const std = @import("std");
const print = std.debug.print;
const db = @import("../execution/db.zig");
const types = @import("../common/types.zig");
const util = @import("../common/util.zig");
const chaincode = @import("../execution/chaincode.zig");
const acl_module = @import("../execution/acl.zig");
const key = @import("../crypto/key.zig");

pub const HydrateTool = struct {
    allocator: std.mem.Allocator,
    data_dir: []const u8,
    verify_signatures: bool, // true = Audit Mode, false = Fast Mode

    pub fn init(allocator: std.mem.Allocator, data_dir: []const u8, verify_signatures: bool) HydrateTool {
        return HydrateTool{
            .allocator = allocator,
            .data_dir = data_dir,
            .verify_signatures = verify_signatures,
        };
    }

    /// Run the hydration process
    pub fn execute(self: *HydrateTool) !void {
        print("[HYDRATE] Starting State Reconstruction (Mode: {s})...\n", .{if (self.verify_signatures) "AUDIT (Secure)" else "FAST (Trust-On-First-Use)"});

        // 1. Nuke the State (Keep Blocks & Wallets)
        const state_dir = try std.fs.path.join(self.allocator, &[_][]const u8{ self.data_dir, "state" });
        defer self.allocator.free(state_dir);

        print("[HYDRATE] Clearing existing state at {s}...\n", .{state_dir});
        std.fs.cwd().deleteTree(state_dir) catch |err| {
            print("[WARN] Failed to clear state (might be empty): {}\n", .{err});
        };

        // 2. Initialize Database (Recreates empty state dir)
        var database = try db.Database.init(self.allocator, self.data_dir);
        defer database.deinit();

        const height = try database.getHeight();
        if (height == 0) {
            print("[HYDRATE] Blockchain is empty. Nothing to hydrate.\n", .{});
            return;
        }

        print("[HYDRATE] Found {} blocks. Replaying...\n", .{height});

        // 3. Init Access Control (Skipped for hydration as we trust the ordered chain)
        // var acl = acl_module.AccessControl.init();

        // 4. Replay Loop
        var prev_hash: ?types.Hash = null;

        for (0..height) |i| {
            if (i % 100 == 0) print("[HYDRATE] Processing Block #{}...\r", .{i});

            // Special Handling: Genesis Account Creation (Magic State)
            if (i == 0) {
                const genesis_public_key = std.mem.zeroes([32]u8);
                const genesis_addr = util.hash(&genesis_public_key);
                const genesis_account = types.Account{
                    .address = genesis_addr,
                    .nonce = 0,
                    .role = 1,
                };
                try database.saveAccount(genesis_addr, genesis_account);
            }

            const block = database.getBlock(@intCast(i)) catch |err| {
                print("\n[CRITICAL] Corrupt Block #{}: {}\n", .{ i, err });
                return err;
            };
            // Deep cleanup of block transactions
            defer {
                for (block.transactions) |tx| {
                    self.allocator.free(tx.payload);
                }
                self.allocator.free(block.transactions);
            }

            // A. Validation
            const current_hash = block.hash();

            // 1. Chain Continuity Check
            if (prev_hash) |p_hash| {
                if (!std.mem.eql(u8, &block.header.previous_hash, &p_hash)) {
                    print("\n[CRITICAL] Broken Chain at Block #{}. Previous hash mismatch!\n", .{i});
                    return error.BrokenChain;
                }
            } else {
                // Check genesis prev hash is zero? Not strictly necessary if we trust height 0 is Genesis.
            }
            prev_hash = current_hash;

            // 2. Audit Mode: Full Crypto Verify
            if (self.verify_signatures) {
                // Skip Genesis (Block 0) as it uses hardcoded zero-signatures
                if (i > 0) {
                    // Verify Block Signature
                    const header_hash = block.header.hash();
                    if (!key.verify(block.header.validator_public_key, &header_hash, block.header.signature)) {
                        print("\n[CRITICAL] Invalid Validator Signature at Block #{}\n", .{i});
                        return error.InvalidBlockSignature;
                    }
                }

                // TODO: Verify Validator Certificate against Root CA?
                // For now, we assume the chain is valid if signatures match.
            }

            // B. Execution (Apply State)
            for (block.transactions, 0..) |tx, tx_index| {
                // 1. Audit Mode: Tx Signature Verify
                if (self.verify_signatures) {
                    const tx_hash = tx.hashForSigning();
                    if (!key.verify(tx.sender_public_key, &tx_hash, tx.signature)) {
                        print("\n[CRITICAL] Invalid Transaction Signature in Block #{} Tx #{}\n", .{ i, tx_index });
                        return error.InvalidTxSignature;
                    }
                }

                // 2. State Application Logic (Mirrors main.zig)
                // Get sender to update nonce
                var sender_account: types.Account = undefined;
                if (database.getAccount(tx.sender)) |acc| {
                    sender_account = acc;
                } else |_| {
                    // Create new if not exists (Lazy Load)
                    sender_account = types.Account{
                        .address = tx.sender,
                        .nonce = 0,
                        .role = 2, // Default Writer
                    };
                    // Special Case: Genesis creates Admin (Role 1)
                    if (i == 0) sender_account.role = 1;
                }

                // Permission Check
                // Note: We skip checking calling ACL because we assume the block WAS valid when mined.
                // However, for strict audit, we COULD re-verify ACLs.
                // Using 'fast' logic here: we trust the recorded transaction was validly ordered.

                // Update Nonce
                sender_account.nonce += 1;
                try database.saveAccount(tx.sender, sender_account);

                // Execute Chaincode
                if (tx.type == .invoke) {
                    var stub = chaincode.Stub.init(self.allocator, &database);
                    defer stub.deinit();

                    // Parse Payload
                    var args = std.ArrayList([]const u8).init(self.allocator);
                    defer {
                        for (args.items) |arg| {
                            self.allocator.free(arg);
                        }
                        args.deinit();
                    }
                    var splitter = std.mem.splitScalar(u8, tx.payload, '|');

                    const chaincode_id = splitter.next();
                    const function_name = splitter.next();

                    if (chaincode_id != null and function_name != null) {
                        while (splitter.next()) |arg| {
                            const arg_dup = try self.allocator.dupe(u8, arg);
                            try args.append(arg_dup);
                        }

                        // Dispatch & Cleanup Result
                        var result: ?[]u8 = null;
                        if (std.mem.eql(u8, chaincode_id.?, chaincode.GeneralLedger.ID)) {
                            result = chaincode.GeneralLedger.invoke(&stub, function_name.?, args.items) catch null;
                        } else if (std.mem.eql(u8, chaincode_id.?, chaincode.AssetLedger.ID)) {
                            const sender_hex = try std.fmt.allocPrint(self.allocator, "{s}", .{std.fmt.fmtSliceHexLower(&tx.sender)});
                            defer self.allocator.free(sender_hex);
                            result = chaincode.AssetLedger.invoke(&stub, function_name.?, args.items, sender_hex) catch null;
                        }

                        if (result) |res| self.allocator.free(res);
                    }

                    // Commit Writes
                    var it = stub.write_set.iterator();
                    while (it.next()) |entry| {
                        try database.putVersioned(entry.key_ptr.*, entry.value_ptr.*, i, @intCast(tx_index));
                    }
                }
            }

            // Flush after each block
            try database.commit();
        }

        print("\n[HYDRATE] Success! Reconstructed state from {} blocks.\n", .{height});
        const state_count = try database.getStateCount();
        print("[HYDRATE] Final State Count: {} items.\n", .{state_count});
    }
};
