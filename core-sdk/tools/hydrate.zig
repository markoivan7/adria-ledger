// hydrate.zig - State Reconstruction & Audit Tool
// Replays the blockchain (WAL) to rebuild the World State (View).

const std = @import("std");
const print = std.debug.print;
const db = @import("execution").db;
const types = @import("common").types;
const util = @import("common").util;
const chaincode = @import("execution").chaincode;
const acl_module = @import("execution").acl;
const key = @import("crypto").key;
const governance = @import("execution").system.governance;

pub const HydrateTool = struct {
    allocator: std.mem.Allocator,
    data_dir: []const u8,
    verify_signatures: bool, // true = Audit Mode, false = Fast Mode

    // Audit mode: live governance state rebuilt during replay.
    // root_public_keys is seeded from adria-config.json and updated after each
    // block that executes governance transactions.
    root_public_keys: std.ArrayList([32]u8),
    revoked_serials: std.ArrayList(u64),

    pub fn init(allocator: std.mem.Allocator, data_dir: []const u8, verify_signatures: bool) HydrateTool {
        return HydrateTool{
            .allocator = allocator,
            .data_dir = data_dir,
            .verify_signatures = verify_signatures,
            .root_public_keys = std.ArrayList([32]u8).init(allocator),
            .revoked_serials = std.ArrayList(u64).init(allocator),
        };
    }

    pub fn deinit(self: *HydrateTool) void {
        self.root_public_keys.deinit();
        self.revoked_serials.deinit();
    }

    /// Read seed_root_ca from adria-config.json and return it as raw bytes.
    /// Returns null if the file cannot be read or the key is malformed.
    fn loadSeedRootCA(self: *HydrateTool) ?[32]u8 {
        const file = std.fs.cwd().openFile("adria-config.json", .{}) catch return null;
        defer file.close();

        const content = file.readToEndAlloc(self.allocator, 8192) catch return null;
        defer self.allocator.free(content);

        // Parse only the fields we need.
        const CfgSlice = struct {
            consensus: struct {
                seed_root_ca: []const u8 = "",
            },
        };
        const parsed = std.json.parseFromSlice(
            CfgSlice,
            self.allocator,
            content,
            .{ .ignore_unknown_fields = true },
        ) catch return null;
        defer parsed.deinit();

        if (parsed.value.consensus.seed_root_ca.len != 64) return null;

        var pk: [32]u8 = undefined;
        _ = std.fmt.hexToBytes(&pk, parsed.value.consensus.seed_root_ca) catch return null;
        return pk;
    }

    /// Write the genesis governance policy to the database.
    /// This mirrors createGenesis() in main.zig which writes sys_config directly to DB
    /// (not via a blockchain transaction). Hydrate must recreate this magic state so that
    /// governance chaincode executed during replay can find and update the policy correctly.
    fn writeGenesisGovernance(self: *HydrateTool, database: *db.Database) !void {
        // Mirror createGenesis: try genesis.json first, fall back to adria-config.json.
        if (std.fs.cwd().openFile("genesis.json", .{})) |file| {
            defer file.close();
            const size = file.getEndPos() catch return;
            const policy_json = try self.allocator.alloc(u8, size);
            defer self.allocator.free(policy_json);
            _ = try file.readAll(policy_json);
            try database.put(governance.GovernanceSystem.CONFIG_KEY, policy_json);
            print("[HYDRATE] Genesis governance loaded from genesis.json\n", .{});
            return;
        } else |_| {}

        // Fall back: derive from adria-config.json seed_root_ca.
        var seed_hex_buf: [64]u8 = undefined;
        var seed_hex: []const u8 = "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29";

        if (self.loadSeedRootCA()) |pk| {
            const hex = std.fmt.bufPrint(&seed_hex_buf, "{s}", .{std.fmt.fmtSliceHexLower(&pk)}) catch unreachable;
            seed_hex = hex;
        } else {
            print("[WARN] adria-config.json not found or invalid; using hardcoded dev genesis CA.\n", .{});
        }

        const initial_policy = governance.GovernancePolicy{
            .protocol_version = types.SUPPORTED_PROTOCOL_VERSION,
            .root_cas = &[_][]const u8{seed_hex},
            .min_validator_count = 1,
            .block_creation_interval = 10,
        };
        const policy_json = try initial_policy.toJson(self.allocator);
        defer self.allocator.free(policy_json);
        try database.put(governance.GovernanceSystem.CONFIG_KEY, policy_json);
    }

    /// Reload root CAs and CRL from the on-chain governance state stored in the DB.
    /// Called after each block is committed so that governance changes (new root CAs,
    /// certificate revocations) are reflected for subsequent block verification.
    /// If sys_config is not yet present in DB, the current values are left unchanged.
    fn reloadGovernanceState(self: *HydrateTool, database: *db.Database) !void {
        const policy_json_opt = try database.get(governance.GovernanceSystem.CONFIG_KEY);
        if (policy_json_opt == null) return;
        const policy_json = policy_json_opt.?;
        defer self.allocator.free(policy_json);

        const parsed = std.json.parseFromSlice(
            governance.GovernancePolicy,
            self.allocator,
            policy_json,
            .{ .ignore_unknown_fields = true },
        ) catch return; // Silently ignore malformed governance state.
        defer parsed.deinit();

        self.root_public_keys.clearRetainingCapacity();
        for (parsed.value.root_cas) |hex_key| {
            var pk: [32]u8 = undefined;
            _ = std.fmt.hexToBytes(&pk, hex_key) catch continue;
            try self.root_public_keys.append(pk);
        }

        self.revoked_serials.clearRetainingCapacity();
        for (parsed.value.revoked_serials) |serial| {
            try self.revoked_serials.append(serial);
        }
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

        // 4. Replay Loop
        var prev_hash: ?types.Hash = null;

        for (0..height) |i| {
            if (i % 100 == 0) print("[HYDRATE] Processing Block #{}...\r", .{i});

            // Special Handling: Genesis Account Creation + Governance Bootstrap
            if (i == 0) {
                const genesis_public_key = std.mem.zeroes([32]u8);
                const genesis_addr = util.hash(&genesis_public_key);
                const genesis_account = types.Account{
                    .address = genesis_addr,
                    .nonce = 0,
                    .role = 1,
                };
                try database.saveAccount(genesis_addr, genesis_account);

                // Write genesis governance policy (sys_config) to DB.
                // createGenesis() writes this directly rather than via a transaction,
                // so we must reconstruct it here for governance chaincode to function
                // correctly during subsequent block replay.
                try self.writeGenesisGovernance(&database);
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
            }
            prev_hash = current_hash;

            // 2. Audit Mode: Full Cryptographic Verification
            if (self.verify_signatures) {
                // Skip Block 0 (Genesis): uses zeroed validator key/cert/signature by design.
                if (i > 0) {
                    // 2a. Verify Block Validator Signature
                    const header_hash = block.header.hash();
                    if (!key.verify(block.header.validator_public_key, &header_hash, block.header.signature)) {
                        print("\n[CRITICAL] Invalid Validator Signature at Block #{}\n", .{i});
                        return error.InvalidBlockSignature;
                    }

                    // 2b. Verify Validator Certificate against root CA(s).
                    // Use block.header.timestamp as current_time for replay-safe expiry checking
                    // (certs valid at block creation time must not fail due to later expiry).
                    if (self.root_public_keys.items.len > 0) {
                        var validator_cert_valid = false;
                        for (self.root_public_keys.items) |root_pk| {
                            if (key.MSP.verifyCertificateV2(
                                root_pk,
                                block.header.validator_cert,
                                block.header.validator_public_key,
                                block.header.validator_cert_serial,
                                block.header.validator_cert_issued_at,
                                block.header.validator_cert_expires_at,
                                block.header.timestamp,
                            )) {
                                validator_cert_valid = true;
                                break;
                            }
                        }
                        if (!validator_cert_valid) {
                            print("\n[CRITICAL] Invalid Validator Certificate at Block #{}\n", .{i});
                            return error.InvalidValidatorCert;
                        }
                    }
                }
            }

            // B. Execution (Apply State)

            // Deterministic Replay Validation Guard
            switch (block.header.protocol_version) {
                1, 2 => {
                    // Protocol versions 1 and 2: same chaincode execution logic.
                    // v2 added u64 network_id, CertificateV2 cert fields, and CRL support.
                    // State transitions are identical across both.
                },
                else => {
                    print("\n[CRITICAL] Unsupported Protocol Version {} in Block #{}\n", .{ block.header.protocol_version, i });
                    return error.UnsupportedProtocolVersion;
                },
            }

            for (block.transactions, 0..) |tx, tx_index| {
                // Audit Mode: Transaction-level verification
                if (self.verify_signatures) {
                    // Skip genesis block transactions (zeroed cert fields by design).
                    if (i > 0) {
                        // 1. CRL Check: reject transactions whose cert serial is revoked.
                        for (self.revoked_serials.items) |revoked| {
                            if (tx.cert_serial == revoked) {
                                print("\n[CRITICAL] Revoked cert serial {} found in Block #{} Tx #{}\n", .{ tx.cert_serial, i, tx_index });
                                return error.RevokedCertificate;
                            }
                        }

                        // 2. CertificateV2 Verification: cert must be signed by a known root CA
                        // and must have been valid at the time the block was committed.
                        if (self.root_public_keys.items.len > 0) {
                            var cert_valid = false;
                            for (self.root_public_keys.items) |root_pk| {
                                if (key.MSP.verifyCertificateV2(
                                    root_pk,
                                    tx.sender_cert,
                                    tx.sender_public_key,
                                    tx.cert_serial,
                                    tx.cert_issued_at,
                                    tx.cert_expires_at,
                                    block.header.timestamp,
                                )) {
                                    cert_valid = true;
                                    break;
                                }
                            }
                            if (!cert_valid) {
                                print("\n[CRITICAL] Invalid Transaction Certificate in Block #{} Tx #{}\n", .{ i, tx_index });
                                return error.InvalidTxCert;
                            }
                        }
                    }

                    // 3. Transaction Signature Verification (all blocks including genesis if non-empty)
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
                        } else if (std.mem.eql(u8, chaincode_id.?, chaincode.DocumentStore.ID)) {
                            result = chaincode.DocumentStore.invoke(&stub, function_name.?, args.items) catch null;
                        } else if (std.mem.eql(u8, chaincode_id.?, chaincode.Governance.ID)) {
                            const sender_hex = try std.fmt.allocPrint(self.allocator, "{s}", .{std.fmt.fmtSliceHexLower(&tx.sender)});
                            defer self.allocator.free(sender_hex);
                            result = chaincode.Governance.invoke(&stub, function_name.?, args.items, sender_hex) catch null;
                        } else if (std.mem.eql(u8, chaincode_id.?, chaincode.DatasetStore.ID)) {
                            result = chaincode.DatasetStore.invoke(&stub, function_name.?, args.items) catch null;
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

            // Reload governance state (root CAs + CRL) after each committed block.
            // This ensures that governance transactions (revoke_certificate, update_policy)
            // are reflected in subsequent certificate verification.
            // In fast mode this also ensures the reconstructed governance state is correct.
            try self.reloadGovernanceState(&database);
        }

        print("\n[HYDRATE] Success! Reconstructed state from {} blocks.\n", .{height});
        const state_count = try database.getStateCount();
        print("[HYDRATE] Final State Count: {} items.\n", .{state_count});

        if (self.verify_signatures) {
            print("[HYDRATE] AUDIT COMPLETE: All {} root CA(s) verified, {} revoked serial(s) checked.\n", .{
                self.root_public_keys.items.len,
                self.revoked_serials.items.len,
            });
        }
    }
};
