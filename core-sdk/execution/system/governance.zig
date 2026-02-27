// governance.zig - System Chaincode for Governance
// Manages network-wide configuration and access control policies

const std = @import("std");
const chaincode = @import("../chaincode.zig");
const json = std.json;

/// Governance Policy Structure (On-Chain Config) — Protocol v2
pub const GovernancePolicy = struct {
    // Protocol version required by this genesis
    protocol_version: u32,

    // List of Root Certificate Authorities (Hex encoded public keys)
    // These keys can sign valid Identity Certificates
    root_cas: []const []const u8,

    // Minimum number of validators required for consensus (future use)
    min_validator_count: u32,

    // Target block creation time in seconds
    block_creation_interval: u64,

    // Certificate Revocation List (CRL): serial numbers of revoked CertificateV2s
    // Stored as decimal u64 strings for JSON compatibility.
    // Empty by default. Only root CA holders may add to this list.
    revoked_serials: []const u64 = &[_]u64{},

    // Helper to serialize policy
    pub fn toJson(self: GovernancePolicy, allocator: std.mem.Allocator) ![]u8 {
        var list = std.ArrayList(u8).init(allocator);
        defer list.deinit();
        try json.stringify(self, .{}, list.writer());
        return list.toOwnedSlice();
    }
};

/// Governance System Chaincode
pub const GovernanceSystem = struct {
    pub const ID = "sys_governance";
    pub const CONFIG_KEY = "sys_config";

    /// Invoke router
    pub fn invoke(stub: *chaincode.Stub, function: []const u8, args: [][]const u8, sender: []const u8) ![]u8 {
        if (std.mem.eql(u8, function, "update_policy")) {
            return updatePolicy(stub, args, sender);
        } else if (std.mem.eql(u8, function, "get_policy")) {
            return getPolicy(stub);
        } else if (std.mem.eql(u8, function, "revoke_certificate")) {
            return revokeCertificate(stub, args, sender);
        } else {
            return chaincode.ChaincodeError.InvalidFunction;
        }
    }

    /// Update the network policy
    /// Args: [new_policy_json]
    /// Logic: Checks if sender is a Root Admin (Policy constraint) then updates state.
    fn updatePolicy(stub: *chaincode.Stub, args: [][]const u8, sender: []const u8) ![]u8 {
        if (args.len != 1) return chaincode.ChaincodeError.InvalidArguments;
        const new_policy_json = args[0];

        // 1. Fetch current policy to Verify Permissions
        const current_policy_json = try stub.getState(CONFIG_KEY);

        // Require initial setup via Genesis block.
        // Check sender against current root CAs.

        if (current_policy_json) |policy_json| {
            defer stub.allocator.free(policy_json);

            // Parse current policy
            const parsed = try json.parseFromSlice(GovernancePolicy, stub.allocator, policy_json, .{ .ignore_unknown_fields = true });
            defer parsed.deinit();
            const policy = parsed.value;

            // Check if sender (address hex) corresponds to a root CA public key.
            // root_cas stores hex-encoded Ed25519 public keys; derive each CA's
            // address (BLAKE3(public_key)) and compare against the sender address.
            var is_admin = false;
            for (policy.root_cas) |admin_key_hex| {
                var admin_pubkey: [32]u8 = undefined;
                _ = std.fmt.hexToBytes(&admin_pubkey, admin_key_hex) catch continue;
                var hasher = std.crypto.hash.Blake3.init(.{});
                hasher.update(&admin_pubkey);
                var admin_address: [32]u8 = undefined;
                hasher.final(&admin_address);
                var admin_addr_buf: [64]u8 = undefined;
                const admin_addr_hex = std.fmt.bufPrint(&admin_addr_buf, "{s}", .{std.fmt.fmtSliceHexLower(&admin_address)}) catch continue;
                if (std.mem.eql(u8, admin_addr_hex, sender)) {
                    is_admin = true;
                    break;
                }
            }

            if (!is_admin) {
                return error.PermissionDenied;
            }
        } else {
            // Bootstrapping: Failed to initialize.
            return chaincode.ChaincodeError.InternalError;
        }

        // 2. Validate New Policy (Schema check)
        const parsed_new = json.parseFromSlice(GovernancePolicy, stub.allocator, new_policy_json, .{ .ignore_unknown_fields = true }) catch {
            return chaincode.ChaincodeError.InvalidArguments;
        };
        defer parsed_new.deinit();

        // 3. Commit Update
        try stub.putState(CONFIG_KEY, new_policy_json);

        return stub.allocator.dupe(u8, "OK");
    }

    /// Get current policy
    fn getPolicy(stub: *chaincode.Stub) ![]u8 {
        const val = try stub.getState(CONFIG_KEY);
        if (val) |v| {
            defer stub.allocator.free(v);
            return stub.allocator.dupe(u8, v);
        }
        return chaincode.ChaincodeError.NotFound;
    }

    /// Revoke a certificate by adding its serial number to the CRL.
    /// Args: [serial_decimal_string]
    /// Only root CA holders (admin keys) may revoke certificates.
    fn revokeCertificate(stub: *chaincode.Stub, args: [][]const u8, sender: []const u8) ![]u8 {
        if (args.len != 1) return chaincode.ChaincodeError.InvalidArguments;

        const serial_str = args[0];
        const serial = std.fmt.parseInt(u64, serial_str, 10) catch {
            return chaincode.ChaincodeError.InvalidArguments;
        };

        // 1. Fetch current policy to verify permissions
        const current_policy_json = try stub.getState(CONFIG_KEY);
        if (current_policy_json == null) return chaincode.ChaincodeError.InternalError;
        defer stub.allocator.free(current_policy_json.?);

        const parsed = try json.parseFromSlice(GovernancePolicy, stub.allocator, current_policy_json.?, .{ .ignore_unknown_fields = true });
        defer parsed.deinit();
        const policy = parsed.value;

        // 2. Verify sender is a Root CA.
        // root_cas stores hex-encoded public keys; derive each CA's address
        // (BLAKE3(public_key)) and compare against the sender address.
        var is_admin = false;
        for (policy.root_cas) |admin_key_hex| {
            var admin_pubkey: [32]u8 = undefined;
            _ = std.fmt.hexToBytes(&admin_pubkey, admin_key_hex) catch continue;
            var hasher = std.crypto.hash.Blake3.init(.{});
            hasher.update(&admin_pubkey);
            var admin_address: [32]u8 = undefined;
            hasher.final(&admin_address);
            var admin_addr_buf: [64]u8 = undefined;
            const admin_addr_hex = std.fmt.bufPrint(&admin_addr_buf, "{s}", .{std.fmt.fmtSliceHexLower(&admin_address)}) catch continue;
            if (std.mem.eql(u8, admin_addr_hex, sender)) {
                is_admin = true;
                break;
            }
        }
        if (!is_admin) return error.PermissionDenied;

        // 3. Check if serial is already revoked (idempotent)
        for (policy.revoked_serials) |rev| {
            if (rev == serial) return stub.allocator.dupe(u8, "OK"); // Already revoked
        }

        // 4. Build updated revoked_serials list
        const new_len = policy.revoked_serials.len + 1;
        const new_revoked = try stub.allocator.alloc(u64, new_len);
        defer stub.allocator.free(new_revoked);
        @memcpy(new_revoked[0..policy.revoked_serials.len], policy.revoked_serials);
        new_revoked[new_len - 1] = serial;

        // 5. Serialize and commit updated policy
        const updated_policy = GovernancePolicy{
            .protocol_version = policy.protocol_version,
            .root_cas = policy.root_cas,
            .min_validator_count = policy.min_validator_count,
            .block_creation_interval = policy.block_creation_interval,
            .revoked_serials = new_revoked,
        };
        const updated_json = try updated_policy.toJson(stub.allocator);
        defer stub.allocator.free(updated_json);

        try stub.putState(CONFIG_KEY, updated_json);
        return stub.allocator.dupe(u8, "OK");
    }
};

test "governance policy update" {
    const testing = std.testing;
    const db = @import("../db.zig"); // Adjust path if needed

    // Setup Mock Stub

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Create temp DB
    var database = try db.Database.init(allocator, "/tmp/adria_test_gov");
    defer database.deinit();

    // Create Stub
    var stub = chaincode.Stub.init(allocator, &database);
    defer stub.deinit();

    // 1. Initial State (Empty) -> Fail Update (No Current Policy)
    // Bootstrap manually (simulating Genesis).

    const admin_key = "admin_pubkey_hex";
    const initial_policy = GovernancePolicy{
        .protocol_version = 1,
        .root_cas = &[_][]const u8{admin_key},
        .min_validator_count = 1,
        .block_creation_interval = 10,
    };
    const initial_json = try initial_policy.toJson(allocator);
    defer allocator.free(initial_json);

    try stub.putState(GovernanceSystem.CONFIG_KEY, initial_json);
    // Commit to DB

    // 2. Try Update with valid Admin
    const new_policy = GovernancePolicy{
        .protocol_version = 1,
        .root_cas = &[_][]const u8{ admin_key, "new_admin" },
        .min_validator_count = 2,
        .block_creation_interval = 5,
    };
    const new_json = try new_policy.toJson(allocator);
    defer allocator.free(new_json);

    var args = std.ArrayList([]const u8).init(allocator);
    defer args.deinit();
    try args.append(new_json);

    const res = try GovernanceSystem.invoke(&stub, "update_policy", args.items, admin_key);
    defer allocator.free(res);
    try testing.expectEqualStrings("OK", res);

    // 3. Verify State Updated
    const updated_json_raw = try GovernanceSystem.invoke(&stub, "get_policy", args.items[0..0], admin_key); // args ignored for get
    defer allocator.free(updated_json_raw);

    // Parse to verify
    const parsed = try json.parseFromSlice(GovernancePolicy, allocator, updated_json_raw, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();

    try testing.expectEqual(@as(u32, 2), parsed.value.min_validator_count);
    try testing.expectEqual(@as(usize, 2), parsed.value.root_cas.len);

    // 4. Try Update with Non-Admin (should fail)
    const unauthorized_policy = GovernancePolicy{
        .protocol_version = 1,
        .root_cas = &[_][]const u8{"hacker"},
        .min_validator_count = 0,
        .block_creation_interval = 0,
    };
    const unauth_json = try unauthorized_policy.toJson(allocator);
    defer allocator.free(unauth_json);

    try args.resize(0);
    try args.append(unauth_json);

    const err = GovernanceSystem.invoke(&stub, "update_policy", args.items, "hacker");
    try testing.expectError(error.PermissionDenied, err);
}
