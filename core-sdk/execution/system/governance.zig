// governance.zig - System Chaincode for Governance
// Manages network-wide configuration and access control policies

const std = @import("std");
const chaincode = @import("../chaincode.zig");
const json = std.json;

/// Governance Policy Structure (On-Chain Config)
pub const GovernancePolicy = struct {
    // List of Root Certificate Authorities (Hex encoded public keys)
    // These keys can sign valid Identity Certificates
    root_cas: []const []const u8,

    // Minimum number of validators required for consensus (future use)
    min_validator_count: u32,

    // Target block creation time in seconds
    block_creation_interval: u64,

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
            // Public read (or can be restricted)
            return getPolicy(stub);
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

        // If no policy exists, we are in Genesis mode (bootstrapping).
        // Only allow if this is the VERY FIRST transaction... or we assume Genesis block sets it.
        // If it's missing, we default to "Allow All" or "Deny All"?
        // Safe default: Initial setup MUST be done via Genesis block.
        // So checking sender against *CURRENT* root CAs.

        if (current_policy_json) |policy_json| {
            defer stub.allocator.free(policy_json);

            // Parse current policy
            const parsed = try json.parseFromSlice(GovernancePolicy, stub.allocator, policy_json, .{ .ignore_unknown_fields = true });
            defer parsed.deinit();
            const policy = parsed.value;

            // Check if sender is in root_cas list
            var is_admin = false;
            for (policy.root_cas) |admin_key| {
                if (std.mem.eql(u8, admin_key, sender)) {
                    is_admin = true;
                    break;
                }
            }

            if (!is_admin) {
                // TODO: Implement proper error types in ChaincodeError
                return error.PermissionDenied;
            }
        } else {
            // Bootstrapping: If state is empty, allow update?
            // This is dangerous. Better to fail if not initialized.
            // But for development convenience we might allow it.
            // Let's FAIL. Genesis block MUST set initial state.
            return chaincode.ChaincodeError.InternalError;
        }

        // 2. Validate New Policy (Schema check)
        const parsed_new = json.parseFromSlice(GovernancePolicy, stub.allocator, new_policy_json, .{ .ignore_unknown_fields = true }) catch {
            return chaincode.ChaincodeError.InvalidArguments;
        };
        defer parsed_new.deinit();

        // 3. Commit Update
        // We must copy the JSON because putState takes ownership or copies?
        // Stub.putState copies.
        try stub.putState(CONFIG_KEY, new_policy_json);

        return stub.allocator.dupe(u8, "OK");
    }

    /// Get current policy
    fn getPolicy(stub: *chaincode.Stub) ![]u8 {
        const val = try stub.getState(CONFIG_KEY);
        if (val) |v| {
            defer stub.allocator.free(v); // Free the copy we got from getState
            return stub.allocator.dupe(u8, v); // Return new copy for caller
        }
        return chaincode.ChaincodeError.NotFound;
    }
};

test "governance policy update" {
    const testing = std.testing;
    const db = @import("../db.zig"); // Adjust path if needed

    // Setup Mock Stub
    // Since Stub relies on real DB in this project, we might need a integration-ish test
    // or mock the DB.
    // For now, let's create a temporary DB.

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
    // Actually our impl returns InternalError if no policy.
    // We must bootstrap it first manually (simulating Genesis).

    const admin_key = "admin_pubkey_hex";
    const initial_policy = GovernancePolicy{
        .root_cas = &[_][]const u8{admin_key},
        .min_validator_count = 1,
        .block_creation_interval = 10,
    };
    const initial_json = try initial_policy.toJson(allocator);
    defer allocator.free(initial_json);

    try stub.putState(GovernanceSystem.CONFIG_KEY, initial_json);
    // Commit to DB (Stub buffers it, but getPolicy reads from Stub too)
    // Actually we don't need to commit to DB for Stub to see its own writes if implemented correctly.
    // However, Stub.getState checks write_set. So yes.

    // 2. Try Update with valid Admin
    const new_policy = GovernancePolicy{
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
