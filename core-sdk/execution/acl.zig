// acl.zig - Access Control Logic
// Implements Role-Based Access Control (RBAC) for Adria Ledger

const std = @import("std");
const types = @import("common").types;
const db = @import("db.zig");

/// Role Definitions
pub const Role = enum(u8) {
    None = 0,
    Admin = 1, // Can manage network, upgrade chaincode, etc.
    Writer = 2, // Can invoke chaincode (write to ledger)
    Reader = 3, // Can query ledger (if private)
    Validator = 4, // Can produce blocks
};

pub const AccessControl = struct {
    /// Initialize ACL
    pub fn init() AccessControl {
        return AccessControl{};
    }

    /// Check if an address has the required role
    /// Returns true if authorized, false otherwise
    /// Check if an address has the required role
    /// Returns true if authorized, false otherwise
    pub fn checkPermission(self: *AccessControl, database: *db.Database, address: types.Address, required_role: Role) !bool {
        _ = self;

        // 1. Check On-Chain Governance Policy for Root Admins
        const governance = @import("system/governance.zig");
        if (database.get(governance.GovernanceSystem.CONFIG_KEY) catch null) |policy_json| {
            defer database.allocator.free(policy_json);

            // Parse Policy
            // We use a temporary arena for parsing to avoid leaks in logic
            var arena = std.heap.ArenaAllocator.init(database.allocator);
            defer arena.deinit();
            const allocator = arena.allocator();

            const parsed = std.json.parseFromSlice(governance.GovernancePolicy, allocator, policy_json, .{ .ignore_unknown_fields = true }) catch {
                // If policy is corrupted, fail safe
                return false;
            };
            const policy = parsed.value;

            // Check if address is in root_cas
            const sender_hex = std.fmt.allocPrint(allocator, "{s}", .{std.fmt.fmtSliceHexLower(&address)}) catch return false;

            for (policy.root_cas) |admin_key| {
                if (std.mem.eql(u8, admin_key, sender_hex)) {
                    // Root Admin has ALL permissions
                    return true;
                }
            }
        }

        // Fetch local account from database (Legacy/Role-based)
        const account = database.getAccount(address) catch |err| {
            if (err == error.NotFound) return false;
            return err;
        };

        // Admin (1) stored in account role (Legacy support)
        if (account.role == @intFromEnum(Role.Admin)) return true;

        // Check specific role match
        if (account.role == @intFromEnum(required_role)) return true;

        return false;
    }

    /// Grant a role to an address (Admin only operation usually, but here just logic)
    /// This function would likely be called by a system chaincode
    /// Grant a role to an address (Admin only operation usually, but here just logic)
    /// This function would likely be called by a system chaincode
    pub fn grantRole(self: *AccessControl, database: *db.Database, address: types.Address, role: Role) !void {
        _ = self;
        var account = try database.getAccount(address);
        account.role = @intFromEnum(role);
        try database.saveAccount(address, account);
    }
};
