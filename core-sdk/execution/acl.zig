// acl.zig - Access Control Logic
// Implements Role-Based Access Control (RBAC) for Adria Ledger

const std = @import("std");
const types = @import("../common/types.zig");
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
        _ = self; // Future use

        // Fetch account from database
        const account = database.getAccount(address) catch |err| {
            if (err == error.NotFound) return false;
            return err;
        };

        // Admin (1) has permission for everything
        if (account.role == @intFromEnum(Role.Admin)) return true;

        // Check specific role match
        // In this simple model, we check for exact match or superiority
        // For now, let's keep it simple: strict match or Admin overrides
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
