// consensus/mod.zig - Pluggable Consensus Interface
// Defines the contract that 'main.zig' uses to talk to the ordering service.

const std = @import("std");

// Re-export interface definitions
pub usingnamespace @import("interface.zig");

// Export implementations
pub const solo = @import("solo.zig");
