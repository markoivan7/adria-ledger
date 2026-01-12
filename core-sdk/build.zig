const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Adria Server
    const adria_server = b.addExecutable(.{
        .name = "adria_server",
        .root_source_file = b.path("server.zig"),
        .target = target,
        .optimize = optimize,
    });
    adria_server.linkLibC();
    b.installArtifact(adria_server);

    // APL CLI - Adria command line interface
    const apl_cli = b.addExecutable(.{
        .name = "apl",
        .root_source_file = b.path("cli.zig"),
        .target = target,
        .optimize = optimize,
    });
    apl_cli.linkLibC();
    b.installArtifact(apl_cli);

    // Unit Tests
    const unit_tests = b.addTest(.{
        .root_source_file = b.path("main.zig"),
        .target = target,
        .optimize = optimize,
    });
    unit_tests.linkLibC();

    const run_unit_tests = b.addRunArtifact(unit_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);

    // Run Step
    const run_cmd = b.addRunArtifact(adria_server);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }
    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);
}
