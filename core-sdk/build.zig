const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Modules
    const common_mod = b.addModule("common", .{
        .root_source_file = b.path("common/mod.zig"),
    });

    const crypto_mod = b.addModule("crypto", .{
        .root_source_file = b.path("crypto/mod.zig"),
    });
    crypto_mod.addImport("common", common_mod);

    const execution_mod = b.addModule("execution", .{
        .root_source_file = b.path("execution/mod.zig"),
    });
    execution_mod.addImport("common", common_mod);
    execution_mod.addImport("crypto", crypto_mod);

    const consensus_mod = b.addModule("consensus", .{
        .root_source_file = b.path("consensus/mod.zig"),
    });
    consensus_mod.addImport("common", common_mod);
    consensus_mod.addImport("crypto", crypto_mod);
    consensus_mod.addImport("execution", execution_mod);

    // Adria Server
    const adria_server = b.addExecutable(.{
        .name = "adria_server",
        .root_source_file = b.path("server.zig"),
        .target = target,
        .optimize = optimize,
    });
    adria_server.root_module.addImport("common", common_mod);
    adria_server.root_module.addImport("crypto", crypto_mod);
    adria_server.root_module.addImport("execution", execution_mod);
    adria_server.root_module.addImport("consensus", consensus_mod);
    adria_server.linkLibC();
    b.installArtifact(adria_server);

    // APL CLI - Adria command line interface
    const apl_cli = b.addExecutable(.{
        .name = "apl",
        .root_source_file = b.path("cli.zig"),
        .target = target,
        .optimize = optimize,
    });
    apl_cli.root_module.addImport("common", common_mod);
    apl_cli.root_module.addImport("crypto", crypto_mod);
    apl_cli.root_module.addImport("execution", execution_mod);
    apl_cli.linkLibC();
    b.installArtifact(apl_cli);

    // Fast Client - Native Load Generator
    const fast_client = b.addExecutable(.{
        .name = "fast_client",
        .root_source_file = b.path("tools/fast_client.zig"),
        .target = target,
        .optimize = optimize,
    });
    fast_client.root_module.addImport("common", common_mod);
    fast_client.root_module.addImport("crypto", crypto_mod);
    fast_client.linkLibC();
    b.installArtifact(fast_client);

    // E2E Benchmark Suite
    const bench_e2e = b.addExecutable(.{
        .name = "bench_e2e",
        .root_source_file = b.path("benchmarks/bench_e2e.zig"),
        .target = target,
        .optimize = optimize,
    });
    bench_e2e.root_module.addImport("common", common_mod);
    bench_e2e.root_module.addImport("crypto", crypto_mod);
    bench_e2e.linkLibC();
    b.installArtifact(bench_e2e);

    // Crypto Benchmark
    const bench_crypto = b.addExecutable(.{
        .name = "bench_crypto",
        .root_source_file = b.path("benchmarks/bench_crypto.zig"),
        .target = target,
        .optimize = optimize,
    });
    bench_crypto.root_module.addImport("common", common_mod);
    bench_crypto.root_module.addImport("crypto", crypto_mod);
    bench_crypto.linkLibC();
    b.installArtifact(bench_crypto);

    // Consensus Benchmark
    const bench_consensus = b.addExecutable(.{
        .name = "bench_consensus",
        .root_source_file = b.path("benchmarks/bench_consensus.zig"),
        .target = target,
        .optimize = optimize,
    });
    bench_consensus.root_module.addImport("common", common_mod);
    bench_consensus.root_module.addImport("crypto", crypto_mod);
    bench_consensus.root_module.addImport("execution", execution_mod);
    bench_consensus.root_module.addImport("consensus", consensus_mod);
    bench_consensus.linkLibC();
    b.installArtifact(bench_consensus);

    // Genesis Generator Tool
    const genesis_gen = b.addExecutable(.{
        .name = "genesis_gen",
        .root_source_file = b.path("tools/genesis_gen.zig"),
        .target = target,
        .optimize = optimize,
    });
    genesis_gen.root_module.addImport("common", common_mod);
    genesis_gen.root_module.addImport("crypto", crypto_mod);
    genesis_gen.root_module.addImport("execution", execution_mod);
    genesis_gen.linkLibC();
    b.installArtifact(genesis_gen);

    // Unit Tests
    const unit_tests = b.addTest(.{
        .root_source_file = b.path("main.zig"),
        .target = target,
        .optimize = optimize,
    });
    unit_tests.root_module.addImport("common", common_mod);
    unit_tests.root_module.addImport("crypto", crypto_mod);
    unit_tests.root_module.addImport("execution", execution_mod);
    unit_tests.root_module.addImport("consensus", consensus_mod);
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
