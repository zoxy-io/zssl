const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // libcrypto, built by Zig for the target — never found on the system.
    // Zig's C sanitizers are off for the vendored C in every mode: this is
    // zoxy's #283 verbatim (ReleaseSafe arms `-fsanitize=function` as a
    // `ud1` trap, and `OPENSSL_sk_pop_free` calling its `free_func` through
    // a cast pointer SIGILLs at key load). One setting for every mode keeps
    // the shipped archive identical to the tested one.
    const openssl_dependency = b.dependency("openssl", .{
        .target = target,
        .optimize = optimize,
    });
    const libcrypto = openssl_dependency.artifact("openssl");
    libcrypto.root_module.sanitize_c = .off;

    const zssl_module = b.addModule("zssl", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    zssl_module.link_libc = true;
    zssl_module.linkLibrary(libcrypto);

    const module_tests = b.addRunArtifact(b.addTest(.{ .root_module = zssl_module }));
    const test_step = b.step("test", "Run unit tests (RFC 8448 vectors + differentials)");
    test_step.dependOn(&module_tests.step);
}
