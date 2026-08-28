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
    const libcrypto = openssl_dependency.artifact("crypto");
    libcrypto.root_module.sanitize_c = .off;

    const zssl_module = b.addModule("zssl", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    zssl_module.link_libc = true;
    zssl_module.linkLibrary(libcrypto);

    const unit_tests = b.addTest(.{ .root_module = zssl_module });
    const module_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run unit tests (RFC 8448 vectors + differentials)");
    test_step.dependOn(&module_tests.step);

    // Line coverage over the suite, via kcov's DWARF instrumentation —
    // the same binary `zig build test` runs, under a tool rather than
    // directly. Scoped to `src/`: libcrypto is vendored C we do not
    // write, and the test fixtures are data.
    //
    // kcov is a Linux tool. On macOS this step will not find it, which
    // is why CI is where the number comes from.
    const coverage_run = b.addSystemCommand(&.{
        "kcov",
        "--clean",
        "--include-pattern=/src/",
        "--exclude-pattern=/src/testdata/,/zig-pkg/,/.zig-cache/",
    });
    // The build system owns the output directory rather than kcov: kcov
    // creates its target but not the target's parent, and nothing else in
    // this build has any reason to create `zig-out`, so a first run on a
    // clean checkout — which is every CI run — died on the missing parent.
    // `addOutputDirectoryArg` makes the directory, passes it as the
    // argument, and hands back the path to install from.
    const coverage_output = coverage_run.addOutputDirectoryArg("coverage");
    coverage_run.addArtifactArg(unit_tests);
    const coverage_install = b.addInstallDirectory(.{
        .source_dir = coverage_output,
        .install_dir = .prefix,
        .install_subdir = "coverage",
    });
    const coverage_step = b.step("coverage", "Line coverage of the unit suite (needs kcov)");
    coverage_step.dependOn(&coverage_install.step);

    // The interop gate: our machines against the real `openssl` binary —
    // genuine libssl, no shared code. Its own executable rather than a
    // test, because it spawns processes and binds sockets, and because a
    // developer without an openssl on PATH should get a SKIP they can
    // read rather than a red unit suite.
    const interop_module = b.createModule(.{
        .root_source_file = b.path("interop/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    interop_module.addImport("zssl", zssl_module);
    interop_module.addAnonymousImport("cert_pem", .{ .root_source_file = b.path("src/testdata/cert.pem") });
    interop_module.addAnonymousImport("key_pem", .{ .root_source_file = b.path("src/testdata/key.pem") });
    const interop_exe = b.addExecutable(.{ .name = "zssl-interop", .root_module = interop_module });
    const interop_run = b.addRunArtifact(interop_exe);
    interop_run.has_side_effects = true;
    const interop_step = b.step("interop", "Interop gate: openssl s_client/s_server against zssl");
    interop_step.dependOn(&interop_run.step);

    // The adversarial gate: BoringSSL's BoGo runner plays a hostile peer
    // and asks what we *refuse*. `bogo/shim.zig` is the binary it drives;
    // `bogo/run.zig` fetches the pinned runner, invokes it, and holds the
    // result against the floor recorded in bogo/config.json. Like the
    // interop gate it is an executable rather than a test: it clones,
    // spawns `go`, and binds sockets, and a machine without Go should get
    // a SKIP it can read rather than a red suite.
    const shim_module = b.createModule(.{
        .root_source_file = b.path("bogo/shim.zig"),
        .target = target,
        .optimize = optimize,
    });
    shim_module.addImport("zssl", zssl_module);
    const shim_exe = b.addExecutable(.{ .name = "zssl-bogo-shim", .root_module = shim_module });

    const bogo_module = b.createModule(.{
        .root_source_file = b.path("bogo/run.zig"),
        .target = target,
        .optimize = optimize,
    });
    const bogo_exe = b.addExecutable(.{ .name = "zssl-bogo", .root_module = bogo_module });
    const bogo_run = b.addRunArtifact(bogo_exe);
    bogo_run.has_side_effects = true;
    bogo_run.addArg("--shim");
    bogo_run.addArtifactArg(shim_exe);
    bogo_run.addArg("--config");
    bogo_run.addFileArg(b.path("bogo/config.json"));
    if (b.args) |forwarded| bogo_run.addArgs(forwarded);
    const bogo_step = b.step("bogo", "Adversarial gate: BoringSSL's BoGo runner against zssl");
    bogo_step.dependOn(&bogo_run.step);
}
