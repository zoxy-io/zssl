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

    // One step per oracle that lives in the suite, so each can carry its
    // own CI workflow and its own badge.
    //
    // Split by *file* rather than by `filters`, deliberately. A
    // compile-time filter that matches nothing still builds, runs zero
    // tests and exits 0 — a green badge over an empty run, which is the
    // one failure this tree treats as worse than a red one. A file either
    // holds tests or does not compile. (Zig 0.16 has no runtime
    // `--test-filter`; its test runner panics on the argument.)
    //
    // `zig build test` still runs everything through `src/root.zig`, and
    // remains the authority. These are windows onto it, not a partition
    // of it.
    const Suite = struct { step: []const u8, file: []const u8, blurb: []const u8 };
    const suites = [_]Suite{
        .{
            .step = "test-rfc8448",
            .file = "src/rfc8448_test.zig",
            .blurb = "RFC 8448's traced bytes, replayed",
        },
        .{
            .step = "test-std-interop",
            .file = "src/std_interop_test.zig",
            .blurb = "A handshake against std.crypto.tls",
        },
        .{
            .step = "test-fuzz",
            .file = "src/fuzz_test.zig",
            .blurb = "Fuzz targets over parsers and both machines",
        },
    };
    for (suites) |suite| {
        const suite_module = b.createModule(.{
            .root_source_file = b.path(suite.file),
            .target = target,
            .optimize = optimize,
        });
        suite_module.link_libc = true;
        suite_module.linkLibrary(libcrypto);
        const suite_tests = b.addTest(.{ .root_module = suite_module });
        const suite_run = b.addRunArtifact(suite_tests);
        b.step(suite.step, suite.blurb).dependOn(&suite_run.step);
    }

    // A second build of the same tests, for kcov only.
    //
    // `use_llvm` is the whole point. Zig's self-hosted x86_64 backend is
    // the default for Debug on Linux, and kcov cannot map the DWARF it
    // emits: pointed at a self-hosted binary it reports 888 source files,
    // every one of them the vendored OpenSSL C compiled through clang,
    // and not a single `.zig`. That is what produced a 0% badge from a
    // run where all 83 tests passed under the tool. macOS defaults to
    // LLVM, which is why the same command measured 97% there and hid the
    // problem. Asking for LLVM explicitly makes the two agree.
    const coverage_tests = b.addTest(.{ .root_module = zssl_module, .use_llvm = true });
    const test_step = b.step("test", "Run unit tests (RFC 8448 vectors + differentials)");
    test_step.dependOn(&module_tests.step);

    // Line coverage over the suite, via kcov's DWARF instrumentation —
    // the same binary `zig build test` runs, under a tool rather than
    // directly. Scoped to `src/`: libcrypto is vendored C we do not
    // write, and the test fixtures are data.
    //
    // The patterns have no leading slash on purpose. kcov matches them
    // against the path as DWARF records it, and that is not the same
    // shape everywhere: macOS carried absolute paths, so `/src/` worked
    // there, while Linux recorded them relative to the compilation
    // directory and `/src/` matched *nothing* — a 0% badge from a run
    // that instrumented zero files. Without the slash both shapes match.
    const coverage_run = b.addSystemCommand(&.{
        "kcov",
        "--clean",
        "--include-pattern=src/",
        "--exclude-pattern=src/testdata/,zig-pkg/,.zig-cache/",
    });
    // The build system owns the output directory rather than kcov: kcov
    // creates its target but not the target's parent, and nothing else in
    // this build has any reason to create `zig-out`, so a first run on a
    // clean checkout — which is every CI run — died on the missing parent.
    // `addOutputDirectoryArg` makes the directory, passes it as the
    // argument, and hands back the path to install from.
    const coverage_output = coverage_run.addOutputDirectoryArg("coverage");
    coverage_run.addArtifactArg(coverage_tests);
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

    // The second adversarial gate: tlsfuzzer, a TLS client in Python over
    // tlslite-ng. It drives our *server* through hundreds of
    // conversations per script, which is the half BoGo reaches least.
    const tlsfuzzer_server_module = b.createModule(.{
        .root_source_file = b.path("tlsfuzzer/server.zig"),
        .target = target,
        .optimize = optimize,
    });
    tlsfuzzer_server_module.addImport("zssl", zssl_module);
    const tlsfuzzer_server = b.addExecutable(.{
        .name = "zssl-tlsfuzzer-server",
        .root_module = tlsfuzzer_server_module,
    });
    const tlsfuzzer_module = b.createModule(.{
        .root_source_file = b.path("tlsfuzzer/run.zig"),
        .target = target,
        .optimize = optimize,
    });
    const tlsfuzzer_exe = b.addExecutable(.{
        .name = "zssl-tlsfuzzer",
        .root_module = tlsfuzzer_module,
    });
    const tlsfuzzer_run = b.addRunArtifact(tlsfuzzer_exe);
    tlsfuzzer_run.has_side_effects = true;
    tlsfuzzer_run.addArg("--server");
    tlsfuzzer_run.addArtifactArg(tlsfuzzer_server);
    tlsfuzzer_run.addArg("--config");
    tlsfuzzer_run.addFileArg(b.path("tlsfuzzer/scripts.json"));
    const tlsfuzzer_step = b.step("tlsfuzzer", "Adversarial gate: tlsfuzzer's scripts against our server");
    tlsfuzzer_step.dependOn(&tlsfuzzer_run.step);

    // The third adversarial gate: TLS-Anvil's RFC-derived corpus, in a
    // container, against the same server harness tlsfuzzer drives. It
    // reuses that harness rather than growing a third one — see
    // tlsanvil/run.zig.
    const tlsanvil_module = b.createModule(.{
        .root_source_file = b.path("tlsanvil/run.zig"),
        .target = target,
        .optimize = optimize,
    });
    const tlsanvil_exe = b.addExecutable(.{
        .name = "zssl-tlsanvil",
        .root_module = tlsanvil_module,
    });
    const tlsanvil_run = b.addRunArtifact(tlsanvil_exe);
    tlsanvil_run.has_side_effects = true;
    tlsanvil_run.addArg("--server");
    tlsanvil_run.addArtifactArg(tlsfuzzer_server);
    tlsanvil_run.addArg("--config");
    tlsanvil_run.addFileArg(b.path("tlsanvil/tests.json"));
    const tlsanvil_step = b.step("tlsanvil", "Adversarial gate: TLS-Anvil's RFC corpus against our server");
    tlsanvil_step.dependOn(&tlsanvil_run.step);

    const tlsfuzzer_server_step = b.step(
        "tlsfuzzer-server",
        "Run the tlsfuzzer server harness on its own (for manual scripts)",
    );
    const tlsfuzzer_server_run = b.addRunArtifact(tlsfuzzer_server);
    tlsfuzzer_server_run.has_side_effects = true;
    if (b.args) |forwarded| tlsfuzzer_server_run.addArgs(forwarded);
    tlsfuzzer_server_step.dependOn(&tlsfuzzer_server_run.step);
}
