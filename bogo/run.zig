//! The adversarial gate: fetch the pinned BoGo runner, point it at
//! `bogo/shim.zig`, and hold the result against a floor.
//!
//! BoGo is BoringSSL's own hostile-peer test runner, a Go program that
//! plays a deliberately broken peer and asks what an implementation
//! *refuses* (docs/BOGO.md). It is not vendored — it is a pinned
//! checkout, fetched on first run into `zig-out/bogo/`, because the
//! corpus is 40k lines of Go that moves weekly and pinning is what makes
//! a run reproducible.
//!
//! Three numbers come back and all three matter:
//!
//!   - **passed** must be at least `passing_floor`. That is the whole
//!     anti-rot mechanism: `bogo/config.json` can disable a case with a
//!     reason, but it cannot disable one quietly, because the floor
//!     falls with it and the gate goes red.
//!   - **failed** must be zero. Every case that BoGo runs and we cannot
//!     satisfy is named in `config.json` with a one-line reason.
//!   - **skipped** is what the shim declined by exiting 89 — a version
//!     below 1.3, an RSA signing key, a flag outside the subset. Printed,
//!     never asserted on, because it moves with the pin.
//!
//! Exit status is the verdict, matching the interop gate: 0 passed,
//! 1 failed, 2 could not run (no Go toolchain, or no network on the
//! first run).

const std = @import("std");
const Io = std.Io;
const assert = std.debug.assert;

/// The pin. Moves deliberately, together with a re-run that re-derives
/// `passing_floor` — a corpus that has grown new cases will otherwise
/// look like a regression, and one that has dropped them like a win.
const boringssl_url = "https://boringssl.googlesource.com/boringssl";
const boringssl_commit = "193233b86d6cbbc20ce30c06a8775311c11be0c4";

/// What the pin above scored on 2026-08-28, on a tree with every fix
/// the BoGo and RSA slices landed, plus findings 4 and 5. Raise it
/// whenever a fix moves the number up; a drop is either a regression or
/// a suppression, and both deserve to stop the build.
const passing_floor: u32 = 266;

const work_dir = "zig-out/bogo";
const checkout_dir = work_dir ++ "/boringssl";
const runner_path = work_dir ++ "/bogo-runner";
const results_path = work_dir ++ "/results.json";
const log_path = work_dir ++ "/bogo.log";

/// Generous: a cold run clones ~8k files, downloads Go modules, and
/// builds a 22 MB test binary before a single case runs. A hang here is
/// a bug report, not a CI that never returns.
const watchdog_budget_ns: u64 = 45 * 60 * std.time.ns_per_s;

var watchdog_stage: std.atomic.Value(u8) = .init(0);
var watchdog_child_pid: std.atomic.Value(i32) = .init(0);

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();

    const options = try parseArguments(init, arena);

    var watchdog: Io.Group = .init;
    try watchdog.concurrent(io, watchdogTask, .{io});
    defer watchdog.cancel(io);

    const go = findGo(io) catch {
        std.debug.print(
            "bogo: SKIP — no Go toolchain on PATH; BoGo's runner is a Go program\n",
            .{},
        );
        return 2;
    };
    std.debug.print("bogo: using {s}\n", .{go});
    Io.Dir.cwd().createDirPath(io, work_dir) catch {};

    watchdog_stage.store(1, .release);
    ensureCheckout(io, arena) catch |err| {
        std.debug.print(
            "bogo: SKIP — could not fetch BoringSSL {s} ({t}); a first run needs network\n",
            .{ boringssl_commit[0..12], err },
        );
        return 2;
    };

    watchdog_stage.store(2, .release);
    buildRunner(io, arena, go) catch |err| {
        std.debug.print(
            "bogo: SKIP — could not build the BoGo runner ({t}); `go test -c` needs the module cache\n",
            .{err},
        );
        return 2;
    };

    watchdog_stage.store(3, .release);
    const outcome = runSuite(io, arena, options.shim_path, options.config_path, options.extra) catch |err| {
        std.debug.print("bogo: FAIL — the runner could not be driven ({t})\n", .{err});
        return 1;
    };

    watchdog_stage.store(4, .release);
    std.debug.print(
        "bogo: {d} passed, {d} failed, {d} declined by the shim (89), floor {d}\n",
        .{ outcome.passed, outcome.failed, outcome.skipped, passing_floor },
    );
    if (outcome.failed >= 1) {
        try printTail(io, arena);
        std.debug.print(
            "bogo: FAIL — {d} case(s) the runner ran and we did not satisfy; see {s}\n",
            .{ outcome.failed, log_path },
        );
        return 1;
    }
    // A filtered run is a debugging tool, not the gate: holding a
    // one-case invocation to the whole corpus's floor would only teach
    // people to pass `-include-disabled` and stop reading.
    if (options.extra.len >= 1) {
        if (outcome.passed == 0) {
            std.debug.print("bogo: FAIL — the filter matched no passing case\n", .{});
            return 1;
        }
        std.debug.print("bogo: PASS (filtered run — the floor applies to the full corpus)\n", .{});
        return 0;
    }
    if (outcome.passed < passing_floor) {
        std.debug.print(
            "bogo: FAIL — {d} passing, below the floor of {d}. Either a case regressed or one\n" ++
                "      was disabled in bogo/config.json; neither is allowed to be quiet.\n",
            .{ outcome.passed, passing_floor },
        );
        return 1;
    }
    std.debug.print("bogo: PASS\n", .{});
    return 0;
}

fn watchdogTask(io: Io) void {
    io.sleep(Io.Duration.fromNanoseconds(watchdog_budget_ns), .awake) catch return;
    const stage = watchdog_stage.load(.acquire);
    const name = switch (stage) {
        0 => "startup",
        1 => "fetching the pinned BoringSSL",
        2 => "building the runner",
        3 => "running the corpus",
        else => "teardown",
    };
    std.debug.print("bogo: FAIL — wedged in: {s}\n", .{name});
    const pid = watchdog_child_pid.load(.acquire);
    if (pid != 0) std.posix.kill(pid, std.posix.SIG.KILL) catch {};
    std.process.exit(1);
}

const Options = struct {
    shim_path: []const u8,
    config_path: []const u8,
    /// Anything after the two we own goes to the runner verbatim, so
    /// `zig build bogo -- -test 'TLS13-*' -debug` works.
    extra: []const []const u8,
};

fn parseArguments(init: std.process.Init, arena: std.mem.Allocator) !Options {
    var iterator = try std.process.Args.Iterator.initAllocator(init.minimal.args, arena);
    defer iterator.deinit();
    _ = iterator.skip();
    var shim_path: ?[]const u8 = null;
    var config_path: ?[]const u8 = null;
    var extra: std.ArrayList([]const u8) = .empty;
    while (iterator.next()) |argument| {
        if (std.mem.eql(u8, argument, "--shim")) {
            shim_path = try arena.dupe(u8, iterator.next() orelse return error.MissingShimPath);
        } else if (std.mem.eql(u8, argument, "--config")) {
            config_path = try arena.dupe(u8, iterator.next() orelse return error.MissingConfigPath);
        } else {
            try extra.append(arena, try arena.dupe(u8, argument));
        }
    }
    return .{
        .shim_path = shim_path orelse return error.MissingShimPath,
        .config_path = config_path orelse return error.MissingConfigPath,
        .extra = extra.items,
    };
}

fn findGo(io: Io) ![]const u8 {
    const candidates = [_][]const u8{
        "go",
        "/opt/homebrew/bin/go",
        "/usr/local/go/bin/go",
        "/usr/local/bin/go",
        "/usr/bin/go",
    };
    for (candidates) |candidate| {
        const status = run(io, &.{ candidate, "version" }, .ignore, .ignore) catch continue;
        if (status == 0) return candidate;
    }
    return error.NoGoToolchain;
}

/// Fetch exactly the pinned commit — not a branch, and not a clone that
/// would drift. `git fetch <sha>` works against googlesource, which is
/// what lets this be a pin rather than a snapshot of whatever main was.
fn ensureCheckout(io: Io, arena: std.mem.Allocator) !void {
    if (try checkoutIsCurrent(io, arena)) return;
    std.debug.print("bogo: fetching BoringSSL {s}\n", .{boringssl_commit[0..12]});
    Io.Dir.cwd().createDirPath(io, checkout_dir) catch {};
    const cwd: std.process.Child.Cwd = .{ .path = checkout_dir };
    // An existing repository answers "reinitialized"; a fresh directory
    // gets one. Both are the state the fetch below needs.
    _ = try runIn(io, &.{ "git", "init", "-q" }, cwd);
    // The remote may already be there from an earlier run, and a second
    // `remote add` is an error rather than a problem.
    _ = runIn(io, &.{ "git", "remote", "add", "origin", boringssl_url }, cwd) catch {};
    _ = runIn(io, &.{ "git", "remote", "set-url", "origin", boringssl_url }, cwd) catch {};
    // Blobless: the runner is a few hundred KB of Go inside a tree with
    // thousands of C files and test vectors we never compile.
    const fetched = try runIn(io, &.{
        "git",            "fetch",     "--depth", "1",
        "--filter",       "blob:none", "-q",      "origin",
        boringssl_commit,
    }, cwd);
    if (fetched != 0) return error.FetchFailed;
    const checked = try runIn(io, &.{ "git", "checkout", "-q", "--detach", "FETCH_HEAD" }, cwd);
    if (checked != 0) return error.CheckoutFailed;
    if (!try checkoutIsCurrent(io, arena)) return error.PinMismatch;
}

fn checkoutIsCurrent(io: Io, arena: std.mem.Allocator) !bool {
    const head = captureIn(io, arena, &.{ "git", "rev-parse", "HEAD" }, .{ .path = checkout_dir }) catch
        return false;
    return std.mem.startsWith(u8, std.mem.trim(u8, head, " \n\r\t"), boringssl_commit);
}

/// `go test -c` rather than `go test`: the runner's own flags collide
/// with `go test`'s (both define `-skip`), and a compiled binary takes
/// them unambiguously. It also means the corpus is built once and reused
/// across runs.
fn buildRunner(io: Io, arena: std.mem.Allocator, go: []const u8) !void {
    const absolute = try absolutePath(io, arena, runner_path);
    std.debug.print("bogo: building the runner\n", .{});
    const status = try runIn(io, &.{
        go, "test", "-c", "-o", absolute, "./ssl/test/runner",
    }, .{ .path = checkout_dir });
    if (status != 0) return error.GoBuildFailed;
}

const Outcome = struct { passed: u32, failed: u32, skipped: u32 };

fn runSuite(
    io: Io,
    arena: std.mem.Allocator,
    shim_path: []const u8,
    config_path: []const u8,
    extra: []const []const u8,
) !Outcome {
    const shim_absolute = try absolutePath(io, arena, shim_path);
    const config_absolute = try absolutePath(io, arena, config_path);
    const results_absolute = try absolutePath(io, arena, results_path);

    var argv: std.ArrayList([]const u8) = .empty;
    try argv.appendSlice(arena, &.{
        try absolutePath(io, arena, runner_path),
        "-test.run",
        "TestAll",
        "-test.timeout",
        "45m",
        "-shim-path",
        shim_absolute,
        "-shim-config",
        config_absolute,
        // PORTING.md's recommendation: a shim that exits 89 has declined
        // the case, and declining is not failing. What it declined is
        // printed above and audited in docs/BOGO.md.
        "-allow-unimplemented",
        // One line per case rather than a redrawn status line, so the
        // log is readable after the fact.
        "-pipe",
        "-json-output",
        results_absolute,
    });
    try argv.appendSlice(arena, extra);

    // Delete the previous run's results before spawning. A runner that
    // dies without writing — the test timeout firing, a Go panic, the
    // watchdog's SIGKILL — would otherwise leave last run's counts in
    // place, and the floor would clear on a run that executed nothing.
    Io.Dir.cwd().deleteFile(io, results_path) catch {};
    const log = try Io.Dir.cwd().createFile(io, log_path, .{});
    defer log.close(io);
    std.debug.print("bogo: running the corpus (this takes a few minutes)\n", .{});
    // The runner wants to be in its own package directory: it writes
    // temporary certificate files beside itself.
    var child = try std.process.spawn(io, .{
        .argv = argv.items,
        .cwd = .{ .path = checkout_dir ++ "/ssl/test/runner" },
        .stdin = .ignore,
        .stdout = .{ .file = log },
        .stderr = .{ .file = log },
    });
    watchdog_child_pid.store(child.id orelse 0, .release);
    defer watchdog_child_pid.store(0, .release);
    // The exit status is not the verdict here — the counts are, and a
    // runner that failed cases exits non-zero with them still written.
    _ = try child.wait(io);
    return parseResults(io, arena);
}

/// The Chromium JSON test-results format the runner writes: a count per
/// outcome, and a per-test map this gate does not need.
fn parseResults(io: Io, arena: std.mem.Allocator) !Outcome {
    const contents = try readFile(io, arena, results_path);
    // Every shape below is a file the runner did not finish writing, and
    // each one has to be an error rather than a panic: this is the path
    // that decides whether the floor is allowed to clear.
    if (contents.len == 0) return error.MalformedResults;
    const parsed = try std.json.parseFromSlice(std.json.Value, arena, contents, .{});
    if (parsed.value != .object) return error.MalformedResults;
    // The runner sets this when it stopped early; the counts under it are
    // a prefix of the corpus and must not be read as a whole run.
    if (parsed.value.object.get("interrupted")) |flag| {
        if (flag == .bool and flag.bool) return error.RunInterrupted;
    }
    const counts = parsed.value.object.get("num_failures_by_type") orelse
        return error.MalformedResults;
    if (counts != .object) return error.MalformedResults;
    return .{
        .passed = countOf(counts, "PASS"),
        .failed = countOf(counts, "FAIL"),
        .skipped = countOf(counts, "SKIP"),
    };
}

fn countOf(counts: std.json.Value, key: []const u8) u32 {
    assert(key.len >= 1);
    const value = counts.object.get(key) orelse return 0;
    return switch (value) {
        .integer => |number| if (number >= 0) @intCast(number) else 0,
        else => 0,
    };
}

/// The last stretch of the runner's log, which is where the failures it
/// printed live. Enough to name them without pasting a 7000-line file.
fn printTail(io: Io, arena: std.mem.Allocator) !void {
    const contents = readFile(io, arena, log_path) catch return;
    var lines: std.ArrayList([]const u8) = .empty;
    var iterator = std.mem.splitScalar(u8, contents, '\n');
    while (iterator.next()) |line| {
        if (std.mem.startsWith(u8, line, "FAILED (")) try lines.append(arena, line);
    }
    for (lines.items, 0..) |line, index| {
        if (index == 40) {
            std.debug.print("bogo: ... and {d} more\n", .{lines.items.len - index});
            break;
        }
        std.debug.print("bogo: {s}\n", .{line});
    }
}

fn absolutePath(io: Io, arena: std.mem.Allocator, path: []const u8) ![]const u8 {
    if (path.len >= 1 and path[0] == '/') return path;
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const used = try std.process.currentPath(io, &buffer);
    return std.fmt.allocPrint(arena, "{s}/{s}", .{ buffer[0..used], path });
}

fn readFile(io: Io, arena: std.mem.Allocator, path: []const u8) ![]const u8 {
    const file = try Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);
    const buffer = try arena.alloc(u8, 64 * 1024);
    var reader = file.reader(io, buffer);
    var sink: std.ArrayList(u8) = .empty;
    var chunks: u32 = 0;
    // A results file larger than this is not a results file. The bound is
    // ours, so it is a counted loop rather than an unbounded one.
    while (chunks < read_chunks_max) : (chunks += 1) {
        const room = try sink.addManyAsSlice(arena, read_chunk_bytes);
        const filled = sink.items.len - room.len;
        // Trim back to what was actually read on every pass, the failing
        // one included: leaving a partly written chunk on the list would
        // hand the JSON parser 64 KiB of whatever the arena last held.
        const read_bytes = reader.interface.readSliceShort(room) catch {
            sink.shrinkRetainingCapacity(filled);
            break;
        };
        sink.shrinkRetainingCapacity(filled + read_bytes);
        if (read_bytes == 0) break;
    }
    assert(sink.items.len <= read_chunks_max * read_chunk_bytes);
    return sink.items;
}

/// 64 MiB of results or log, which no honest run approaches.
const read_chunk_bytes: usize = 64 * 1024;
const read_chunks_max: u32 = 1024;

fn run(
    io: Io,
    argv: []const []const u8,
    stdout: std.process.SpawnOptions.StdIo,
    stderr: std.process.SpawnOptions.StdIo,
) !u8 {
    assert(argv.len >= 1);
    var child = try std.process.spawn(io, .{
        .argv = argv,
        .stdin = .ignore,
        .stdout = stdout,
        .stderr = stderr,
    });
    return switch (try child.wait(io)) {
        .exited => |code| code,
        else => 1,
    };
}

fn runIn(
    io: Io,
    argv: []const []const u8,
    cwd: std.process.Child.Cwd,
) !u8 {
    assert(argv.len >= 1);
    var child = try std.process.spawn(io, .{
        .argv = argv,
        .cwd = cwd,
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .inherit,
    });
    watchdog_child_pid.store(child.id orelse 0, .release);
    defer watchdog_child_pid.store(0, .release);
    return switch (try child.wait(io)) {
        .exited => |code| code,
        else => 1,
    };
}

fn captureIn(
    io: Io,
    arena: std.mem.Allocator,
    argv: []const []const u8,
    cwd: std.process.Child.Cwd,
) ![]const u8 {
    var child = try std.process.spawn(io, .{
        .argv = argv,
        .cwd = cwd,
        .stdin = .ignore,
        .stdout = .pipe,
        .stderr = .ignore,
    });
    var output = child.stdout.?.reader(io, try arena.alloc(u8, 4096));
    var sink: [4096]u8 = undefined;
    const read_bytes = output.interface.readSliceShort(&sink) catch 0;
    switch (try child.wait(io)) {
        .exited => |code| if (code != 0) return error.CommandFailed,
        else => return error.CommandSignalled,
    }
    return arena.dupe(u8, sink[0..read_bytes]);
}
