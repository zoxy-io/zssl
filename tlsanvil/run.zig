//! The TLS-Anvil gate: drive TLS-Anvil's RFC-derived corpus at our
//! server and hold the result against a floor (docs/TLSANVIL.md).
//!
//! The third adversarial oracle, and the first whose cases are derived
//! from the RFCs rather than from an implementation. BoGo is BoringSSL's
//! own regression corpus and tlsfuzzer is hand-written attack scripts;
//! both are shaped by what their authors already believed could go
//! wrong. TLS-Anvil enumerates requirements out of 14 RFCs and combines
//! them, which is a different way of being wrong and therefore a
//! different set of things it can catch.
//!
//! Where it differs from the other two in shape:
//!
//!   - it ships as a container, so the pin is an image digest rather
//!     than a git commit, and the SKIP is "no Docker" rather than "no Go";
//!   - it scopes itself. Client-side cases disable themselves against a
//!     server ("TestEndpointMode doesn't match") and TLS 1.2 ones against
//!     a 1.3-only peer ("ProtocolVersion of the test is not supported"),
//!     so the declined count comes from the tool, the way BoGo's exit-89
//!     does, rather than from a ledger we maintain;
//!   - it reuses `tlsfuzzer/server.zig` as the server under test. That
//!     harness is already a long-lived listener that echoes application
//!     data, which is exactly the shape TLS-Anvil wants, and a third
//!     harness would be a third thing to keep correct.
//!
//! Exit status is the verdict: 0 passed, 1 failed, 2 could not run.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const assert = std.debug.assert;

/// The pin, by digest rather than by tag. `:latest` is a moving target
/// and a gate whose corpus can change underneath it measures nothing.
const tlsanvil_image = "ghcr.io/tls-attacker/tlsanvil";
const tlsanvil_digest = "sha256:a8a4bb924b09453926ccb4721028c68051c7b61168829469a28f5af47df311d4";

/// What the pin above scores on this tree: 115 of the 116 tests that run,
/// out of 437 the corpus holds. Raise it whenever a fix moves the number
/// up; a drop is either a regression or a suppression, and both deserve
/// to stop the build.
const passing_floor: u32 = 115;

const work_dir = "zig-out/tlsanvil";
const results_dir = work_dir ++ "/results";
const log_path = work_dir ++ "/tlsanvil.log";

/// The loopback port the harness binds. Fixed rather than ephemeral
/// because it is passed to a container on its command line.
const server_port: u16 = 4435;

/// How a container reaches a harness bound to 127.0.0.1, which differs
/// by platform because Docker's host networking does.
///
/// On Linux `--add-host=host.docker.internal:host-gateway` resolves to
/// the bridge gateway (172.17.0.1 on a default docker0), and a listener
/// bound to loopback is *not* reachable there — the corpus retries
/// "Server not yet available" until the 90-minute watchdog fires, which
/// is how this gate spent its first Linux run. Host networking puts the
/// container in the host's network namespace instead, so 127.0.0.1 is
/// the same 127.0.0.1 the harness bound, and nothing is published on any
/// interface. On macOS the reverse holds: Docker Desktop runs a VM, its
/// `host.docker.internal` proxies through to the host's loopback, and
/// `--network=host` does not give the container the host's stack.
///
/// The harness stays on loopback either way. Binding 0.0.0.0 would make
/// one flag serve both, and would also put a test server that speaks to
/// anyone on every interface of the machine running the gate.
///
/// What this actually keys on is `builtin.os.tag` — the OS running the
/// `docker` client — plus an unstated assumption that the daemon is
/// local and shares that OS. Both hold on `ubuntu-latest`, which is
/// where CI runs it. Two setups break the assumption and land back in
/// the 90-minute stall above: WSL2, which reports `.linux` while Docker
/// Desktop's daemon lives in a separate VM whose namespace
/// `--network=host` joins instead of the distro's, and a `DOCKER_HOST`
/// pointing at a remote engine, where host networking joins that
/// machine's namespace and not the one the harness bound. Neither is
/// worth detecting here; both are worth naming, because the symptom is
/// a silent retry loop rather than an error.
///
/// Note what the host-side liveness probe cannot do for this: it dials
/// 127.0.0.1 from the host, which is the path that works even when the
/// container's path does not, so a reachability failure looks perfectly
/// healthy to it. Only the corpus's own silence reveals it.
///
/// The flag and the address are one value rather than two ternaries:
/// they must agree, and a third platform added to one and not the other
/// is exactly the silent mismatch this constant exists to end.
const Networking = struct { flag: []const u8, host: []const u8 };
const networking: Networking = if (builtin.os.tag == .linux)
    .{ .flag = "--network=host", .host = "127.0.0.1" }
else
    .{ .flag = "--add-host=host.docker.internal:host-gateway", .host = "host.docker.internal" };

/// TLS-Anvil is a JVM in a container running an amd64 image; on an
/// arm64 host it runs under emulation and takes about four times as
/// long. Generous enough for that, short enough that a wedged run is
/// still a build failure rather than a career.
const watchdog_budget_ns: u64 = 90 * 60 * std.time.ns_per_s;

/// How often the harness is checked for signs of life while the corpus
/// runs. The first measurement this gate was built from sat for 46
/// minutes talking to a server that had already aborted, because nothing
/// was watching. A gate that cannot tell "the peer refuses my cases"
/// from "the peer is gone" reports the second as the first.
const liveness_interval_ns: u64 = 15 * std.time.ns_per_s;

var watchdog_stage: std.atomic.Value(u8) = .init(0);
var watchdog_server_pid: std.atomic.Value(i32) = .init(0);
var harness_died: std.atomic.Value(bool) = .init(false);
var corpus_running: std.atomic.Value(bool) = .init(false);

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();
    const options = try parseArguments(init, arena);

    var watchdog: Io.Group = .init;
    try watchdog.concurrent(io, watchdogTask, .{io});
    defer watchdog.cancel(io);

    watchdog_stage.store(1, .release);
    if (!dockerAvailable(io)) {
        std.debug.print(
            "tlsanvil: SKIP — no reachable Docker daemon; TLS-Anvil ships as a container\n",
            .{},
        );
        return 2;
    }
    Io.Dir.cwd().createDirPath(io, results_dir) catch {};

    watchdog_stage.store(2, .release);
    ensureImage(io, arena) catch |err| {
        std.debug.print(
            "tlsanvil: SKIP — could not pull {s}@{s} ({t}); a first run needs network\n",
            .{ tlsanvil_image, tlsanvil_digest[0..19], err },
        );
        return 2;
    };

    watchdog_stage.store(3, .release);
    const server = try startServer(io, arena, options.server_path);
    defer stopServer(io, server);
    try awaitListening(io, server);

    watchdog_stage.store(4, .release);
    corpus_running.store(true, .release);
    var liveness: Io.Group = .init;
    try liveness.concurrent(io, livenessTask, .{io});
    const status = runCorpus(io, arena) catch |err| {
        corpus_running.store(false, .release);
        liveness.cancel(io);
        return err;
    };
    corpus_running.store(false, .release);
    liveness.cancel(io);

    watchdog_stage.store(5, .release);
    // Said before the numbers, because it decides what they mean: a
    // corpus that ran against a dead server produces a low count that
    // looks exactly like a corpus that refused us.
    if (harness_died.load(.acquire)) {
        std.debug.print(
            "tlsanvil: FAIL — the harness died during the run. Whatever the counts\n" ++
                "      below say, they are that crash and not the corpus. See {s}\n",
            .{log_path},
        );
        return 1;
    }

    const outcome = try readOutcome(io, arena, options.config_path);
    return verdict(outcome, status);
}

/// The counts, then the three ways they can be a failure. Split out of
/// `main` to keep it under TIGER_STYLE's 70-line limit, which the other
/// two gates' `main` functions also sit beneath.
fn verdict(outcome: Outcome, status: u8) u8 {
    // Before the counts, and for the same reason the dead-harness check
    // is: a number that does not add up must not be read as a number.
    // Printing the totals first and the discrepancy second invites the
    // eye to take "115 passed" at face value and skim the line that says
    // three hundred tests went missing.
    if (outcome.total != 0 and outcome.accounted != outcome.total) {
        std.debug.print(
            "tlsanvil: FAIL — {d} tests accounted for of {d} the report holds. A result " ++
                "bucket this gate does not read is a test that cannot fail, so no count " ++
                "below is trustworthy; check report.json's counters against `parseOutcome`.\n",
            .{ outcome.accounted, outcome.total },
        );
        return 1;
    }
    std.debug.print(
        "tlsanvil: {d} passed, {d} failed, {d} suppressed, {d} disabled of {d} tests ({d} cases), floor {d}\n",
        .{ outcome.passed, outcome.failed, outcome.suppressed, outcome.disabled, outcome.total, outcome.cases, passing_floor },
    );
    for (outcome.failures.items) |name| std.debug.print("tlsanvil: FAILED {s}\n", .{name});
    if (status != 0 and outcome.total == 0) {
        std.debug.print("tlsanvil: FAIL — the runner exited {d} without a report; see {s}\n", .{ status, log_path });
        return 1;
    }
    if (outcome.failed >= 1) {
        std.debug.print(
            "tlsanvil: FAIL — {d} test(s) the corpus ran and we did not satisfy; see {s}\n",
            .{ outcome.failed, log_path },
        );
        return 1;
    }
    if (outcome.passed < passing_floor) {
        std.debug.print(
            "tlsanvil: FAIL — {d} passing, below the floor of {d}. Either a test\n" ++
                "      regressed or one stopped running; neither is allowed to be quiet.\n",
            .{ outcome.passed, passing_floor },
        );
        return 1;
    }
    std.debug.print("tlsanvil: PASS\n", .{});
    return 0;
}

fn watchdogTask(io: Io) void {
    io.sleep(Io.Duration.fromNanoseconds(watchdog_budget_ns), .awake) catch return;
    const name = switch (watchdog_stage.load(.acquire)) {
        0, 1 => "startup",
        2 => "pulling the pinned image",
        3 => "starting the server harness",
        4 => "running the corpus",
        else => "teardown",
    };
    std.debug.print("tlsanvil: FAIL — wedged in: {s}\n", .{name});
    const pid = watchdog_server_pid.load(.acquire);
    if (pid != 0) std.posix.kill(pid, std.posix.SIG.KILL) catch {};
    killContainer(io);
    std.process.exit(1);
}

/// Watch the harness while the corpus runs, and stop the run the moment
/// it stops answering. Killing the container rather than waiting is the
/// whole point: the remaining cases would all fail for a reason that is
/// not theirs, and the run would take another hour to say so.
fn livenessTask(io: Io) void {
    while (corpus_running.load(.acquire)) {
        io.sleep(Io.Duration.fromNanoseconds(liveness_interval_ns), .awake) catch return;
        if (!corpus_running.load(.acquire)) return;
        if (serverIsAccepting(io)) continue;
        harness_died.store(true, .release);
        std.debug.print("tlsanvil: the harness stopped answering; ending the run\n", .{});
        killContainer(io);
        return;
    }
}

fn serverIsAccepting(io: Io) bool {
    const address: Io.net.IpAddress = .{ .ip4 = .loopback(server_port) };
    const stream = address.connect(io, .{ .mode = .stream }) catch return false;
    stream.close(io);
    return true;
}

fn killContainer(io: Io) void {
    _ = run(io, &.{ "docker", "kill", container_name }, .ignore, .ignore) catch {};
}

const container_name = "zssl-tlsanvil";

const Options = struct { server_path: []const u8, config_path: []const u8 };

fn parseArguments(init: std.process.Init, arena: std.mem.Allocator) !Options {
    var iterator = try std.process.Args.Iterator.initAllocator(init.minimal.args, arena);
    defer iterator.deinit();
    _ = iterator.skip();
    var server_path: ?[]const u8 = null;
    var config_path: ?[]const u8 = null;
    while (iterator.next()) |argument| {
        if (std.mem.eql(u8, argument, "--server")) {
            server_path = try arena.dupe(u8, iterator.next() orelse return error.MissingServerPath);
        } else if (std.mem.eql(u8, argument, "--config")) {
            config_path = try arena.dupe(u8, iterator.next() orelse return error.MissingConfigPath);
        }
    }
    return .{
        .server_path = server_path orelse return error.MissingServerPath,
        .config_path = config_path orelse return error.MissingConfigPath,
    };
}

/// A Docker binary on PATH is not enough — the daemon has to answer.
/// `docker version` fails against a stopped daemon where `--help` would
/// not, which is the difference between a real SKIP and a confusing one.
fn dockerAvailable(io: Io) bool {
    const status = run(io, &.{ "docker", "version", "--format", "{{.Server.Version}}" }, .ignore, .ignore) catch
        return false;
    return status == 0;
}

fn ensureImage(io: Io, arena: std.mem.Allocator) !void {
    const reference = try std.fmt.allocPrint(arena, "{s}@{s}", .{ tlsanvil_image, tlsanvil_digest });
    if (run(io, &.{ "docker", "image", "inspect", reference }, .ignore, .ignore) catch 1 == 0) return;
    std.debug.print("tlsanvil: pulling {s}@{s}\n", .{ tlsanvil_image, tlsanvil_digest[0..19] });
    if (try run(io, &.{ "docker", "pull", "--platform", "linux/amd64", reference }, .ignore, .inherit) != 0) {
        return error.PullFailed;
    }
}

const Server = struct {
    child: std.process.Child,
    reader: Io.File.Reader,
    buffer: [4096]u8,
};

fn startServer(io: Io, arena: std.mem.Allocator, server_path: []const u8) !*Server {
    const absolute = try absolutePath(io, arena, server_path);
    const port = try std.fmt.allocPrint(arena, "{d}", .{server_port});
    const server = try arena.create(Server);
    server.child = try std.process.spawn(io, .{
        // A deadline sized for this corpus rather than for tlsfuzzer's.
        // The harness default of five seconds is what keeps a sequential
        // listener from starving on tlsfuzzer's abort cases; TLS-Anvil
        // under emulation can spend longer than that on one legitimate
        // conversation, and the socket closing under it reads as a
        // protocol failure rather than as a deadline.
        .argv = &.{ absolute, "--port", port, "--connection-budget-s", "30" },
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .pipe,
    });
    watchdog_server_pid.store(server.child.id orelse 0, .release);
    server.reader = server.child.stderr.?.reader(io, &server.buffer);
    return server;
}

/// `fill(1)` then `buffered()`, never `readSliceShort`: the latter waits
/// until its whole buffer is full and the harness prints one line.
fn awaitListening(io: Io, server: *Server) !void {
    _ = io;
    var reads: u8 = 0;
    while (reads < 32) : (reads += 1) {
        server.reader.interface.fill(1) catch return error.ServerNeverListened;
        const available = server.reader.interface.buffered();
        assert(available.len >= 1);
        if (std.mem.indexOf(u8, available, "listening") != null) return;
        server.reader.interface.toss(available.len);
    }
    return error.ServerNeverListened;
}

fn stopServer(io: Io, server: *Server) void {
    server.child.kill(io);
    watchdog_server_pid.store(0, .release);
}

fn runCorpus(io: Io, arena: std.mem.Allocator) !u8 {
    const log = try Io.Dir.cwd().createFile(io, log_path, .{});
    defer log.close(io);
    const mount = try std.fmt.allocPrint(arena, "{s}:/output", .{try absolutePath(io, arena, work_dir)});
    const reference = try std.fmt.allocPrint(arena, "{s}@{s}", .{ tlsanvil_image, tlsanvil_digest });
    const connect = try std.fmt.allocPrint(arena, "{s}:{d}", .{ networking.host, server_port });

    std.debug.print("tlsanvil: running the corpus (this takes a while)\n", .{});
    var child = try std.process.spawn(io, .{
        .argv = &.{
            "docker",              "run",
            "--rm",                "--name",
            container_name,
            // The image is amd64; asking for it explicitly keeps an
            // arm64 host from failing rather than emulating.
                   "--platform",
            "linux/amd64",
            // How the container reaches a harness bound to the host's
            // loopback. See `networking`.
                    networking.flag,
            "-v",                  mount,
            reference,
            // tcpdump wants capabilities the container is not given, and
            // a packet capture is not what this gate reads.
                        "-disableTcpDump",
            // The harness is a sequential listener, so one handshake at
            // a time is not a tuning choice.
            "-parallelHandshakes", "1",
            "-connectionTimeout",  "1000",
            "-strength",           "1",
            "-identifier",         "zssl",
            "-outputFolder",       "/output/results",
            "-prettyPrintJSON",    "server",
            "-connect",            connect,
        },
        .stdin = .ignore,
        .stdout = .{ .file = log },
        .stderr = .{ .file = log },
    });
    const term = child.wait(io) catch return 1;
    return switch (term) {
        .exited => |code| code,
        else => 1,
    };
}

const Outcome = struct {
    passed: u32,
    failed: u32,
    disabled: u32,
    total: u32,
    /// Every test the report put in a bucket this gate counts. Held
    /// against `total`, because a bucket we do not know about is a test
    /// that vanishes from the arithmetic without failing anything.
    accounted: u32,
    cases: u32,
    /// Failures with no entry in the ledger. These are the ones that
    /// stop the build.
    failures: std.ArrayList([]const u8),
    /// Failures the ledger names, with a written reason each.
    suppressed: u32,
};

/// Two files, because they answer different questions. `report.json`
/// carries the counts; `result_map.json` carries which test landed in
/// which bucket, keyed by an id that is *not* stable — the same failure
/// carried different ids across runs once the tree changed underneath
/// it. Every id is therefore resolved to `<class>.<method>` before it is
/// compared against anything.
fn readOutcome(io: Io, arena: std.mem.Allocator, config_path: []const u8) !Outcome {
    var outcome: Outcome = .{
        .passed = 0,
        .failed = 0,
        .disabled = 0,
        .total = 0,
        .accounted = 0,
        .cases = 0,
        .failures = .empty,
        .suppressed = 0,
    };
    const report = readFile(io, arena, results_dir ++ "/report.json") catch return outcome;
    const parsed = std.json.parseFromSlice(std.json.Value, arena, report, .{}) catch return outcome;
    if (parsed.value != .object) return outcome;
    const object = parsed.value.object;
    outcome.passed = countOf(object, "StrictlySucceededTests") + countOf(object, "ConceptuallySucceededTests");
    outcome.failed = countOf(object, "FullyFailedTests") + countOf(object, "PartiallyFailedTests") +
        countOf(object, "TestSuiteErrorTests");
    outcome.disabled = countOf(object, "DisabledTests");
    outcome.total = countOf(object, "TotalTests");
    outcome.cases = countOf(object, "TestCaseCount");
    // Summed from the same counters, before the ledger carves
    // suppressions out of `failed` below. What this is for is the bucket
    // that does not exist yet: TLS-Anvil is pinned by image digest, and
    // a bump that adds a result category — skipped, inconclusive,
    // whatever they call it next — would take tests out of every count
    // here at once. The floor would not notice, because a test that
    // stopped being counted never fails.
    outcome.accounted = outcome.passed + outcome.failed + outcome.disabled;

    const map = readFile(io, arena, results_dir ++ "/result_map.json") catch return outcome;
    const map_parsed = std.json.parseFromSlice(std.json.Value, arena, map, .{}) catch return outcome;
    if (map_parsed.value != .object) return outcome;
    const ledger = try readLedger(io, arena, config_path);
    for ([_][]const u8{ "FULLY_FAILED", "PARTIALLY_FAILED", "TEST_SUITE_ERROR" }) |bucket| {
        const list = map_parsed.value.object.get(bucket) orelse continue;
        if (list != .array) continue;
        for (list.array.items) |entry| {
            if (entry != .string) continue;
            // The opaque id is not the name. It is also not stable —
            // the same failure carried a different id across two runs of
            // a changed tree — so the ledger keys on class and method,
            // which are Java identifiers and do not move.
            const name = testName(io, arena, entry.string) catch entry.string;
            if (ledger.get(name) != null) {
                outcome.suppressed += 1;
                continue;
            }
            try outcome.failures.append(arena, name);
        }
    }
    outcome.failed = @intCast(outcome.failures.items.len);
    return outcome;
}

/// `<class>.<method>` for a test id, read from the run's own record.
fn testName(io: Io, arena: std.mem.Allocator, id: []const u8) ![]const u8 {
    const path = try std.fmt.allocPrint(arena, "{s}/results/{s}/_testRun.json", .{ results_dir, id });
    const contents = try readFile(io, arena, path);
    const parsed = try std.json.parseFromSlice(std.json.Value, arena, contents, .{});
    if (parsed.value != .object) return error.MalformedResult;
    const class = parsed.value.object.get("TestClass") orelse return error.MalformedResult;
    const method = parsed.value.object.get("TestMethod") orelse return error.MalformedResult;
    if (class != .string or method != .string) return error.MalformedResult;
    return std.fmt.allocPrint(arena, "{s}.{s}", .{ class.string, method.string });
}

/// `tlsanvil/tests.json`: a `Disabled` map from `<class>.<method>` to the
/// one-line reason that failure is accepted. Same rule as the other two
/// ledgers — an entry without a reason is not an entry.
fn readLedger(
    io: Io,
    arena: std.mem.Allocator,
    path: []const u8,
) !std.StringHashMapUnmanaged(void) {
    var names: std.StringHashMapUnmanaged(void) = .empty;
    const contents = readFile(io, arena, path) catch return names;
    const parsed = try std.json.parseFromSlice(std.json.Value, arena, contents, .{});
    if (parsed.value != .object) return error.MalformedConfig;
    const map = parsed.value.object.get("Disabled") orelse return names;
    if (map != .object) return error.MalformedConfig;
    var it = map.object.iterator();
    while (it.next()) |kv| {
        if (kv.value_ptr.* != .string) return error.MalformedConfig;
        if (kv.value_ptr.string.len == 0) return error.MalformedConfig;
        try names.put(arena, kv.key_ptr.*, {});
    }
    return names;
}

fn countOf(object: std.json.ObjectMap, key: []const u8) u32 {
    const value = object.get(key) orelse return 0;
    return switch (value) {
        .integer => |number| if (number >= 0 and number <= std.math.maxInt(u32)) @intCast(number) else 0,
        else => 0,
    };
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
    const buffer = try arena.alloc(u8, 4 * 1024 * 1024);
    var reader = file.reader(io, buffer);
    const sink = try arena.alloc(u8, 4 * 1024 * 1024);
    const read_bytes = try reader.interface.readSliceShort(sink);
    if (read_bytes == 0) return error.EmptyReport;
    return sink[0..read_bytes];
}

fn run(
    io: Io,
    argv: []const []const u8,
    stdout: std.process.SpawnOptions.StdIo,
    stderr: std.process.SpawnOptions.StdIo,
) !u8 {
    assert(argv.len >= 1);
    var child = std.process.spawn(io, .{
        .argv = argv,
        .stdin = .ignore,
        .stdout = stdout,
        .stderr = stderr,
    }) catch return error.SpawnFailed;
    const term = child.wait(io) catch return 1;
    return switch (term) {
        .exited => |code| code,
        else => 1,
    };
}
