//! The tlsfuzzer gate: start our server, drive a curated script list at
//! it, and hold the result against a floor (docs/TLSFUZZER.md).
//!
//! Same shape as `bogo/run.zig`, and for the same reasons: the checkout
//! is pinned by commit rather than vendored, the dependencies land in a
//! virtualenv under `zig-out/`, every script that is *not* run is named
//! with a reason in `tlsfuzzer/scripts.json`, and a floor on the passing
//! count is what stops a suppression from being quiet.
//!
//! Where it differs from BoGo is the shape of the runner. tlsfuzzer has
//! no dispatcher: each script is a separate Python process that connects
//! to a server we start first and leave running for the whole gate. So
//! this program owns a child server as well as a child interpreter, and
//! its most important job after reporting the numbers is not leaving
//! either behind.
//!
//! Exit status is the verdict: 0 passed, 1 failed, 2 could not run (no
//! Python, or no network on the first run).

const std = @import("std");
const Io = std.Io;
const assert = std.debug.assert;

/// The pin. Moves deliberately, together with a re-run that re-derives
/// `passing_floor` — see docs/TLSFUZZER.md.
const tlsfuzzer_url = "https://github.com/tlsfuzzer/tlsfuzzer";
const tlsfuzzer_commit = "5eebc4464e5197a7f7392fb9acda99cfc32441f7";

/// tlsfuzzer's own pin for its TLS stack, from its requirements.txt.
const tlslite_requirement = "tlslite-ng==0.9.0b2";
const ecdsa_requirement = "ecdsa>=0.15";

/// What the pin above scores on this tree: 22 scripts, 1428
/// conversations between them. Raise it whenever a fix moves the number
/// up; a drop is either a regression or a suppression, and both deserve
/// to stop the build.
const passing_floor: u32 = 22;

const work_dir = "zig-out/tlsfuzzer";
const checkout_dir = work_dir ++ "/tlsfuzzer";
const venv_dir = work_dir ++ "/venv";
const log_path = work_dir ++ "/tlsfuzzer.log";

/// The leaves the gate serves, one harness instance each.
///
/// Two, because a dozen-odd scripts advertise *only* RSA-PSS signature
/// algorithms, and a server holding an ECDSA leaf can answer those with
/// nothing but handshake_failure. That fails the script's own `sanity`
/// conversation and every case queued behind it, which reads as "the
/// corpus rejects us" when it is a fixture mismatch and nothing more.
/// Serving one leaf was costing this gate scripts that had never been
/// given a chance to fail on their merits.
///
/// The ports are fixed rather than ephemeral because the scripts are
/// told where to connect on their command line.
const Leaf = struct {
    name: []const u8,
    port: u16,
    cert_path: []const u8,
    key_path: []const u8,
    /// How this instance answers application data. The corpus is not of
    /// one mind about that and cannot be made to be: `test-tls13-lengths`
    /// checks the reply's *length* against what it sent across 1002
    /// conversations, which only an echo satisfies, while several scripts
    /// send one request across several records, expect the single reply
    /// an HTTP server gives, and expect *silence* until the request is
    /// complete. Serving both from one instance is not a harness that
    /// needs cleverness; it is two harnesses.
    http: bool = false,
};

const leaves = [_]Leaf{
    .{
        .name = "ecdsa",
        .port = 4433,
        .cert_path = "src/testdata/cert.pem",
        .key_path = "src/testdata/key.pem",
    },
    .{
        .name = "rsa",
        .port = 4434,
        .cert_path = "src/testdata/rsa2048-cert.pem",
        .key_path = "src/testdata/rsa2048-key.pem",
    },
    .{
        .name = "rsa-http",
        // 4436, not 4435: `tlsanvil/run.zig` binds 4435 for its own
        // instance of this same harness, and both gates document
        // hand-driving it there. Separate CI jobs never collide, but a
        // developer running `zig build tlsfuzzer` while TLS-Anvil's
        // hundred-minute budget is still going would have one of them
        // fail to bind — and fail for a reason belonging to neither
        // corpus.
        .port = 4436,
        .cert_path = "src/testdata/rsa2048-cert.pem",
        .key_path = "src/testdata/rsa2048-key.pem",
        .http = true,
    },
};

/// What a `Run` entry that names no leaf is served.
const default_leaf = "ecdsa";

/// The out-of-band PSK both harnesses carry, and the identity it answers
/// to. `test-tls13-psk_dhe_ke` is the only script that offers an
/// external identity, and it needs both sides to hold the same bytes —
/// so the value lives here and its `arguments` entry in `scripts.json`
/// repeats it, rather than each side inventing one.
///
/// Throwaway material by construction: it authenticates nothing but a
/// loopback conversation with a corpus, and it is committed for the same
/// reason `src/testdata`'s keys are.
const external_psk_hex = "ab" ** 32;
const external_psk_identity = "test";

/// Generous: a cold run clones the corpus and pip-installs two packages
/// before a single script runs.
const watchdog_budget_ns: u64 = 45 * 60 * std.time.ns_per_s;

var watchdog_stage: std.atomic.Value(u8) = .init(0);
var watchdog_child_pid: std.atomic.Value(i32) = .init(0);
var watchdog_server_pids: [leaves.len]std.atomic.Value(i32) = @splat(.init(0));

/// The ledger has to name every script the checkout carries: a pin bump
/// adds cases, and one nobody triaged is one the gate silently does not
/// run. Split out of `main` to keep it under TIGER_STYLE's 70-line
/// limit — which is also what `tlsanvil/run.zig`'s `verdict` says it did,
/// and that claim was false for this file until now.
///
/// Non-null is an exit code and `main` should return it.
fn refuseUnnamedScripts(io: Io, arena: std.mem.Allocator, scripts: Scripts) !?u8 {
    const unnamed = countUnnamedScripts(io, arena, scripts) catch |err| {
        std.debug.print("tlsfuzzer: could not read the checkout's scripts ({t})\n", .{err});
        return 2;
    };
    if (unnamed == 0) return null;
    std.debug.print(
        "tlsfuzzer: {d} `test-tls13-*` script(s) in the checkout that scripts.json does " ++
            "not name. A pin bump adds cases; each needs a Run entry or a Disabled reason.\n",
        .{unnamed},
    );
    return 1;
}

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();
    const options = try parseArguments(init, arena);

    var watchdog: Io.Group = .init;
    try watchdog.concurrent(io, watchdogTask, .{io});
    defer watchdog.cancel(io);

    const python = findPython(io) catch {
        std.debug.print(
            "tlsfuzzer: SKIP — no python3 on PATH; tlsfuzzer is a Python program\n",
            .{},
        );
        return 2;
    };
    Io.Dir.cwd().createDirPath(io, work_dir) catch {};

    watchdog_stage.store(1, .release);
    ensureCheckout(io, arena) catch |err| {
        std.debug.print(
            "tlsfuzzer: SKIP — could not fetch tlsfuzzer {s} ({t}); a first run needs network\n",
            .{ tlsfuzzer_commit[0..12], err },
        );
        return 2;
    };

    watchdog_stage.store(2, .release);
    const venv_python = ensureVirtualenv(io, arena, python) catch |err| {
        std.debug.print(
            "tlsfuzzer: SKIP — could not build the virtualenv ({t}); a first run needs network\n",
            .{err},
        );
        return 2;
    };

    watchdog_stage.store(3, .release);
    const scripts = try loadScripts(io, arena, options.config_path);
    if (try refuseUnnamedScripts(io, arena, scripts)) |code| return code;
    std.debug.print(
        "tlsfuzzer: {d} scripts to run, {d} disabled ({d} of those untriaged)\n",
        .{ scripts.run.len, scripts.disabled, scripts.untriaged },
    );

    watchdog_stage.store(4, .release);
    const servers = try startServers(io, arena, options.server_path);
    defer stopServers(io, servers);

    watchdog_stage.store(5, .release);
    const outcome = try runScripts(io, arena, venv_python, scripts.run);

    watchdog_stage.store(6, .release);
    std.debug.print(
        "tlsfuzzer: {d} scripts passed, {d} failed, {d} disabled, floor {d}\n",
        .{ outcome.passed, outcome.failed, scripts.disabled, passing_floor },
    );
    for (outcome.failures.items) |name| std.debug.print("tlsfuzzer: FAILED {s}\n", .{name});
    if (!reportDeadHarness(io)) return 1;
    if (outcome.failed >= 1) {
        std.debug.print(
            "tlsfuzzer: FAIL — {d} script(s) we ran and did not satisfy; see {s}\n",
            .{ outcome.failed, log_path },
        );
        return 1;
    }
    if (outcome.passed < passing_floor) {
        std.debug.print(
            "tlsfuzzer: FAIL — {d} passing, below the floor of {d}. Either a script\n" ++
                "      regressed or one was disabled; neither is allowed to be quiet.\n",
            .{ outcome.passed, passing_floor },
        );
        return 1;
    }
    std.debug.print("tlsfuzzer: PASS\n", .{});
    return 0;
}

fn watchdogTask(io: Io) void {
    io.sleep(Io.Duration.fromNanoseconds(watchdog_budget_ns), .awake) catch return;
    const name = switch (watchdog_stage.load(.acquire)) {
        0 => "startup",
        1 => "fetching the pinned tlsfuzzer",
        2 => "building the virtualenv",
        3 => "reading the script list",
        4 => "starting the server harness",
        5 => "running the scripts",
        else => "teardown",
    };
    std.debug.print("tlsfuzzer: FAIL — wedged in: {s}\n", .{name});
    // Every child, because leaving a listener on a fixed port behind
    // makes the *next* run fail for a reason that has nothing to do with
    // the code under test.
    const child = watchdog_child_pid.load(.acquire);
    if (child != 0) std.posix.kill(child, std.posix.SIG.KILL) catch {};
    for (&watchdog_server_pids) |*slot| {
        const pid = slot.load(.acquire);
        if (pid != 0) std.posix.kill(pid, std.posix.SIG.KILL) catch {};
    }
    std.process.exit(1);
}

const Options = struct {
    server_path: []const u8,
    config_path: []const u8,
};

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

fn findPython(io: Io) ![]const u8 {
    const candidates = [_][]const u8{ "python3", "/usr/bin/python3", "/opt/homebrew/bin/python3" };
    for (candidates) |candidate| {
        const status = run(io, &.{ candidate, "--version" }, .ignore, .ignore) catch continue;
        if (status == 0) return candidate;
    }
    return error.NoPython;
}

fn ensureCheckout(io: Io, arena: std.mem.Allocator) !void {
    if (try checkoutIsCurrent(io, arena)) return;
    std.debug.print("tlsfuzzer: fetching tlsfuzzer {s}\n", .{tlsfuzzer_commit[0..12]});
    Io.Dir.cwd().createDirPath(io, checkout_dir) catch {};
    const cwd: std.process.Child.Cwd = .{ .path = checkout_dir };
    _ = try runIn(io, &.{ "git", "init", "-q" }, cwd);
    _ = runIn(io, &.{ "git", "remote", "add", "origin", tlsfuzzer_url }, cwd) catch {};
    _ = runIn(io, &.{ "git", "remote", "set-url", "origin", tlsfuzzer_url }, cwd) catch {};
    const fetched = try runIn(io, &.{
        "git", "fetch", "--depth", "1", "-q", "origin", tlsfuzzer_commit,
    }, cwd);
    if (fetched != 0) return error.FetchFailed;
    const checked = try runIn(io, &.{ "git", "checkout", "-q", "--detach", "FETCH_HEAD" }, cwd);
    if (checked != 0) return error.CheckoutFailed;
    if (!try checkoutIsCurrent(io, arena)) return error.PinMismatch;
}

fn checkoutIsCurrent(io: Io, arena: std.mem.Allocator) !bool {
    const head = captureIn(io, arena, &.{ "git", "rev-parse", "HEAD" }, .{ .path = checkout_dir }) catch
        return false;
    return std.mem.startsWith(u8, std.mem.trim(u8, head, " \n\r\t"), tlsfuzzer_commit);
}

/// A virtualenv rather than the system interpreter: tlsfuzzer pins its
/// TLS stack and we should install that pin, not whatever the machine
/// happens to carry.
fn ensureVirtualenv(io: Io, arena: std.mem.Allocator, python: []const u8) ![]const u8 {
    const venv_python = try absolutePath(io, arena, venv_dir ++ "/bin/python");
    if (run(io, &.{ venv_python, "-c", "import tlslite, ecdsa" }, .ignore, .ignore) catch 1 == 0) {
        return venv_python;
    }
    std.debug.print("tlsfuzzer: building the virtualenv\n", .{});
    const venv_absolute = try absolutePath(io, arena, venv_dir);
    if (try run(io, &.{ python, "-m", "venv", venv_absolute }, .ignore, .inherit) != 0) {
        return error.VenvFailed;
    }
    const pip = try absolutePath(io, arena, venv_dir ++ "/bin/pip");
    const installed = try run(io, &.{
        pip,                           "install",         "-q",
        "--disable-pip-version-check", ecdsa_requirement, tlslite_requirement,
    }, .ignore, .inherit);
    if (installed != 0) return error.PipFailed;
    return venv_python;
}

const Script = struct {
    name: []const u8,
    arguments: []const []const u8,
    /// Index into `leaves`: which harness this script is pointed at.
    leaf: usize,
};

const Scripts = struct {
    run: []const Script,
    /// Every name the ledger mentions, run or disabled — what
    /// `countUnnamedScripts` holds the checkout against.
    names: std.StringHashMapUnmanaged(void),
    disabled: u32,
    /// Disabled entries whose reason says nobody has worked out *why*
    /// yet. Counted separately and printed on every run, because a
    /// suppression ledger where most entries say "unknown" is a debt,
    /// and a debt that is not counted is a debt that is not paid.
    untriaged: u32,
};

/// Every `test-tls13-*.py` the checkout holds must be named in
/// `scripts.json`, in one list or the other.
///
/// The ledger used to be trusted to know its own corpus, and it did not:
/// the gate ran what the file named and counted what the file disabled,
/// so a script present on disk and absent from both lists was invisible.
/// A pin bump that adds cases is exactly when that matters — new tests
/// arrive and nothing says so, which is the quiet suppression the
/// passing floor exists to prevent, arriving by a door the floor does
/// not watch. BoGo's runner enumerates its own corpus and ours did not.
///
/// The prefix is the corpus definition and it is imperfect: five scripts
/// drive TLS 1.3 without carrying it in their name, and they are named
/// in the ledger individually because a convention is not a decision.
/// What this catches is the class that would otherwise be silent.
fn countUnnamedScripts(io: Io, arena: std.mem.Allocator, scripts: Scripts) !u32 {
    const checkout = try absolutePath(io, arena, checkout_dir);
    const path = try std.fmt.allocPrint(arena, "{s}/scripts", .{checkout});
    var dir = try Io.Dir.cwd().openDir(io, path, .{ .iterate = true });
    defer dir.close(io);
    var unnamed: u32 = 0;
    var it = dir.iterate();
    while (try it.next(io)) |entry| {
        // No `entry.kind` filter, and that is not laziness: every script
        // in this checkout is a symlink to a shared `_stub.py`, so all
        // but one entry answers `.sym_link` and a filter on `.file`
        // silently matches nothing. The name is the whole test, which is
        // what a directory of dispatch stubs leaves us.
        if (!std.mem.startsWith(u8, entry.name, "test-tls13-")) continue;
        if (!std.mem.endsWith(u8, entry.name, ".py")) continue;
        if (scripts.names.contains(entry.name)) continue;
        std.debug.print("tlsfuzzer: unnamed script: {s}\n", .{entry.name});
        unnamed += 1;
    }
    return unnamed;
}

/// `scripts.json`: a `Run` list of `{name, arguments?, leaf?}` and a
/// `Disabled` map from script name to the one-line reason it is not run.
/// The shape follows tlsfuzzer's own `tests/tlslite-ng.json` closely
/// enough that a reader of one can read the other; `leaf` is ours, and
/// names an entry in `leaves` above.
fn loadScripts(io: Io, arena: std.mem.Allocator, path: []const u8) !Scripts {
    var names: std.StringHashMapUnmanaged(void) = .empty;
    const contents = try readFile(io, arena, path);
    const parsed = try std.json.parseFromSlice(std.json.Value, arena, contents, .{});
    if (parsed.value != .object) return error.MalformedConfig;
    const run_list = parsed.value.object.get("Run") orelse return error.MalformedConfig;
    if (run_list != .array) return error.MalformedConfig;
    var scripts: std.ArrayList(Script) = .empty;
    for (run_list.array.items) |entry| {
        if (entry != .object) return error.MalformedConfig;
        const name = entry.object.get("name") orelse return error.MalformedConfig;
        if (name != .string) return error.MalformedConfig;
        var arguments: std.ArrayList([]const u8) = .empty;
        if (entry.object.get("arguments")) |list| {
            if (list != .array) return error.MalformedConfig;
            for (list.array.items) |argument| {
                if (argument != .string) return error.MalformedConfig;
                try arguments.append(arena, argument.string);
            }
        }
        const leaf_name = if (entry.object.get("leaf")) |value| blk: {
            if (value != .string) return error.MalformedConfig;
            break :blk value.string;
        } else default_leaf;
        try names.put(arena, name.string, {});
        try scripts.append(arena, .{
            .name = name.string,
            .arguments = arguments.items,
            .leaf = try leafIndex(leaf_name),
        });
    }
    var disabled: u32 = 0;
    var untriaged: u32 = 0;
    if (parsed.value.object.get("Disabled")) |map| {
        if (map != .object) return error.MalformedConfig;
        // Every entry carries its reason; the count is what the gate
        // reports, and the reasons are what a reader audits.
        var it = map.object.iterator();
        while (it.next()) |kv| {
            if (kv.value_ptr.* != .string) return error.MalformedConfig;
            if (kv.value_ptr.string.len == 0) return error.MalformedConfig;
            try names.put(arena, kv.key_ptr.*, {});
            disabled += 1;
            if (std.mem.indexOf(u8, kv.value_ptr.string, "not yet triaged") != null) {
                untriaged += 1;
            }
        }
    }
    assert(scripts.items.len >= 1);
    return .{
        .run = scripts.items,
        .names = names,
        .disabled = disabled,
        .untriaged = untriaged,
    };
}

/// A `leaf` naming no harness is a typo in the ledger, not a default to
/// paper over: it would silently point the script at the wrong server.
fn leafIndex(name: []const u8) !usize {
    for (&leaves, 0..) |leaf, index| {
        if (std.mem.eql(u8, leaf.name, name)) return index;
    }
    return error.UnknownLeaf;
}

const Server = struct {
    child: std.process.Child,
    reader: Io.File.Reader,
    buffer: [4096]u8,
};

fn startServer(
    io: Io,
    arena: std.mem.Allocator,
    server_path: []const u8,
    leaf: Leaf,
    index: usize,
) !*Server {
    assert(index < leaves.len);
    const absolute = try absolutePath(io, arena, server_path);
    const port = try std.fmt.allocPrint(arena, "{d}", .{leaf.port});
    const server = try arena.create(Server);
    server.child = try std.process.spawn(io, .{
        .argv = &.{
            absolute,                          "--port",              port,
            "--cert",                          leaf.cert_path,        "--key",
            leaf.key_path,                     "--psk",               external_psk_hex,
            "--psk-iden",                      external_psk_identity, "--reply",
            if (leaf.http) "http" else "echo",
        },
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .pipe,
    });
    watchdog_server_pids[index].store(server.child.id orelse 0, .release);
    server.reader = server.child.stderr.?.reader(io, &server.buffer);
    return server;
}

/// Wait for the harness's own "listening" line rather than sleeping.
///
/// `fill(1)` then `buffered()`, never `readSliceShort`: the latter waits
/// until its whole buffer is full, and the harness prints one line and
/// then goes quiet — so asking for 256 bytes waits forever for 210 that
/// never come. `interop/main.zig` documents this exact trap on its own
/// socket reads; this is the same mistake on a pipe.
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

/// One harness per leaf, each waited for rather than slept on.
///
/// The scripts connect the moment they start, so every listener has to
/// be up before the first one does — and "up" is a line the harness
/// prints, not a guess at how long it takes.
fn startServers(io: Io, arena: std.mem.Allocator, server_path: []const u8) ![leaves.len]*Server {
    assert(server_path.len >= 1);
    var servers: [leaves.len]*Server = undefined;
    for (&leaves, 0..) |leaf, index| {
        servers[index] = try startServer(io, arena, server_path, leaf, index);
    }
    for (servers) |server| try awaitListening(io, server);
    return servers;
}

fn stopServers(io: Io, servers: [leaves.len]*Server) void {
    for (servers, 0..) |server, index| stopServer(io, server, index);
}

/// True when every harness is still up. A harness that died mid-run
/// fails every script queued behind it, which reads as "the corpus
/// rejects us" and is the most expensive way to be told the server
/// crashed. Said right after the failures are printed, because it
/// decides what they mean: this gate has already lost one measurement
/// to that ambiguity.
fn reportDeadHarness(io: Io) bool {
    for (&leaves) |leaf| {
        if (serverIsAccepting(io, leaf)) continue;
        std.debug.print(
            "tlsfuzzer: FAIL — the {s}-leaf harness on port {d} died during the run.\n" ++
                "      The failures above are that crash, not the corpus: every script\n" ++
                "      queued behind it was answered by nothing. Re-run after fixing it.\n",
            .{ leaf.name, leaf.port },
        );
        return false;
    }
    return true;
}

/// Alive, asked the way the scripts ask.
///
/// Not `kill(pid, 0)` and not `child.term`: nothing here reaps the
/// harness, so a crashed one is a zombie that both of those still call
/// living. A connect is the property that actually matters — a listener
/// that is gone refuses it — and the harness is built to survive a peer
/// that opens a socket and says nothing, since half the corpus does
/// exactly that.
fn serverIsAccepting(io: Io, leaf: Leaf) bool {
    const address: Io.net.IpAddress = .{ .ip4 = .loopback(leaf.port) };
    const stream = address.connect(io, .{ .mode = .stream }) catch return false;
    stream.close(io);
    return true;
}

fn stopServer(io: Io, server: *Server, index: usize) void {
    assert(index < leaves.len);
    server.child.kill(io);
    watchdog_server_pids[index].store(0, .release);
}

const Outcome = struct {
    passed: u32,
    failed: u32,
    failures: std.ArrayList([]const u8),
};

fn runScripts(
    io: Io,
    arena: std.mem.Allocator,
    venv_python: []const u8,
    scripts: []const Script,
) !Outcome {
    const log = try Io.Dir.cwd().createFile(io, log_path, .{});
    defer log.close(io);
    const checkout = try absolutePath(io, arena, checkout_dir);
    var ports: [leaves.len][]const u8 = undefined;
    for (&leaves, 0..) |leaf, index| {
        ports[index] = try std.fmt.allocPrint(arena, "{d}", .{leaf.port});
    }

    var outcome: Outcome = .{ .passed = 0, .failed = 0, .failures = .empty };
    for (scripts) |script| {
        assert(script.leaf < leaves.len);
        var argv: std.ArrayList([]const u8) = .empty;
        try argv.appendSlice(arena, &.{
            venv_python,
            try std.fmt.allocPrint(arena, "{s}/scripts/{s}", .{ checkout, script.name }),
            "-h",
            "localhost",
            "-p",
            ports[script.leaf],
        });
        try argv.appendSlice(arena, script.arguments);
        // tlsfuzzer imports itself from the repository root.
        var environment: std.process.Environ.Map = .init(arena);
        try environment.put("PYTHONPATH", checkout);
        try environment.put("PATH", "/usr/bin:/bin:/usr/local/bin");

        var child = try std.process.spawn(io, .{
            .argv = argv.items,
            .cwd = .{ .path = checkout_dir },
            .environ_map = &environment,
            .stdin = .ignore,
            .stdout = .{ .file = log },
            .stderr = .{ .file = log },
        });
        watchdog_child_pid.store(child.id orelse 0, .release);
        const term: ?std.process.Child.Term = child.wait(io) catch null;
        watchdog_child_pid.store(0, .release);
        // A script we could not even reap counts as failed: silence is
        // not a pass anywhere else in this tree either.
        const ok = if (term) |t| switch (t) {
            .exited => |code| code == 0,
            else => false,
        } else false;
        if (ok) {
            outcome.passed += 1;
        } else {
            outcome.failed += 1;
            try outcome.failures.append(arena, try std.fmt.allocPrint(
                arena,
                "{s} ({s} leaf)",
                .{ script.name, leaves[script.leaf].name },
            ));
        }
    }
    assert(outcome.passed + outcome.failed == scripts.len);
    return outcome;
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
    const buffer = try arena.alloc(u8, 256 * 1024);
    var reader = file.reader(io, buffer);
    const sink = try arena.alloc(u8, 256 * 1024);
    const read_bytes = try reader.interface.readSliceShort(sink);
    if (read_bytes == 0) return error.EmptyConfig;
    return sink[0..read_bytes];
}

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

fn runIn(io: Io, argv: []const []const u8, cwd: std.process.Child.Cwd) !u8 {
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
