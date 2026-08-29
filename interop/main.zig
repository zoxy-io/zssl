//! The real-OpenSSL interop gate (slice 5).
//!
//! Four legs, all against the `openssl` binary — genuine libssl, a TLS
//! stack sharing no line of code with this one, written by different
//! people over thirty years:
//!
//!   1. `openssl s_client` handshakes with our `ServerHandshake`, with
//!      openssl's own X.509 verifying our Certificate against the
//!      fixture CA. Its `Verify return code: 0 (ok)` is the assertion.
//!   2. The same leg over a **P-384** leaf. DESIGN.md §1 puts ECDSA
//!      P-384 in the signing policy and `backend.SignatureScheme` has
//!      always carried `ecdsa_secp384r1_sha384`, but every fixture in
//!      this tree was P-256 or RSA — so nothing had ever asked that
//!      signer for a signature, let alone had one checked. Our own
//!      tests now sign and verify the curve, and that is one tree
//!      agreeing with itself; openssl is the first party here that did
//!      not also produce the signature. The leg asserts the negotiated
//!      scheme too, because one that quietly settled on P-256 would
//!      pass while proving nothing.
//!   3. Our `ClientHandshake` handshakes with `openssl s_server -rev`,
//!      our certificate policy checking *their* CertificateVerify, and
//!      our record layer opening the reversed echo they seal back.
//!   4. The same leg again against an **RSA** server certificate,
//!      generated here by openssl itself. ECDSA and RSA are different
//!      code paths in `ClientHandshake.verifyCertificate`, and the RSA
//!      one exists precisely for upstreams we do not control — so it is
//!      proven against a real RSA signer rather than a vector. Both
//!      client legs also run the `chain_verifier` seam and assert it
//!      saw the chain.
//!
//! In both directions application bytes cross afterwards, because a
//! handshake that completes but cannot carry traffic has proven the
//! easier half. The unit suite's `std.crypto.tls.Client` leg is the
//! same kind of evidence in-process; this one adds a second independent
//! implementation and a real kernel socket.
//!
//! What it is not: adversarial. Nothing here tests what we *refuse* —
//! that is BoGo's job, and `docs/BOGO.md` says where it stands.
//!
//! Exit status is the verdict: 0 passed, 1 failed, 2 could not run
//! (no openssl binary, or one too old for TLS 1.3).

const std = @import("std");
const Io = std.Io;
const assert = std.debug.assert;

const zssl = @import("zssl");
const ClientHandshake = zssl.ClientHandshake;
const Credentials = zssl.Credentials;
const ServerHandshake = zssl.ServerHandshake;
const backend = zssl.backend;
const client_hello = zssl.client_hello;
const record = zssl.record;

const cert_pem = @embedFile("cert_pem");
const key_pem = @embedFile("key_pem");
/// The P-384 pair. `backend.SignatureScheme` has carried
/// `ecdsa_secp384r1_sha384` since the beginning and DESIGN.md §1 puts
/// P-384 in the signing policy, but every fixture in this tree was P-256
/// or RSA — so until this leg existed, nothing had ever asked the P-384
/// signer for a signature a third party then checked.
const p384_cert_pem = @embedFile("p384_cert_pem");
const p384_key_pem = @embedFile("p384_key_pem");

/// Written beside the binary so the openssl child can read them; the
/// fixture is throwaway self-signed material, not a credential.
const cert_path = "zig-out/interop/cert.pem";
const key_path = "zig-out/interop/key.pem";
const p384_cert_path = "zig-out/interop/p384-cert.pem";
const p384_key_path = "zig-out/interop/p384-key.pem";
const s_client_log_path = "zig-out/interop/s_client.log";
const s_client_p384_log_path = "zig-out/interop/s_client_p384.log";
const s_client_retry_log_path = "zig-out/interop/s_client_retry.log";
const s_server_log_path = "zig-out/interop/s_server.log";
/// Generated at run time rather than embedded: an RSA fixture would be a
/// second key pair to keep in `src/testdata/`, which is shared with
/// zoxy's copy, and this leg only needs openssl to sign something with
/// an RSA key — which openssl can do on the spot.
const rsa_cert_path = "zig-out/interop/rsa-cert.pem";
const rsa_key_path = "zig-out/interop/rsa-key.pem";
const s_server_rsa_log_path = "zig-out/interop/s_server_rsa.log";
const work_dir = "zig-out/interop";

/// The whole gate, both legs, generously bounded. A hang here is a bug
/// report, not a CI that never returns.
const watchdog_budget_ns: u64 = 90 * std.time.ns_per_s;

/// Loopback ports the legs bind. Fixed rather than ephemeral because the
/// std listener does not report the bound port back, and the child needs
/// to be told where to connect; a busy port retries onto the next.
const port_base: u16 = 34580;
const port_attempts: u16 = 16;

var watchdog_stage: std.atomic.Value(u8) = .init(0);

/// The openssl child currently under test, so the watchdog can kill it
/// before exiting. `std.process.exit` does not unwind, so the `defer`
/// that normally reaps it never runs on that path — without this, a
/// wedged local run leaves an orphan holding the loopback port.
var watchdog_child_pid: std.atomic.Value(i32) = .init(0);

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();

    var watchdog: Io.Group = .init;
    try watchdog.concurrent(io, watchdogTask, .{io});
    defer watchdog.cancel(io);

    const openssl = findOpenssl(io, arena) catch {
        std.debug.print(
            "interop: SKIP — no openssl binary with TLS 1.3 found on PATH\n",
            .{},
        );
        return 2;
    };
    std.debug.print("interop: using {s}\n", .{openssl});
    try writeFixtures(io);

    if (!runServerLegs(io, arena, openssl)) return 1;

    watchdog_stage.store(4, .release);
    runClientLeg(io, arena, openssl, .{
        .cert_path = cert_path,
        .key_path = key_path,
        .log_path = s_server_log_path,
        .port = port_base + port_attempts,
        .expect_algo = .X9_62_id_ecPublicKey,
    }) catch |err| {
        std.debug.print("interop: FAIL — our client against s_server ({t})\n", .{err});
        return 1;
    };
    std.debug.print("interop: ok — ClientHandshake completed against openssl s_server (ECDSA)\n", .{});

    watchdog_stage.store(5, .release);
    generateRsaFixture(io, arena, openssl) catch |err| {
        std.debug.print("interop: FAIL — could not generate the RSA fixture ({t})\n", .{err});
        return 1;
    };
    runClientLeg(io, arena, openssl, .{
        .cert_path = rsa_cert_path,
        .key_path = rsa_key_path,
        .log_path = s_server_rsa_log_path,
        .port = port_base + port_attempts + 1,
        .expect_algo = .rsaEncryption,
    }) catch |err| {
        std.debug.print("interop: FAIL — our client against s_server, RSA ({t})\n", .{err});
        return 1;
    };
    std.debug.print("interop: ok — ClientHandshake completed against openssl s_server (RSA)\n", .{});

    watchdog_stage.store(6, .release);
    std.debug.print("interop: PASS — all five legs\n", .{});
    return 0;
}

/// Legs 1 to 3, every one of them `openssl s_client` against our server.
/// Split out of `main` because `main` should read as the list of phases
/// and was at TIGER_STYLE's line limit with no room for the next one.
///
/// Answers `true` when all passed; each message is printed here, beside
/// the leg that produced it, rather than handed back for `main` to
/// re-describe.
fn runServerLegs(io: Io, arena: std.mem.Allocator, openssl: []const u8) bool {
    watchdog_stage.store(1, .release);
    runServerLeg(io, arena, openssl, .{
        .cert_pem = cert_pem,
        .key_pem = key_pem,
        .cert_path = cert_path,
        .log_path = s_client_log_path,
        .expect_scheme = .ecdsa_secp256r1_sha256,
    }) catch |err| {
        std.debug.print("interop: FAIL — s_client against our server ({t})\n", .{err});
        return false;
    };
    std.debug.print("interop: ok — openssl s_client completed against ServerHandshake\n", .{});

    // The same leg over a P-384 leaf, and its own watchdog stage: folded
    // into leg 1's, a hang here would be reported under leg 1's name.
    //
    // Our own tests sign and verify this curve, but they are one tree
    // agreeing with itself; openssl verifying the CertificateVerify is
    // the first party here that did not also produce the signature.
    watchdog_stage.store(2, .release);
    runServerLeg(io, arena, openssl, .{
        .cert_pem = p384_cert_pem,
        .key_pem = p384_key_pem,
        .cert_path = p384_cert_path,
        .log_path = s_client_p384_log_path,
        .expect_scheme = .ecdsa_secp384r1_sha384,
    }) catch |err| {
        std.debug.print("interop: FAIL — s_client against our server, P-384 ({t})\n", .{err});
        return false;
    };
    std.debug.print("interop: ok — openssl s_client completed against ServerHandshake (P-384)\n", .{});

    // §4.1.4 against a foreign implementation. Our server refuses to
    // speak x25519 here, s_client is told to offer it first — and
    // openssl sends a key_share only for the first group it names — so
    // the handshake cannot complete without a HelloRetryRequest and a
    // second ClientHello answering it.
    //
    // `client_server_test` drives the same shape with both of our own
    // machines, which is one tree agreeing with itself. This is the
    // first party that did not also build the retry it is answering.
    watchdog_stage.store(3, .release);
    runServerLeg(io, arena, openssl, .{
        .cert_pem = cert_pem,
        .key_pem = key_pem,
        .cert_path = cert_path,
        .log_path = s_client_retry_log_path,
        .expect_scheme = .ecdsa_secp256r1_sha256,
        .groups = &.{ client_hello.group_secp256r1, client_hello.group_secp384r1 },
        .offer_groups = "X25519:P-256",
        .expect_group = .secp256r1,
        .expect_retry = true,
    }) catch |err| {
        std.debug.print("interop: FAIL — s_client against our server, retry ({t})\n", .{err});
        return false;
    };
    std.debug.print(
        "interop: ok — openssl s_client completed against ServerHandshake (HelloRetryRequest)\n",
        .{},
    );
    return true;
}

fn watchdogTask(io: Io) void {
    io.sleep(Io.Duration.fromNanoseconds(watchdog_budget_ns), .awake) catch return;
    const stage = watchdog_stage.load(.acquire);
    const name = switch (stage) {
        0 => "startup",
        1 => "s_client against our server (P-256)",
        2 => "s_client against our server (P-384)",
        3 => "s_client against our server (HelloRetryRequest)",
        4 => "our client against s_server (ECDSA)",
        5 => "our client against s_server (RSA)",
        else => "teardown",
    };
    std.debug.print("interop: FAIL — wedged in: {s}\n", .{name});
    const pid = watchdog_child_pid.load(.acquire);
    if (pid != 0) std.posix.kill(pid, std.posix.SIG.KILL) catch {};
    std.process.exit(1);
}

/// Homebrew's openssl first: macOS ships LibreSSL as `openssl`, and
/// LibreSSL's s_client has no `-tls1_3`.
fn findOpenssl(io: Io, arena: std.mem.Allocator) ![]const u8 {
    const candidates = [_][]const u8{
        "/opt/homebrew/opt/openssl@3/bin/openssl",
        "/usr/local/opt/openssl@3/bin/openssl",
        "/usr/bin/openssl",
        "openssl",
    };
    for (candidates) |candidate| {
        const supports = supportsTls13(io, arena, candidate) catch continue;
        if (supports) return candidate;
    }
    return error.NoOpensslWithTls13;
}

fn supportsTls13(io: Io, arena: std.mem.Allocator, path: []const u8) !bool {
    var child = std.process.spawn(io, .{
        .argv = &.{ path, "ciphers", "-s", "-tls1_3" },
        .stdout = .pipe,
        .stderr = .ignore,
        // A candidate that will not even spawn is simply not our
        // openssl; the next one gets its turn.
    }) catch return false;
    var output = child.stdout.?.reader(io, try arena.alloc(u8, 4096));
    var sink: [4096]u8 = undefined;
    // A probe that cannot be read answers "no" the same way an openssl
    // without 1.3 does: the caller only needs a verdict, not a reason.
    const read_bytes = output.interface.readSliceShort(&sink) catch 0;
    // Reaping is best-effort here — the probe is over either way, and a
    // failure to reap says nothing about the candidate's suitability.
    _ = child.wait(io) catch {};
    // The 1.3 suite names appear only on a build that speaks 1.3.
    return std.mem.indexOf(u8, sink[0..read_bytes], "TLS_AES_128_GCM_SHA256") != null;
}

fn writeFixtures(io: Io) !void {
    // mkdir -p semantics: an existing directory is the expected case,
    // and any real failure (permissions, no space) surfaces loudly on
    // the createFile below rather than being guessed at here.
    Io.Dir.cwd().createDirPath(io, work_dir) catch {};
    const cert = try Io.Dir.cwd().createFile(io, cert_path, .{});
    defer cert.close(io);
    try cert.writeStreamingAll(io, cert_pem);
    const key = try Io.Dir.cwd().createFile(io, key_path, .{});
    defer key.close(io);
    try key.writeStreamingAll(io, key_pem);
    const p384_cert = try Io.Dir.cwd().createFile(io, p384_cert_path, .{});
    defer p384_cert.close(io);
    try p384_cert.writeStreamingAll(io, p384_cert_pem);
    const p384_key = try Io.Dir.cwd().createFile(io, p384_key_path, .{});
    defer p384_key.close(io);
    try p384_key.writeStreamingAll(io, p384_key_pem);
}

/// Bind the first free loopback port at or after `port_base`.
fn listenLoopback(io: Io) !struct { server: Io.net.Server, port: u16 } {
    var attempt: u16 = 0;
    while (attempt < port_attempts) : (attempt += 1) {
        assert(attempt < port_attempts);
        const port = port_base + attempt;
        var address: Io.net.IpAddress = .{ .ip4 = .loopback(port) };
        const server = address.listen(io, .{ .reuse_address = true }) catch continue;
        return .{ .server = server, .port = port };
    }
    return error.NoFreePort;
}

/// What one server leg presents. Two legs differ only in the leaf, and
/// the leaf is the whole point of the second one: openssl verifying our
/// CertificateVerify is the only oracle here that did not also produce
/// the signature.
const ServerLeg = struct {
    cert_pem: []const u8,
    key_pem: []const u8,
    /// Where `writeFixtures` put the certificate, for openssl's -CAfile.
    cert_path: []const u8,
    log_path: []const u8,
    /// The scheme this leaf must make the server choose. Asserted rather
    /// than assumed: a leg that silently negotiated P-256 would pass
    /// while proving nothing about P-384.
    expect_scheme: backend.SignatureScheme,
    /// Our server's group preference. Leaving x25519 out is what makes
    /// it answer s_client's x25519 share with a HelloRetryRequest.
    groups: []const u16 = &client_hello.groups_supported,
    /// What s_client is told to offer, most preferred first; it sends a
    /// key_share for the first alone, so this decides whether a retry
    /// happens. Null leaves openssl's default list.
    offer_groups: ?[]const u8 = null,
    /// The group the completed handshake must have settled on. Asserted
    /// for the same reason `expect_scheme` is: a leg that quietly took
    /// the share it was first offered would pass while proving nothing
    /// about the preference it set.
    expect_group: backend.Group = .x25519,
    /// Whether a HelloRetryRequest must have gone out. Separate from
    /// `expect_group` on purpose — landing on the demanded group does
    /// not mean we demanded it, since a peer that key_shares everything
    /// it offers gets there in one round trip — and asserted in both
    /// directions, so a leg that means not to retry says so.
    expect_retry: bool = false,
};

/// The most arguments `serverLegArgv` can write: twelve fixed, plus one
/// flag and its value.
const argv_bytes_max: usize = 14;

/// The `s_client` command line for one leg, into caller-owned storage.
///
/// Built rather than written out at the call site because `-groups` is
/// conditional, and a leg that does not care which groups openssl offers
/// must not silently pin its default list — which is what naming the
/// flag unconditionally would do.
fn serverLegArgv(
    openssl: []const u8,
    connect_arg: []const u8,
    leg: ServerLeg,
    storage: *[argv_bytes_max][]const u8,
) []const []const u8 {
    var len: usize = 0;
    for ([_][]const u8{
        openssl,       "s_client",
        "-connect",    connect_arg,
        "-tls1_3",
        // Verify our chain against the fixture as its own root: the
        // point of the leg is that openssl's X.509 accepts what we
        // present, not that we ship a public CA's signature.
            "-CAfile",
        leg.cert_path, "-verify_return_error",
        "-servername", "spike.zoxy.test",
        "-quiet",      "-no_ign_eof",
    }) |arg| {
        assert(len < storage.len);
        storage[len] = arg;
        len += 1;
    }
    assert(len == argv_bytes_max - 2);
    if (leg.offer_groups) |groups| {
        storage[len] = "-groups";
        storage[len + 1] = groups;
        len += 2;
    }
    assert(len <= storage.len);
    return storage[0..len];
}

/// One `s_client` leg: openssl drives a handshake against our server,
/// then sends a line of application data which we echo back. What leaf
/// we present, which groups either side will speak, and what the result
/// must have negotiated are all `leg`'s to say.
fn runServerLeg(io: Io, arena: std.mem.Allocator, openssl: []const u8, leg: ServerLeg) !void {
    var listener = try listenLoopback(io);
    defer listener.server.deinit(io);

    const connect_arg = try std.fmt.allocPrint(arena, "127.0.0.1:{d}", .{listener.port});
    const log = try Io.Dir.cwd().createFile(io, leg.log_path, .{});
    defer log.close(io);
    var argv_storage: [argv_bytes_max][]const u8 = undefined;
    var child = try std.process.spawn(io, .{
        .argv = serverLegArgv(openssl, connect_arg, leg, &argv_storage),
        .stdin = .pipe,
        .stdout = .{ .file = log },
        .stderr = .{ .file = log },
    });
    var reaped = false;
    defer if (!reaped) child.kill(io);
    watchdog_child_pid.store(child.id orelse 0, .release);
    defer watchdog_child_pid.store(0, .release);

    const stream = try listener.server.accept(io);
    defer stream.close(io);

    var chain_storage: [Credentials.chain_bytes_max]u8 = undefined;
    var credentials = try Credentials.load(leg.cert_pem, leg.key_pem, &chain_storage, false);
    defer credentials.deinit();
    var reassembly: [16384]u8 = undefined;
    var flight: [Credentials.chain_bytes_max + 1024]u8 = undefined;
    var entropy: [80]u8 = undefined;
    io.random(&entropy);
    var server = ServerHandshake.init(&.{
        .credentials = &credentials,
        .server_random = entropy[0..32].*,
        .key_share_private = entropy[32..80].*,
        .groups = leg.groups,
        .reassembly = &reassembly,
        .flight = &flight,
    });
    defer server.deinit();

    var pump: Pump = undefined;
    pump.init(io, stream);
    const retried = try pump.handshakeServer(&server);
    if (server.signature_scheme != leg.expect_scheme) return error.WrongSignatureScheme;
    if (server.key_share_group != leg.expect_group) return error.WrongGroup;
    if (retried != leg.expect_retry) return error.WrongRetryOutcome;

    // The peer talks first here: s_client sends what we write to its
    // stdin. One line in, the same line back out.
    const greeting = "hello from zssl interop\n";
    try child.stdin.?.writeStreamingAll(io, greeting);
    const echoed = try pump.readApplication(&server);
    if (!std.mem.eql(u8, echoed, greeting)) return error.EchoMismatch;
    var out: [record.wire_record_bytes_max]u8 = undefined;
    try pump.write(try server.sendApplicationData(echoed, &out));
    try pump.write(try server.sendClose(&out));

    child.stdin.?.close(io);
    child.stdin = null;
    const term = try child.wait(io);
    reaped = true;
    // s_client returns non-zero when verification fails, which is the
    // assertion this leg exists for.
    switch (term) {
        .exited => |code| if (code != 0) {
            try printFile(io, arena, leg.log_path);
            return error.SclientFailed;
        },
        else => return error.SclientSignalled,
    }
}

/// Have openssl mint a throwaway RSA-2048 self-signed leaf for leg 4.
///
/// 2048 bits because it is what the public web overwhelmingly presents,
/// and because it exercises the 256-byte modulus arm of
/// `verifyRsaPss` — the one an upstream is most likely to hand us.
/// openssl chooses `rsa_pss_rsae_sha256` for the CertificateVerify on
/// its own, which is the scheme we most need proven.
fn generateRsaFixture(io: Io, arena: std.mem.Allocator, openssl: []const u8) !void {
    var child = try std.process.spawn(io, .{
        .argv = &.{
            openssl,    "req",
            "-x509",    "-newkey",
            "rsa:2048", "-nodes",
            "-keyout",  rsa_key_path,
            "-out",     rsa_cert_path,
            "-days",    "1",
            "-subj",    "/CN=spike.zoxy.test",
            "-addext",  "subjectAltName=DNS:spike.zoxy.test",
            // The default digest is fine, but pinning it keeps the
            // fixture identical across openssl versions.
            "-sha256",
        },
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .pipe,
    });
    // Read stderr before waiting: openssl narrates key generation there,
    // and a full pipe would deadlock the child we are about to reap.
    var stderr = child.stderr.?.reader(io, try arena.alloc(u8, 4096));
    var sink: [4096]u8 = undefined;
    const complained = stderr.interface.readSliceShort(&sink) catch 0;
    switch (try child.wait(io)) {
        .exited => |code| if (code != 0) {
            std.debug.print("interop: openssl req said: {s}\n", .{sink[0..complained]});
            return error.RsaFixtureFailed;
        },
        else => return error.RsaFixtureSignalled,
    }
}

/// The `chain_verifier` seam, as an embedder would use it minus the
/// X.509: count what the peer presented so the leg can assert the chain
/// actually reached us. Returning false here would abort the handshake,
/// which is the property the seam exists to give an embedder.
const ChainWitness = struct {
    entries: usize = 0,
    leaf_bytes: usize = 0,
    malformed: bool = false,
    /// What the leaf's SPKI actually says, so a leg can assert it drove
    /// the code path it claims to. Without this the RSA leg would still
    /// pass if openssl quietly presented an ECDSA certificate, and the
    /// arm it exists to cover would go untested.
    leaf_algo: ?std.meta.Tag(std.crypto.Certificate.Parsed.PubKeyAlgo) = null,

    fn verify(context: *anyopaque, chain: zssl.certificate_list.CertificateList) bool {
        const self: *ChainWitness = @ptrCast(@alignCast(context));
        var it = chain.iterator();
        while (it.next() catch {
            self.malformed = true;
            return false;
        }) |entry| {
            if (self.entries == 0) {
                self.leaf_bytes = entry.len;
                const certificate: std.crypto.Certificate = .{ .buffer = entry, .index = 0 };
                if (certificate.parse()) |parsed| {
                    self.leaf_algo = parsed.pub_key_algo;
                } else |_| {
                    self.malformed = true;
                    return false;
                }
            }
            self.entries += 1;
        }
        return true;
    }
};

const ClientLegOptions = struct {
    cert_path: []const u8,
    key_path: []const u8,
    log_path: []const u8,
    port: u16,
    /// The leaf key type this leg exists to exercise.
    expect_algo: std.meta.Tag(std.crypto.Certificate.Parsed.PubKeyAlgo),
};

/// Legs 3 and 4: `openssl s_server` accepts one connection from our
/// client, presenting whichever key type `options` names.
fn runClientLeg(
    io: Io,
    arena: std.mem.Allocator,
    openssl: []const u8,
    options: ClientLegOptions,
) !void {
    // The child binds, so pick a port it is likely to get and let the
    // connect retry cover the race.
    const port = options.port;
    const accept_arg = try std.fmt.allocPrint(arena, "{d}", .{port});
    // Both streams to one log: `-quiet` makes s_server echo the
    // plaintext it decrypted to stdout, which is the evidence this leg
    // rests on — our bytes came out the far side readable.
    const log = try Io.Dir.cwd().createFile(io, options.log_path, .{});
    defer log.close(io);
    var child = try std.process.spawn(io, .{
        .argv = &.{
            openssl,   "s_server",
            "-accept", accept_arg,
            "-cert",   options.cert_path,
            "-key",    options.key_path,
            "-tls1_3", "-naccept",
            // `-rev` echoes each line back reversed over TLS, which is
            // what lets our client prove it can *decrypt* records real
            // openssl produced, not merely encrypt ones it accepts. No
            // `-quiet`: the session banner it suppresses is the log
            // evidence this leg asserts on.
            "1",       "-rev",
        },
        .stdin = .pipe,
        .stdout = .{ .file = log },
        .stderr = .{ .file = log },
    });
    var reaped = false;
    defer if (!reaped) child.kill(io);
    watchdog_child_pid.store(child.id orelse 0, .release);
    defer watchdog_child_pid.store(0, .release);

    const stream = try connectWithRetry(io, port);
    defer stream.close(io);

    var reassembly: [16384]u8 = undefined;
    var entropy: [80]u8 = undefined;
    io.random(&entropy);
    var witness: ChainWitness = .{};
    var client = ClientHandshake.init(&.{
        .client_random = entropy[0..32].*,
        .x25519_private = entropy[32..64].*,
        .server_name = "spike.zoxy.test",
        // s_server offers no ALPN, so this proves the offer is *sent*
        // and its absence from EncryptedExtensions is survivable — not
        // that a selection round-trips, which the unit suite covers.
        .alpn_protocols = &.{ "h2", "http/1.1" },
        // openssl presents the fixture leaf; our policy proves it holds
        // the key its certificate names.
        .certificate_policy = .leaf_signature,
        .chain_verifier = .{ .context = &witness, .verify = ChainWitness.verify },
        .reassembly = &reassembly,
    });
    defer client.deinit();

    var pump: Pump = undefined;
    pump.init(io, stream);
    try pump.handshakeClient(&client);
    if (!client.certificate_verified) return error.CertificateNotVerified;
    // The seam ran, and ran on real bytes: a verifier that is never
    // called would leave an embedder believing it had validated a chain
    // it never saw.
    if (witness.malformed) return error.ChainMalformed;
    if (witness.entries == 0) return error.ChainVerifierNotCalled;
    if (witness.leaf_bytes < 64) return error.ChainLeafImplausible;
    if (witness.leaf_algo != options.expect_algo) return error.UnexpectedLeafKeyType;
    // s_server names no protocol, so neither may we.
    if (client.alpnSelected() != null) return error.UnexpectedAlpnSelection;

    var out: [record.wire_record_bytes_max]u8 = undefined;
    const greeting = "hello from zssl client\n";
    try pump.write(try client.sendApplicationData(greeting, &out));
    // The far side reverses the line and sends it back; reading it is
    // this leg's proof that our record layer opens what openssl sealed.
    const echoed = try pump.readApplication(&client);
    var expected: [greeting.len]u8 = undefined;
    reverseLine(greeting, &expected);
    if (!std.mem.eql(u8, echoed, expected[0..echoed.len])) {
        std.debug.print("interop: expected reversed echo, got '{s}'\n", .{echoed});
        return error.EchoMismatch;
    }
    try pump.write(try client.sendClose(&out));

    child.stdin.?.close(io);
    child.stdin = null;
    const term = try child.wait(io);
    reaped = true;
    switch (term) {
        .exited => |code| if (code != 0) {
            try printFile(io, arena, options.log_path);
            return error.SserverFailed;
        },
        else => {
            try printFile(io, arena, options.log_path);
            return error.SserverSignalled;
        },
    }
    // openssl's own account of the session: it negotiated 1.3 and
    // counted an accept that *finished*, which a handshake that merely
    // started would not produce.
    if (!try fileContains(io, arena, options.log_path, "Protocol version: TLSv1.3")) {
        try printFile(io, arena, options.log_path);
        return error.NoTls13Negotiated;
    }
    if (!try fileContains(io, arena, options.log_path, "1 server accepts that finished")) {
        try printFile(io, arena, options.log_path);
        return error.AcceptDidNotFinish;
    }
}

/// s_server's `-rev` reverses the line's characters, keeping the
/// trailing newline where it is.
fn reverseLine(line: []const u8, out: []u8) void {
    assert(line.len >= 2);
    assert(out.len == line.len);
    assert(line[line.len - 1] == '\n');
    const body = line[0 .. line.len - 1];
    for (body, 0..) |byte, index| out[body.len - 1 - index] = byte;
    out[line.len - 1] = '\n';
}

fn readFileAlloc(io: Io, arena: std.mem.Allocator, path: []const u8) ![]const u8 {
    const file = try Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);
    const buffer = try arena.alloc(u8, 64 * 1024);
    var reader = file.reader(io, buffer);
    var sink = try arena.alloc(u8, 64 * 1024);
    const read_bytes = reader.interface.readSliceShort(sink) catch |err| switch (err) {
        error.ReadFailed => return error.ReadFailed,
    };
    return sink[0..read_bytes];
}

fn fileContains(io: Io, arena: std.mem.Allocator, path: []const u8, needle: []const u8) !bool {
    assert(needle.len >= 1);
    const contents = try readFileAlloc(io, arena, path);
    return std.mem.indexOf(u8, contents, needle) != null;
}

fn printFile(io: Io, arena: std.mem.Allocator, path: []const u8) !void {
    const contents = readFileAlloc(io, arena, path) catch return;
    if (contents.len >= 1) std.debug.print("interop: {s}:\n{s}\n", .{ path, contents });
}

fn connectWithRetry(io: Io, port: u16) !Io.net.Stream {
    var attempt: u16 = 0;
    while (attempt < 200) : (attempt += 1) {
        assert(attempt < 200);
        var address: Io.net.IpAddress = .{ .ip4 = .loopback(port) };
        return address.connect(io, .{ .mode = .stream }) catch {
            io.sleep(Io.Duration.fromNanoseconds(25 * std.time.ns_per_ms), .awake) catch {};
            continue;
        };
    }
    return error.ServerNeverListened;
}

/// The socket side of a session: raw bytes in, whole records out, and
/// whatever the machine answers written straight back.
const Pump = struct {
    io: Io,
    stream: Io.net.Stream,
    records: zssl.record_buffer.RecordBuffer,
    /// The reader and writer are built once and kept: a fresh `Reader`
    /// per call would drop whatever the previous one had buffered but
    /// not yet returned, which reads as a peer that stopped talking.
    reader: Io.net.Stream.Reader,
    writer: Io.net.Stream.Writer,
    read_buffer: [4 * record.wire_record_bytes_max]u8,
    write_buffer: [4 * record.wire_record_bytes_max]u8,
    storage: [4 * record.wire_record_bytes_max]u8,
    out: [4 * record.wire_record_bytes_max]u8,
    plaintext: [record.wire_record_bytes_max]u8,
    plaintext_bytes: usize,

    /// In place through an out-pointer: the reader and writer hold
    /// pointers into the buffers beside them, so the address has to be
    /// final before either is built.
    fn init(pump: *Pump, io: Io, stream: Io.net.Stream) void {
        pump.io = io;
        pump.stream = stream;
        pump.plaintext_bytes = 0;
        pump.records = zssl.record_buffer.RecordBuffer.init(&pump.storage);
        pump.reader = stream.reader(io, &pump.read_buffer);
        pump.writer = stream.writer(io, &pump.write_buffer);
    }

    fn write(pump: *Pump, bytes: []const u8) !void {
        assert(bytes.len >= 1);
        try pump.writer.interface.writeAll(bytes);
        try pump.writer.interface.flush();
    }

    /// Read one wire record, refilling from the socket as needed.
    fn nextRecord(pump: *Pump) ![]const u8 {
        var refills: u16 = 0;
        while (true) : (refills += 1) {
            assert(refills < 4096);
            if (try pump.records.next()) |one| return one;
            // `fill(1)` blocks only until *something* arrives; taking
            // `buffered()` then consumes exactly what did. Asking for a
            // fixed count instead (readSliceShort) would wait for bytes
            // the peer will not send until it hears from us — a deadlock
            // that looks exactly like a hung socket.
            pump.reader.interface.fill(1) catch |err| switch (err) {
                error.EndOfStream => return error.PeerClosed,
                else => return err,
            };
            const available = pump.reader.interface.buffered();
            assert(available.len >= 1);
            try pump.records.push(available);
            pump.reader.interface.toss(available.len);
        }
    }

    /// Answers whether a HelloRetryRequest went out on the way. The
    /// caller cannot infer it from the finished connection: a peer that
    /// sends a key_share for every group it offers lands on the same
    /// negotiated group with no retry at all, so the leg that means to
    /// exercise §4.1.4 has to watch it happen.
    fn handshakeServer(pump: *Pump, server: *ServerHandshake) !bool {
        var records_seen: u16 = 0;
        var retried = false;
        while (server.state != .connected) : (records_seen += 1) {
            assert(records_seen < 64);
            const one = try pump.nextRecord();
            if (try server.handleRecord(one, &pump.out)) |event| switch (event) {
                .send => |bytes| try pump.write(bytes),
                .connected => {},
                else => return error.UnexpectedEvent,
            };
            if (server.state == .awaiting_retry_client_hello) retried = true;
        }
        return retried;
    }

    fn handshakeClient(pump: *Pump, client: *ClientHandshake) !void {
        try pump.write(client.start(&pump.out));
        var records_seen: u16 = 0;
        while (client.state != .connected) : (records_seen += 1) {
            assert(records_seen < 64);
            const one = try pump.nextRecord();
            if (try client.handleRecord(one, &pump.out)) |event| switch (event) {
                .send, .connected => |bytes| try pump.write(bytes),
                else => return error.UnexpectedEvent,
            };
        }
    }

    /// Read records until one carries application data. Generic over
    /// the two machines: both answer the same event union.
    fn readApplication(pump: *Pump, machine: anytype) ![]const u8 {
        var records_seen: u16 = 0;
        var tickets_seen: u16 = 0;
        while (records_seen < 64) : (records_seen += 1) {
            // Deliberately not `assert(tickets_seen <= records_seen)`.
            // That held only while one record meant at most one event,
            // and a real openssl server sends two NewSessionTickets —
            // packed into one record, which is the shape this gate now
            // exists to prove works. The count is the peer's to choose
            // and is bounded by §5's record cap, not by how many records
            // it took; asserting a relationship the peer controls is how
            // a harness aborts against a compliant server.
            const one = try pump.nextRecord();
            // Drained rather than taken one event at a time: a real
            // openssl server packs its NewSessionTickets, and the record
            // that carries the application data may carry them too. The
            // whole record is consumed before the next is read, because
            // `handleRecord` refuses to run with events still pending.
            var found: ?[]const u8 = null;
            var event = try machine.handleRecord(one, &pump.out);
            while (event) |ready| : (event = try machine.drain(&pump.out)) {
                switch (ready) {
                    .application_data => |bytes| {
                        @memcpy(pump.plaintext[0..bytes.len], bytes);
                        pump.plaintext_bytes = bytes.len;
                        found = pump.plaintext[0..bytes.len];
                    },
                    .send => {},
                    else => {
                        // A real openssl server issues NewSessionTickets
                        // right after the handshake; parsing them without
                        // incident is itself a small proof, and they are
                        // not what we came to read here. Matched by tag
                        // name because only the client machine has the
                        // variant, and this helper serves both.
                        if (!std.mem.eql(u8, @tagName(ready), "ticket")) {
                            return error.UnexpectedEvent;
                        }
                        tickets_seen += 1;
                    },
                }
            }
            if (found) |bytes| return bytes;
        }
        return error.NoApplicationData;
    }
};
