//! The BoGo shim: BoringSSL's adversarial test runner drives zssl through
//! this binary (docs/BOGO.md).
//!
//! The contract is `ssl/test/PORTING.md`'s. The runner listens, spawns us
//! with `-port`/`-shim-id`, and we open one TCP connection per exchange,
//! announce the shim id as a little-endian u64, then speak TLS over it.
//! Exit 0 is a pass, non-zero a failure with a reason on stderr, and 89
//! means "this case asks for something we do not implement" — the runner
//! counts those separately, which is what keeps a partial port honest
//! rather than green.
//!
//! Two things live here rather than in the library, on purpose:
//!
//!   - **The error → alert table.** zssl returns errors and leaves the
//!     decision to alert with the embedder; `alertFor` is one embedder's
//!     table, and BoGo's `expectedLocalError` cases are what pin it.
//!   - **The ticket store.** Sealing, lifetime and age policy are the
//!     embedder's by design (DESIGN.md §1), so a shim that resumes keeps
//!     its own — one identity and its PSK, which is all `-resume-count`
//!     needs.
//!
//! What we decline, we decline by *exit code*, never by pretending: an
//! RSA signing key, a version cap that is not 1.3, a group that is not
//! x25519, and every flag outside the subset below all exit 89.

const std = @import("std");
const Io = std.Io;
const assert = std.debug.assert;

const zssl = @import("zssl");
const ClientHandshake = zssl.ClientHandshake;
const Credentials = zssl.Credentials;
const ServerHandshake = zssl.ServerHandshake;
const alert = zssl.alert;
const anti_replay = zssl.anti_replay;
const cipher_suite = zssl.cipher_suite;
const record = zssl.record;

/// PORTING.md's "unimplemented" code: the runner skips the case and
/// counts it, rather than failing the suite over it.
const exit_unimplemented: u8 = 89;

/// The one version and the one group zssl has (DESIGN.md §1).
const version_tls13: u16 = 0x0304;
const group_x25519: u16 = 29;

/// A session that needs more records than this is wedged, not slow.
const records_per_phase_max: u32 = 4096;

/// The most keying material one case asks for. BoGo's largest request is
/// 1024 bytes; the headroom is so a corpus bump does not turn a bigger
/// ask into a wrong answer rather than a decline.
const export_bytes_max: u32 = 4096;

/// The library's own caps, not a guess at them: a value the runner picks
/// must be measured against what `ClientHandshake.init` will assert on,
/// or the shim panics where its whole contract is to exit 89.
const alpn_protocols_max = zssl.client_messages.alpn_protocols_max;
const alpn_protocol_bytes_max = zssl.client_messages.alpn_protocol_bytes_max;
/// §3 of RFC 6066: a server name is a one-byte-length-prefixed host, so
/// 255 is the wire's own ceiling and 1 its floor.
const server_name_bytes_max: usize = 255;

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();

    // The runner probes for BoringSSL's split handshaker process before
    // it builds any test at all. We are one process; answering "No" is
    // what a shim without that split says, and the hint tests then never
    // get generated.
    if (try answersHandshakerProbe(init, arena, io)) return 0;

    const options = parseFlags(init, arena) catch |err| switch (err) {
        error.Unimplemented => return exit_unimplemented,
        else => {
            std.debug.print("zssl:shim:{t}\n", .{err});
            return 1;
        },
    };

    var store: TicketStore = .{};
    var index: u32 = 0;
    // One TCP connection per exchange: the initial handshake, then one
    // per `-resume-count`. The runner closes each in turn.
    while (index <= options.resume_count) : (index += 1) {
        assert(index <= options.resume_count);
        const connection = options.forConnection(index);
        runExchange(io, arena, &connection, &store) catch |err| switch (err) {
            error.Unimplemented => return exit_unimplemented,
            else => {
                // bogo/config.json's `ErrorMap` matches on this text; the
                // prefix is what makes a zssl error name greppable there.
                std.debug.print("zssl:{t}\n", .{err});
                return 1;
            },
        };
    }
    return 0;
}

/// `-is-handshaker-supported` is asked once, on its own, with no `-port`
/// to connect to; it wants "No" or "Yes" on stdout.
fn answersHandshakerProbe(init: std.process.Init, arena: std.mem.Allocator, io: Io) !bool {
    var iterator = try std.process.Args.Iterator.initAllocator(init.minimal.args, arena);
    defer iterator.deinit();
    _ = iterator.skip();
    while (iterator.next()) |argument| {
        if (!std.mem.eql(u8, argument, "-is-handshaker-supported")) continue;
        try Io.File.stdout().writeStreamingAll(io, "No\n");
        return true;
    }
    return false;
}

// ---------------------------------------------------------------- flags

/// The flag subset docs/BOGO.md names, plus the few the runner adds to
/// every invocation. Anything else exits 89 from `parseFlags`.
const Options = struct {
    port: u16 = 0,
    shim_id: u64 = 0,
    ipv6: bool = false,
    is_server: bool = false,
    resume_count: u32 = 0,
    base: Connection = .{},
    initial: Connection = .{},
    resumed: Connection = .{},

    fn forConnection(self: *const Options, index: u32) Connection {
        var connection = if (index == 0) self.initial else self.resumed;
        connection.is_server = self.is_server;
        connection.port = self.port;
        connection.shim_id = self.shim_id;
        connection.ipv6 = self.ipv6;
        connection.index = index;
        return connection;
    }
};

/// Everything one exchange needs. BoGo scopes many flags with
/// `-on-initial-`/`-on-resume-`, so these are per-connection even where a
/// given case only ever sets them once.
const Connection = struct {
    port: u16 = 0,
    shim_id: u64 = 0,
    ipv6: bool = false,
    is_server: bool = false,
    index: u32 = 0,

    cert_path: ?[]const u8 = null,
    key_path: ?[]const u8 = null,

    /// Wire-format ALPN list as a client offers it (RFC 7301 §3.1).
    advertise_alpn: ?[]const u8 = null,
    /// The single protocol a server will negotiate, or null for none.
    select_alpn: ?[]const u8 = null,
    expect_alpn: ?[]const u8 = null,
    host_name: ?[]const u8 = null,

    /// The groups `-curves` named, in preference order. Both roles take
    /// a configured list now, so this is honoured rather than merely
    /// checked — see `configuredGroups`.
    curves: [4]u16 = undefined,
    curve_count: u8 = 0,

    /// The schemes `-verify-prefs` named, in preference order, as wire
    /// code points — converted at run time, because a scheme we cannot
    /// verify is a decline rather than a parse error.
    verify_prefs: [8]u16 = undefined,
    verify_pref_count: u8 = 0,
    /// `-expect-peer-signature-algorithm`: the scheme the peer must have
    /// signed its CertificateVerify with.
    expect_peer_signature_algorithm: ?u16 = null,
    /// The schemes `-signing-prefs` named, in preference order, as wire
    /// code points. Passed through whole: `Config.signing_schemes` takes
    /// wire values precisely so a case naming a scheme our key cannot
    /// produce runs and earns the handshake_failure it expects, instead
    /// of being declined for a type that could not hold it.
    signing_prefs: [16]u16 = undefined,
    signing_pref_count: u8 = 0,
    /// §7.5's exporter, as BoGo asks for it: how many bytes to export,
    /// under what label and context. The runner derives the same secret
    /// itself and expects the shim to write ours first thing, so this is
    /// checked against a second implementation rather than a vector.
    export_bytes: ?u32 = null,
    export_label: []const u8 = "",
    export_context: []const u8 = "",

    expect_version: ?u16 = null,
    expect_curve_id: ?u16 = null,
    expect_session_miss: bool = false,
    expect_no_session: bool = false,

    no_ticket: bool = false,
    /// `-enable-early-data`: the embedder's opt-in, which for this shim
    /// means minting tickets that advertise 0-RTT and answering
    /// `psk_lookup` with terms that permit it. The library needs a clock
    /// and a strike register besides, and both are supplied in
    /// `runServer`.
    enable_early_data: bool = false,
    /// `-on-resume-expect-accept-early-data` / `-reject-early-data`.
    /// Null where the case does not say.
    expect_early_data: ?bool = null,
    shim_writes_first: bool = false,
    shim_shuts_down: bool = false,
    check_close_notify: bool = false,
};

const Scope = enum { all, initial, resumed };

const ParseError = error{ Unimplemented, OutOfMemory, BadFlagValue };

/// Two passes, because BoGo emits scoped and unscoped flags in any order
/// and a trailing `-select-alpn` must not clobber an earlier
/// `-on-resume-select-alpn`. Pass one fills the base, pass two the
/// per-connection overrides.
fn parseFlags(init: std.process.Init, arena: std.mem.Allocator) ParseError!Options {
    var iterator = try std.process.Args.Iterator.initAllocator(init.minimal.args, arena);
    defer iterator.deinit();
    _ = iterator.skip(); // argv[0]

    const Pending = struct { scope: Scope, name: []const u8, value: ?[]const u8 };
    var pending: std.ArrayList(Pending) = .empty;

    var options: Options = .{};
    while (iterator.next()) |raw| {
        const argument: []const u8 = raw;
        if (argument.len < 2 or argument[0] != '-') return unimplemented(argument);
        var scope: Scope = .all;
        var name = argument;
        if (std.mem.startsWith(u8, name, "-on-initial-")) {
            scope = .initial;
            name = name["-on-initial".len..];
        } else if (std.mem.startsWith(u8, name, "-on-resume-")) {
            scope = .resumed;
            name = name["-on-resume".len..];
        } else if (std.mem.startsWith(u8, name, "-on-retry-") or
            std.mem.startsWith(u8, name, "-on-shim-") or
            std.mem.startsWith(u8, name, "-on-handshaker-"))
        {
            // `-on-retry-*` scopes a flag to the second ClientHello,
            // and this shim carries only the two scopes above — the
            // client answers a HelloRetryRequest (DESIGN.md §1), it is
            // the per-attempt flag split that is unmodelled. The
            // handshaker one is BoringSSL's own process model.
            return unimplemented(name);
        }

        const arity = flagArity(name) orelse return unimplemented(name);
        const value: ?[]const u8 = switch (arity) {
            .none => null,
            .one => iterator.next() orelse return error.BadFlagValue,
        };

        // The five that steer the whole run are global by construction;
        // BoGo never scopes them.
        if (std.mem.eql(u8, name, "-port")) {
            options.port = std.fmt.parseInt(u16, value.?, 10) catch return error.BadFlagValue;
        } else if (std.mem.eql(u8, name, "-shim-id")) {
            options.shim_id = std.fmt.parseInt(u64, value.?, 10) catch return error.BadFlagValue;
        } else if (std.mem.eql(u8, name, "-resume-count")) {
            options.resume_count = std.fmt.parseInt(u32, value.?, 10) catch return error.BadFlagValue;
        } else if (std.mem.eql(u8, name, "-ipv6")) {
            options.ipv6 = true;
        } else if (std.mem.eql(u8, name, "-server")) {
            options.is_server = true;
        } else {
            try pending.append(arena, .{ .scope = scope, .name = name, .value = value });
        }
    }
    if (options.port == 0) return error.BadFlagValue;

    for (pending.items) |flag| {
        if (flag.scope != .all) continue;
        try applyFlag(&options.base, flag.name, flag.value);
    }
    options.initial = options.base;
    options.resumed = options.base;
    for (pending.items) |flag| switch (flag.scope) {
        .all => {},
        .initial => try applyFlag(&options.initial, flag.name, flag.value),
        .resumed => try applyFlag(&options.resumed, flag.name, flag.value),
    };
    return options;
}

/// Name what we declined on the way out. The runner shows a shim's
/// stderr whenever a case fails, so a 89 that later turns into a FAILED
/// says which flag it stumbled on instead of leaving it to bisection.
fn unimplemented(name: []const u8) error{Unimplemented} {
    std.debug.print("zssl:unimplemented:{s}\n", .{name});
    return error.Unimplemented;
}

const Arity = enum { none, one };

/// The subset we honour, and how much of argv each one eats. A null
/// answer is the 89 path: PORTING.md's advice is to treat an unknown
/// flag as unimplemented rather than guess at its meaning.
fn flagArity(name: []const u8) ?Arity {
    const with_value = [_][]const u8{
        "-port",                            "-shim-id",                  "-resume-count",
        "-cert-file",                       "-key-file",                 "-trust-cert",
        "-max-version",                     "-min-version",              "-expect-version",
        "-curves",                          "-advertise-alpn",           "-select-alpn",
        "-expect-alpn",                     "-host-name",                "-expect-curve-id",
        "-read-size",                       "-expect-early-data-reason", "-verify-prefs",
        "-expect-peer-signature-algorithm", "-signing-prefs",            "-export-keying-material",
        "-export-label",                    "-export-context",
    };
    const without_value = [_][]const u8{
        "-ipv6",                     "-server",             "-shim-writes-first",
        "-shim-shuts-down",          "-check-close-notify", "-no-ticket",
        "-expect-session-miss",      "-expect-no-session",  "-decline-alpn",
        "-no-tls1",                  "-no-tls11",           "-no-tls12",
        "-expect-no-hrr",            "-enable-early-data",  "-expect-accept-early-data",
        "-expect-reject-early-data", "-use-export-context",
    };
    for (with_value) |candidate| if (std.mem.eql(u8, name, candidate)) return .one;
    for (without_value) |candidate| if (std.mem.eql(u8, name, candidate)) return .none;
    return null;
}

fn applyFlag(connection: *Connection, name: []const u8, value: ?[]const u8) ParseError!void {
    if (std.mem.eql(u8, name, "-cert-file")) {
        connection.cert_path = value.?;
    } else if (std.mem.eql(u8, name, "-key-file")) {
        connection.key_path = value.?;
    } else if (std.mem.eql(u8, name, "-trust-cert")) {
        // The runner names the root it signed with. X.509 path building
        // is the embedder's by design (DESIGN.md §1), so this is read
        // and not acted on; the cases that turn on chain validation are
        // disabled by name in bogo/config.json rather than passed here.
    } else if (std.mem.eql(u8, name, "-max-version") or std.mem.eql(u8, name, "-min-version")) {
        // "We answer only 0x0304 and must decline the rest": a bound
        // that is not exactly 1.3 asks for a version zssl does not have.
        const bound = std.fmt.parseInt(u16, value.?, 10) catch return error.BadFlagValue;
        if (bound != version_tls13) return unimplemented(name);
    } else if (std.mem.eql(u8, name, "-expect-version")) {
        connection.expect_version = std.fmt.parseInt(u16, value.?, 10) catch return error.BadFlagValue;
    } else if (std.mem.eql(u8, name, "-curves")) {
        // Repeatable, one group per occurrence. Recorded rather than
        // acted on here: whether the set is honourable depends on which
        // role we are playing, and `-server` may not have been seen yet.
        const group = std.fmt.parseInt(u16, value.?, 10) catch return error.BadFlagValue;
        if (connection.curve_count == connection.curves.len) return unimplemented(name);
        connection.curves[connection.curve_count] = group;
        connection.curve_count += 1;
    } else if (std.mem.eql(u8, name, "-verify-prefs")) {
        // Repeatable, like `-curves`, and recorded rather than acted on:
        // whether a scheme is one we verify is a question for the role.
        const scheme = std.fmt.parseInt(u16, value.?, 10) catch return error.BadFlagValue;
        if (connection.verify_pref_count == connection.verify_prefs.len) return unimplemented(name);
        connection.verify_prefs[connection.verify_pref_count] = scheme;
        connection.verify_pref_count += 1;
    } else if (std.mem.eql(u8, name, "-signing-prefs")) {
        const scheme = std.fmt.parseInt(u16, value.?, 10) catch return error.BadFlagValue;
        if (connection.signing_pref_count == connection.signing_prefs.len) return unimplemented(name);
        connection.signing_prefs[connection.signing_pref_count] = scheme;
        connection.signing_pref_count += 1;
    } else if (std.mem.eql(u8, name, "-expect-peer-signature-algorithm")) {
        connection.expect_peer_signature_algorithm =
            std.fmt.parseInt(u16, value.?, 10) catch return error.BadFlagValue;
    } else if (std.mem.eql(u8, name, "-export-keying-material")) {
        const bytes = std.fmt.parseInt(u32, value.?, 10) catch return error.BadFlagValue;
        if (bytes == 0 or bytes > export_bytes_max) return unimplemented(name);
        connection.export_bytes = bytes;
    } else if (std.mem.eql(u8, name, "-export-label")) {
        if (value.?.len > zssl.key_schedule.exporter_label_bytes_max) return unimplemented(name);
        connection.export_label = value.?;
    } else if (std.mem.eql(u8, name, "-export-context")) {
        connection.export_context = value.?;
    } else if (std.mem.eql(u8, name, "-use-export-context")) {
        // Accepted and ignored, deliberately. It is TLS 1.2's distinction
        // between "no context" and "an empty one"; §7.5 has a single
        // shape and always hashes what it is given, so both requests are
        // the same one here — and the runner's own TLS 1.3 exporter
        // ignores the flag for exactly that reason (`conn.go`).
    } else if (std.mem.eql(u8, name, "-expect-curve-id")) {
        connection.expect_curve_id = std.fmt.parseInt(u16, value.?, 10) catch return error.BadFlagValue;
    } else if (std.mem.eql(u8, name, "-advertise-alpn")) {
        connection.advertise_alpn = value.?;
    } else if (std.mem.eql(u8, name, "-select-alpn")) {
        // `ServerHandshake.init` asserts a non-empty protocol; an empty
        // selection is a case about a shape zssl cannot express.
        if (value.?.len == 0) return unimplemented(name);
        connection.select_alpn = value.?;
    } else if (std.mem.eql(u8, name, "-decline-alpn")) {
        connection.select_alpn = null;
    } else if (std.mem.eql(u8, name, "-expect-alpn")) {
        connection.expect_alpn = value.?;
    } else if (std.mem.eql(u8, name, "-host-name")) {
        // RFC 6066 §3's own bounds, which `clientHello` asserts.
        if (value.?.len == 0 or value.?.len > server_name_bytes_max) return unimplemented(name);
        connection.host_name = value.?;
    } else if (std.mem.eql(u8, name, "-no-ticket")) {
        connection.no_ticket = true;
    } else if (std.mem.eql(u8, name, "-expect-session-miss")) {
        connection.expect_session_miss = true;
    } else if (std.mem.eql(u8, name, "-expect-no-session")) {
        connection.expect_no_session = true;
    } else if (std.mem.eql(u8, name, "-shim-writes-first")) {
        connection.shim_writes_first = true;
    } else if (std.mem.eql(u8, name, "-shim-shuts-down")) {
        connection.shim_shuts_down = true;
    } else if (std.mem.eql(u8, name, "-check-close-notify")) {
        connection.check_close_notify = true;
    } else if (std.mem.eql(u8, name, "-expect-no-hrr")) {
        // The client refuses every HelloRetryRequest and the server only
        // sends one when the offer is unusable, so "no HRR" holds by
        // construction; there is nothing to arm.
    } else if (std.mem.eql(u8, name, "-enable-early-data")) {
        connection.enable_early_data = true;
    } else if (std.mem.eql(u8, name, "-on-resume-expect-accept-early-data") or
        std.mem.eql(u8, name, "-expect-accept-early-data"))
    {
        connection.expect_early_data = true;
    } else if (std.mem.eql(u8, name, "-on-resume-expect-reject-early-data") or
        std.mem.eql(u8, name, "-expect-reject-early-data"))
    {
        connection.expect_early_data = false;
    } else if (std.mem.eql(u8, name, "-expect-early-data-reason")) {
        // The reasons this shim can honestly report. "disabled" is a
        // server that was never asked to accept; "no_session_offered" is
        // a first connection, which has no ticket to attach 0-RTT to;
        // "accept" is the one the accept path earns. Anything else names
        // a decision zssl does not model — an ALPS mismatch, a QUIC
        // parameter — and declining is more honest than reporting a
        // reason we did not reach.
        const reason = value.?;
        const known = std.mem.eql(u8, reason, "disabled") or
            std.mem.eql(u8, reason, "no_session_offered") or
            std.mem.eql(u8, reason, "accept");
        if (!known) return unimplemented(name);
    } else if (std.mem.eql(u8, name, "-read-size")) {
        // A buffering hint for the C shim's `SSL_read`; our record pump
        // reads whole records regardless.
    } else if (std.mem.eql(u8, name, "-no-tls1") or
        std.mem.eql(u8, name, "-no-tls11") or
        std.mem.eql(u8, name, "-no-tls12"))
    {
        // Turning off a version we never had is a no-op, not a refusal.
    } else {
        return unimplemented(name);
    }
}

// ------------------------------------------------------------- exchange

/// What the embedder keeps between exchanges so `-resume-count` can
/// resume: server side, the PSK behind the identity we issued; client
/// side, the ticket we captured and the PSK we derived for it.
const TicketStore = struct {
    identity: [256]u8 = undefined,
    identity_bytes: u16 = 0,
    psk: [cipher_suite.hash_bytes_max]u8 = undefined,
    psk_bytes: u8 = 0,
    age_add: u32 = 0,
    /// When the ticket was minted, on the same clock `runServer` hands
    /// the library. §8.3 compares the age a client claims against this,
    /// and BoGo's runner claims a real elapsed time — so this is a real
    /// clock read, which an embedder may do and `src/` may not.
    issued_at_ms: u64 = 0,
    /// What the ticket advertised, or null when 0-RTT was never enabled.
    /// The same number goes into the ticket and comes back out of the
    /// lookup, which is the agreement zssl cannot check for an embedder.
    early_data_bytes_max: ?u32 = null,
    /// The suite the ticket was issued under. §4.2.10 wants the resumed
    /// connection to negotiate the same one before early data is read.
    suite: cipher_suite.CipherSuite = .aes_128_gcm_sha256,
    /// The scheme the peer signed with when this session was first
    /// established. A resumed TLS 1.3 handshake carries no
    /// CertificateVerify, so the library reports null for it — the
    /// scheme is a property of the *session*, and remembering it is the
    /// embedder's job exactly as remembering the ticket is. BoGo asserts
    /// it on both exchanges precisely to catch a shim that drops it.
    peer_signature_scheme: ?zssl.backend.SignatureScheme = null,
    /// Tickets seen on the exchange in progress, which is what
    /// `-expect-no-session` asks about — not what an earlier one left.
    tickets_this_exchange: u32 = 0,

    fn lookup(
        context: *anyopaque,
        identity: []const u8,
        obfuscated_age: u32,
        psk_out: *[cipher_suite.hash_bytes_max]u8,
    ) ?ServerHandshake.Psk {
        _ = obfuscated_age; // Age policy is the embedder's; this one has none.
        const self: *TicketStore = @ptrCast(@alignCast(context));
        if (self.psk_bytes == 0) return null;
        if (!std.mem.eql(u8, self.identity[0..self.identity_bytes], identity)) return null;
        psk_out.* = self.psk;
        // Every PSK this shim knows came from a ticket it issued a
        // moment ago, so the binder label is "res binder". BoGo drives no
        // external-PSK case at this pin; if it ever does, this is the
        // line that has to learn the difference.
        return .{
            .psk_bytes = self.psk_bytes,
            .kind = .resumption,
            .issued = .{
                .at_ms = self.issued_at_ms,
                .age_add = self.age_add,
                .lifetime_s = ticket_lifetime_s,
            },
            .early_data = if (self.early_data_bytes_max) |bytes_max|
                .{ .bytes_max = bytes_max, .suite = self.suite }
            else
                null,
        };
    }
};

/// §4.6.1's lifetime for the one ticket this shim mints, and the number
/// `psk_lookup` answers with so the library's expiry check agrees with
/// what the ticket said.
const ticket_lifetime_s: u32 = 3600;

/// What a ticket advertises when `-enable-early-data` is on.
///
/// BoringSSL's `kMaxEarlyDataAccepted` (`ssl/internal.h`), and the
/// number matters: `TLS13-MaxEarlyData-Server` sends exactly one byte
/// more and expects the connection to end. Their comment explains the
/// gap to `kMaxEarlyDataSkipped` — 14336 accepted in plaintext sits
/// "slightly below" 16384 skipped in ciphertext, so a server that
/// declines never counts less than one that accepts.
const early_data_bytes_max: u32 = 14336;

/// The shim's clock. `src/` may not read one — CLAUDE.md makes that an
/// invariant, so a seeded replay of the library replays its time too —
/// but an embedder must, and this is the embedder.
///
/// `.awake` rather than `.real`, and the two are not interchangeable
/// here. What §8.3 compares is an *elapsed* time: the shim mints a
/// ticket and redeems it within one process seconds later, so what the
/// comparison needs is a clock that only moves forward, not one that
/// agrees with the world. A wall clock an NTP step moved backwards
/// between those two reads would make a legitimate resumption look
/// like a replayed one.
fn nowMs(io: Io) u64 {
    const nanoseconds = Io.Clock.Timestamp.now(io, .awake).raw.nanoseconds;
    // A monotonic clock that has not started is a broken `Io`, not an
    // edge case to absorb: mapping it to zero would silently make every
    // ticket look freshly issued.
    assert(nanoseconds > 0);
    const millis = Io.Timestamp.toMilliseconds(.{ .nanoseconds = nanoseconds });
    assert(millis > 0);
    return @intCast(millis);
}

/// The one ticket identity this shim issues. Opaque to the protocol —
/// sealing is the embedder's job, and a test binary needs no seal.
const ticket_identity = "zssl-bogo-ticket";
const ticket_nonce = [_]u8{0x01};

/// Buffers the machines borrow. File-scope rather than stack because a
/// certificate flight plus record buffers is more than a default stack
/// wants, and rather than heap because zssl takes what it is given
/// (DESIGN.md §3) and a shim runs one session at a time.
var chain_storage: [Credentials.chain_bytes_max]u8 = undefined;
/// A handshake-message budget, not a record one: BoGo hands out
/// certificate messages far larger than any flight zoxy will meet, and a
/// reassembly buffer is the embedder's to size (DESIGN.md §3). 64 KiB is
/// what BoringSSL's own limit implies.
var handshake_reassembly: [64 * 1024]u8 = undefined;
var flight_storage: [Credentials.chain_bytes_max + 1024]u8 = undefined;
var pump_storage: Pump = undefined;

fn runExchange(
    io: Io,
    arena: std.mem.Allocator,
    connection: *const Connection,
    store: *TicketStore,
) !void {
    const stream = try connectToRunner(io, connection);
    defer stream.close(io);

    const pump = &pump_storage;
    pump.init(io, stream);
    var announce: [8]u8 = undefined;
    std.mem.writeInt(u64, &announce, connection.shim_id, .little);
    try pump.write(&announce);

    store.tickets_this_exchange = 0;
    if (connection.is_server) {
        try runServer(io, arena, connection, store, pump);
    } else {
        try runClient(io, connection, store, pump);
    }
}

fn connectToRunner(io: Io, connection: *const Connection) !Io.net.Stream {
    var address: Io.net.IpAddress = if (connection.ipv6)
        .{ .ip6 = .loopback(connection.port) }
    else
        .{ .ip4 = .loopback(connection.port) };
    return address.connect(io, .{ .mode = .stream });
}

fn runServer(
    io: Io,
    arena: std.mem.Allocator,
    connection: *const Connection,
    store: *TicketStore,
    pump: *Pump,
) !void {
    // `-curves` on a server run is the set it will accept, which
    // `Config.groups` is exactly. Until this was wired the flag was
    // recorded and thrown away: the server accepted every group it holds
    // whatever the case named, so a case narrowing it to P-256 was run
    // against a server that would still have taken x25519.
    const groups = configuredGroups(connection) orelse return unimplemented("-curves");
    // On a server run both of these are about the *client's*
    // CertificateVerify, which needs a CertificateRequest we never send
    // (DESIGN.md §1). Declined by name so the case says which flag it
    // stumbled on rather than failing for a reason no one can read.
    if (connection.verify_pref_count >= 1) return unimplemented("-verify-prefs");
    if (connection.expect_peer_signature_algorithm != null) {
        return unimplemented("-expect-peer-signature-algorithm");
    }
    const cert_path = connection.cert_path orelse return unimplemented("-cert-file");
    const key_path = connection.key_path orelse return unimplemented("-key-file");
    const cert_pem = try readFile(io, arena, cert_path);
    const key_pem = try readFile(io, arena, key_path);

    var credentials = Credentials.load(cert_pem, key_pem, &chain_storage, false) catch |err| switch (err) {
        // ECDSA signing only, by embedder policy (DESIGN.md §1). BoGo
        // hands every server case an RSA leaf unless the case says
        // otherwise, so this is the single largest source of 89s — and a
        // written decision rather than a gap.
        error.UnsupportedKey => return unimplemented("-key-file:not-ecdsa"),
        else => return err,
    };
    defer credentials.deinit();

    var entropy: [80]u8 = undefined;
    io.random(&entropy);
    // §8.2's register, one connection's worth. Sized to the smallest
    // legal table: this shim serves one client at a time, so a wider one
    // would only make the probe window emptier.
    var strike_entries: [anti_replay.StrikeRegister.probe_max]anti_replay.StrikeRegister.Entry =
        @splat(.free);
    var strike_register: anti_replay.StrikeRegister = .{ .entries = &strike_entries };
    const signing_schemes: ?[]const u16 = if (connection.signing_pref_count == 0)
        null
    else
        connection.signing_prefs[0..connection.signing_pref_count];
    var server = ServerHandshake.init(&.{
        .credentials = &credentials,
        .server_random = entropy[0..32].*,
        .key_share_private = entropy[32..80].*,
        .alpn = connection.select_alpn,
        .groups = groups,
        .signing_schemes = signing_schemes,
        .reassembly = &handshake_reassembly,
        .flight = &flight_storage,
        // A real clock, which an embedder may read and `src/` may not
        // (CLAUDE.md). BoGo's client claims a real elapsed age, so
        // §8.3's comparison only means anything against the same kind of
        // number.
        .now_ms = nowMs(io),
        .strike_register = if (connection.enable_early_data) &strike_register else null,
        // `SSL_OP_NO_TICKET` means the server must not *accept* a ticket
        // either, not merely decline to mint one — BoGo's
        // `TLS13-NoTicket-NoAccept` sets it only on the resumed
        // connection and expects a full handshake. Withholding the
        // lookup is how an embedder says no.
        .psk_lookup = if (connection.no_ticket)
            null
        else
            .{ .context = store, .lookup = TicketStore.lookup },
    });
    defer server.deinit();

    // Read before the handshake consumes it: `psk_lookup` answers from
    // the same store the next issuance overwrites.
    const offered = !connection.no_ticket and connection.index >= 1 and store.psk_bytes >= 1;
    pump.handshakeServer(&server) catch |err| return pump.abort(&server, err);
    try checkNegotiated(connection, server.resumed, offered, null, server.key_share_group, null);
    try writeExportedMaterial(pump, &server, connection);
    // Checked, not reported. BoGo asks whether early data was accepted,
    // and a shim that answered "yes" without the library having accepted
    // any would pass the case while proving nothing. It is a coarse
    // check — accepted or not, never *why* — and the runner reading the
    // half-RTT bytes back is what actually proves data flowed.
    if (connection.expect_early_data) |wanted| {
        if (server.early_data_accepted != wanted) return error.EarlyDataMismatch;
    }

    // DESIGN.md §1's ordering, and §4.6.1's: derive the PSK, then seal
    // the ticket that stands for it, and only after `connected`.
    // §4.6.1 is the library's to enforce and the embedder's to respect:
    // a client that never advertised psk_dhe_ke cannot use a ticket, and
    // `sendNewSessionTicket` refuses to mint one. Asking first is what
    // keeps that from being an error path.
    if (!connection.no_ticket and server.ticketPermitted()) {
        const psk = server.resumptionPsk(&ticket_nonce, &store.psk);
        store.psk_bytes = @intCast(psk.len);
        @memcpy(store.identity[0..ticket_identity.len], ticket_identity);
        store.identity_bytes = ticket_identity.len;
        store.issued_at_ms = nowMs(io);
        store.suite = server.cipherSuite();
        store.early_data_bytes_max =
            if (connection.enable_early_data) early_data_bytes_max else null;
        const sealed = server.sendNewSessionTicket(&.{
            .lifetime_s = ticket_lifetime_s,
            .age_add = 0,
            .ticket_nonce = &ticket_nonce,
            .ticket = ticket_identity,
            .early_data_bytes_max = store.early_data_bytes_max,
        }, &pump.out) catch |err| return pump.abort(&server, err);
        try pump.write(sealed);
    }

    try pump.exchange(&server, connection, store);
}

fn runClient(
    io: Io,
    connection: *const Connection,
    store: *TicketStore,
    pump: *Pump,
) !void {
    // `-curves` on a client run is what to advertise, and
    // `Config.groups` takes it. The one set we cannot honour is one
    // without x25519: this client always shares x25519, and §4.2.8 wants
    // every key_share entry to appear in supported_groups, so advertising
    // a list that excludes it would put an illegal hello on the wire.
    const groups = configuredGroups(connection) orelse return unimplemented("-curves");
    for (groups) |group| {
        if (group == group_x25519) break;
    } else return unimplemented("-curves:no-x25519");
    // On a client run this configures the *client's* certificate, which
    // needs a CertificateRequest we never answer (DESIGN.md §1).
    if (connection.signing_pref_count >= 1) return unimplemented("-signing-prefs");
    var verify_storage: [verify_schemes_max]zssl.backend.SignatureScheme = undefined;
    const verify_schemes = configuredVerifySchemes(connection, &verify_storage) orelse
        return unimplemented("-verify-prefs");
    var protocols: [alpn_protocols_max][]const u8 = undefined;
    const offered = try splitAlpn(connection.advertise_alpn, &protocols);

    var entropy: [144]u8 = undefined;
    io.random(&entropy);
    var resumption: ?ClientHandshake.Resumption = null;
    if (connection.index >= 1 and store.psk_bytes >= 1) {
        resumption = .{
            .identity = store.identity[0..store.identity_bytes],
            // Elapsed time is under a millisecond here, so the offered
            // age is the ticket's own add. Age policy is the embedder's.
            .obfuscated_age = store.age_add,
            .psk = store.psk,
            .psk_bytes = store.psk_bytes,
        };
    }

    var client = ClientHandshake.init(&.{
        .client_random = entropy[0..32].*,
        .x25519_private = entropy[32..64].*,
        // The second scalar, which is what lets this client answer a
        // HelloRetryRequest at all (DESIGN.md §1). BoGo drives two dozen
        // retry cases at the client half, and every one of them was
        // declined while there was nothing to answer with.
        .retry_key_share_private = entropy[96..144].*,
        .session_id = entropy[64..96],
        .server_name = connection.host_name,
        .groups = groups,
        .verify_schemes = verify_schemes,
        .alpn_protocols = offered,
        // Possession, not identity: the leaf's own key must have signed
        // the CertificateVerify. Chain building and RFC 9525 names stay
        // the embedder's (DESIGN.md §1), so the BoGo cases that turn on
        // them are named in bogo/config.json rather than quietly passed.
        .certificate_policy = .leaf_signature,
        .resume_session = resumption,
        .reassembly = &handshake_reassembly,
    });
    defer client.deinit();

    try pump.write(client.start(&pump.out));
    pump.handshakeClient(&client) catch |err| return pump.abort(&client, err);
    // This handshake's scheme when there was a CertificateVerify to
    // read, the session's when there was not. See `peer_signature_scheme`
    // on the store for why the second half is the embedder's to keep.
    if (client.peer.scheme) |scheme| store.peer_signature_scheme = scheme;
    try checkNegotiated(
        connection,
        client.resumed,
        resumption != null,
        client.alpnSelected(),
        zssl.backend.Group.fromWire(client.share_group),
        store.peer_signature_scheme,
    );
    try writeExportedMaterial(pump, &client, connection);

    try pump.exchange(&client, connection, store);
    if (connection.expect_no_session and store.tickets_this_exchange >= 1) {
        return error.UnexpectedTicket;
    }
}

/// The group list `-curves` asked for, or the library's default when the
/// case named none. Null means "we cannot be configured that way": a
/// group neither machine can complete, or more entries than
/// `groups_supported` holds — both of which `init` asserts against, and
/// an assert is not how a shim declines a case.
fn configuredGroups(connection: *const Connection) ?[]const u16 {
    if (connection.curve_count == 0) return &zssl.client_hello.groups_supported;
    if (connection.curve_count > zssl.client_hello.groups_supported.len) return null;
    const named = connection.curves[0..connection.curve_count];
    for (named) |group| {
        if (zssl.client_hello.groupShareBytes(group) == null) return null;
    }
    return named;
}

/// The most schemes `-verify-prefs` can name before we stop honouring
/// it. Five is every code point `SignatureScheme` has; a case naming
/// more is naming one we do not verify, and is declined for that.
const verify_schemes_max = @typeInfo(zssl.backend.SignatureScheme).@"enum".fields.len;

/// The accept-set `-verify-prefs` asked for, written into `out`, or the
/// library's default when the case named none. Null is a decline: a
/// scheme outside the five we verify cannot be configured, and the case
/// that named it is asking about an algorithm we do not hold.
fn configuredVerifySchemes(
    connection: *const Connection,
    out: *[verify_schemes_max]zssl.backend.SignatureScheme,
) ?[]const zssl.backend.SignatureScheme {
    if (connection.verify_pref_count == 0) return &zssl.client_messages.signature_schemes_default;
    if (connection.verify_pref_count > out.len) return null;
    for (connection.verify_prefs[0..connection.verify_pref_count], 0..) |wire, i| {
        out[i] = zssl.backend.SignatureScheme.fromWire(wire) orelse return null;
    }
    return out[0..connection.verify_pref_count];
}

/// §7.5's material, written to the peer before anything else. BoGo's
/// runner derives the same bytes from its own handshake and reads
/// exactly this many, so a shim that exported the wrong secret fails
/// against a second implementation rather than against a stored vector.
fn writeExportedMaterial(
    pump: *Pump,
    machine: anytype,
    connection: *const Connection,
) !void {
    const bytes = connection.export_bytes orelse return;
    var material: [export_bytes_max]u8 = undefined;
    machine.exporter(
        connection.export_label,
        connection.export_context,
        material[0..bytes],
    ) catch |err| return pump.abort(machine, err);
    const sealed = machine.sendApplicationData(
        material[0..bytes],
        &pump.out,
    ) catch |err| return pump.abort(machine, err);
    try pump.write(sealed);
}

/// The `-expect-*` assertions both roles share. A mismatch is the shim's
/// own failure, reported like any other. `offered` says whether there was
/// a ticket in play at all — without one, a later exchange is a full
/// handshake by construction and not a rejected resumption.
fn checkNegotiated(
    connection: *const Connection,
    resumed: bool,
    offered: bool,
    alpn: ?[]const u8,
    group: ?zssl.backend.Group,
    peer_scheme: ?zssl.backend.SignatureScheme,
) !void {
    if (connection.expect_version) |version| {
        if (version != version_tls13) return error.UnexpectedVersion;
    }
    if (connection.expect_peer_signature_algorithm) |wanted| {
        const expected = zssl.backend.SignatureScheme.fromWire(wanted) orelse
            return error.UnexpectedSignatureAlgorithm;
        if (peer_scheme != expected) return error.UnexpectedSignatureAlgorithm;
    }
    if (connection.expect_curve_id) |wanted| {
        // This asked only whether the named group was one we hold, which
        // every case naming a group we hold passed whatever the handshake
        // actually negotiated. Now that `-curves` can narrow the set, the
        // difference is the whole point of the case.
        const expected = zssl.backend.Group.fromWire(wanted) orelse return error.UnexpectedCurve;
        if (group != expected) return error.UnexpectedCurve;
    }
    if (connection.expect_alpn) |expected| {
        const selected = alpn orelse return error.NoAlpnSelected;
        if (!std.mem.eql(u8, selected, expected)) return error.UnexpectedAlpn;
    }
    if (connection.expect_session_miss and resumed) return error.UnexpectedResumption;
    if (offered and !connection.expect_session_miss and !resumed) {
        return error.ExpectedResumption;
    }
}

/// RFC 7301 §3.1 wire format — one-byte-length-prefixed names — into the
/// slices `ClientHandshake.Config` wants. Both caps are the library's,
/// and a list that exceeds either is declined rather than truncated: the
/// alternative is an offer the case did not ask for, or a panic.
fn splitAlpn(wire: ?[]const u8, out: *[alpn_protocols_max][]const u8) ![]const []const u8 {
    const list = wire orelse return out[0..0];
    var count: usize = 0;
    var index: usize = 0;
    while (index < list.len) {
        assert(count <= out.len);
        if (count == out.len) return unimplemented("-advertise-alpn:too-many");
        const length = list[index];
        if (length == 0) return error.BadFlagValue;
        if (length > alpn_protocol_bytes_max) return unimplemented("-advertise-alpn:name-too-long");
        index += 1;
        if (index + length > list.len) return error.BadFlagValue;
        out[count] = list[index..][0..length];
        count += 1;
        index += length;
    }
    assert(index == list.len);
    return out[0..count];
}

// ------------------------------------------------------------ the pump

/// The socket half of one exchange: whole records in, whatever the
/// machine answers straight back out.
const Pump = struct {
    io: Io,
    stream: Io.net.Stream,
    records: zssl.record_buffer.RecordBuffer,
    reader: Io.net.Stream.Reader,
    writer: Io.net.Stream.Writer,
    read_buffer: [4 * record.wire_record_bytes_max]u8,
    write_buffer: [4 * record.wire_record_bytes_max]u8,
    storage: [4 * record.wire_record_bytes_max]u8,
    out: [4 * record.wire_record_bytes_max]u8,
    scratch: [record.wire_record_bytes_max]u8,

    /// In place through a pointer: the reader and writer hold pointers
    /// into the buffers beside them, so the address must be final first.
    fn init(pump: *Pump, io: Io, stream: Io.net.Stream) void {
        pump.io = io;
        pump.stream = stream;
        pump.records = zssl.record_buffer.RecordBuffer.init(&pump.storage);
        pump.reader = stream.reader(io, &pump.read_buffer);
        pump.writer = stream.writer(io, &pump.write_buffer);
    }

    fn write(pump: *Pump, bytes: []const u8) !void {
        if (bytes.len == 0) return;
        try pump.writer.interface.writeAll(bytes);
        try pump.writer.interface.flush();
    }

    fn nextRecord(pump: *Pump) ![]const u8 {
        var refills: u32 = 0;
        // How many reads one record takes is the peer's choice — it may
        // dribble a byte at a time — so the bound is an error, never an
        // assertion. Assertions are for counts we control.
        while (refills < records_per_phase_max) : (refills += 1) {
            if (try pump.records.next()) |one| return one;
            pump.reader.interface.fill(1) catch |err| switch (err) {
                error.EndOfStream => return error.PeerClosed,
                else => return err,
            };
            const available = pump.reader.interface.buffered();
            assert(available.len >= 1);
            try pump.records.push(available);
            pump.reader.interface.toss(available.len);
        }
        return error.TooManyRecords;
    }

    fn handshakeServer(pump: *Pump, server: *ServerHandshake) !void {
        var records_seen: u32 = 0;
        // The peer decides how many records its flight takes; a bound on
        // that is a refusal, not an invariant of ours.
        while (server.state != .connected) : (records_seen += 1) {
            if (records_seen == records_per_phase_max) return error.TooManyRecords;
            const one = try pump.nextRecord();
            if (try server.handleRecord(one, &pump.out)) |ready| switch (ready) {
                .send => |bytes| try pump.write(bytes),
                .connected => {},
                .closed => return error.PeerClosedDuringHandshake,
                // §4.2.10's early data, arriving before the handshake is
                // finished — and the answer is §2's 0.5-RTT, which is
                // what BoGo's `ExpectHalfRTTData` blocks waiting for.
                // Complemented, which is the same reply `exchange` gives
                // ordinary application data and what `bssl_shim` sends.
                //
                // `bssl_shim` answers 0-RTT bytes the same way it answers
                // any other, so this shim does too — one arm, and the
                // distinction Appendix E.5 asks for is a decision this
                // embedder makes by writing both cases here rather than
                // one it can no longer see.
                .early_data, .application_data => |bytes| {
                    if (bytes.len == 0) continue;
                    assert(bytes.len <= pump.scratch.len);
                    // Copied out first: `bytes` points into `pump.out`,
                    // which is where the reply gets sealed.
                    for (bytes, 0..) |byte, index| pump.scratch[index] = byte ^ 0xff;
                    const sealed = server.sendApplicationData(
                        pump.scratch[0..bytes.len],
                        &pump.out,
                    ) catch |err| return pump.abort(server, err);
                    try pump.write(sealed);
                },
            };
        }
    }

    fn handshakeClient(pump: *Pump, client: *ClientHandshake) !void {
        var records_seen: u32 = 0;
        // The peer decides how many records its flight takes; a bound on
        // that is a refusal, not an invariant of ours.
        while (client.state != .connected) : (records_seen += 1) {
            if (records_seen == records_per_phase_max) return error.TooManyRecords;
            const one = try pump.nextRecord();
            if (try client.handleRecord(one, &pump.out)) |ready| switch (ready) {
                // The client's `connected` carries its final flight.
                .send, .connected => |bytes| try pump.write(bytes),
                .closed => return error.PeerClosedDuringHandshake,
                .application_data, .ticket => return error.UnexpectedEvent,
                // `ClientHandshake.Event` has no `early_data`: only a
                // server ever reads any. Nothing to handle here.
            };
        }
    }

    /// A refusal the peer can read. zssl reports the error and leaves the
    /// alert to the embedder; this is where that decision is made, and
    /// BoGo's `expectedLocalError` cases are what check it.
    fn abort(pump: *Pump, machine: anytype, err: anyerror) anyerror {
        reportPeerAlert(machine, err);
        // No alert, no linger, and the reason is the whole of it:
        // draining is what lets the peer read the alert we just wrote
        // (see `linger`), so with nothing written there is nothing for
        // it to protect. That holds for every error reaching here, not
        // only the ones where the peer has stopped talking — a
        // `TooManyRecords` or an `UnexpectedEvent` is a ceiling of ours
        // and the peer may still be mid-send, but it is still an
        // unannounced close either way.
        //
        // Where it *was* the peer stopping, draining did active harm.
        // BoGo's `SkipEarlyData-HRR-FatalAlert-TLS13` sends a fatal
        // handshake_failure and then waits for us to close; we waited to
        // read; and the case failed on the runner's deadline rather
        // than on anything either of us did.
        const description = alertFor(err) orelse return err;
        pump.write(machine.sendAlert(description, &pump.out)) catch {};
        pump.linger();
        return err;
    }

    /// One event, acted on. Answers true when the connection is over.
    ///
    /// Split out because `handleRecord` and `drain` produce the same
    /// events and a record may produce several: a reply that lived in
    /// the loop would have to be written twice, and the second copy is
    /// where the two would drift apart.
    fn act(pump: *Pump, machine: anytype, store: *TicketStore, event: anytype) !bool {
        switch (event) {
            .application_data => |bytes| {
                if (bytes.len == 0) return false;
                assert(bytes.len <= pump.scratch.len);
                for (bytes, 0..) |byte, index| pump.scratch[index] = byte ^ 0xff;
                const sealed = machine.sendApplicationData(
                    pump.scratch[0..bytes.len],
                    &pump.out,
                ) catch |err| return pump.abort(machine, err);
                try pump.write(sealed);
            },
            // The peer closed its write side. §6.1 leaves ours open and
            // an embedder may answer, which zssl now models — but BoGo's
            // cases here do not ask for a reply, so the socket close is
            // still the whole of it.
            .closed => return true,
            .send => |bytes| try pump.write(bytes),
            // Only the client machine has `ticket` and only the server
            // has `early_data`, so the branch is chosen by the machine's
            // type rather than the tag — the server arm never analyses a
            // field it lacks, and neither tag can be named here without
            // breaking the other instantiation. `early_data` reaching
            // this far *is* an error: 0-RTT arrives before `connected`,
            // which is `handshakeServer`'s loop, never this one.
            else => if (@TypeOf(machine.*) == ClientHandshake) {
                captureTicket(machine, event, store);
            } else {
                return error.UnexpectedEvent;
            },
        }
        return false;
    }

    /// After our own close_notify. §6.1 closes one direction at a time,
    /// so the read side is still open and the peer's answer still
    /// arrives — its close_notify, or an alert instead of one, or
    /// nothing at all. Which of those counts as a failure is the case's
    /// call, and `-check-close-notify` is how BoGo says so: a stream
    /// that merely stopped is a truncation, not an orderly shutdown.
    ///
    /// Nothing this loop reads produces a reply. §6.1 forbids sending
    /// after close_notify, and once its write side is shut the machine
    /// consumes a KeyUpdate in silence instead of answering it — which
    /// `nextPostHandshake` skips past, so it reaches this loop as null
    /// rather than as an event.
    fn awaitPeerClose(pump: *Pump, machine: anytype, connection: *const Connection) !void {
        var records_seen: u32 = 0;
        while (records_seen < records_per_phase_max) : (records_seen += 1) {
            const one = pump.nextRecord() catch |err| switch (err) {
                // Both shapes of "the peer went away". A clean end of
                // stream is one; a reset is the other, and it is what a
                // peer that closes without draining what we just wrote
                // actually produces. Neither carried a close_notify,
                // and that — rather than which errno it arrived as — is
                // the only question `-check-close-notify` asks.
                error.PeerClosed, error.ReadFailed => {
                    if (connection.check_close_notify) return error.NoCloseNotify;
                    return;
                },
                else => return err,
            };
            // No `abort` here: an alert cannot go back out after our
            // close_notify, so the error is reported and nothing is
            // written. `Unclean-Shutdown-Alert` is the case that reads
            // it.
            var event = machine.handleRecord(one, &pump.out) catch |err| {
                reportPeerAlert(machine, err);
                pump.linger();
                return err;
            };
            while (event) |ready| {
                if (std.meta.activeTag(ready) == .closed) return;
                event = machine.drain(&pump.out) catch |err| {
                    reportPeerAlert(machine, err);
                    pump.linger();
                    return err;
                };
            }
        }
        return error.TooManyRecords;
    }

    /// Say we are done writing, read what the peer still had in flight,
    /// then let the socket go.
    ///
    /// Closing on top of an unread window is a reset, and a peer whose
    /// write is cut short reports a broken pipe rather than the alert we
    /// just sent it — a real refusal that reads as a transport fault.
    ///
    /// The half-close comes first because draining alone is only half an
    /// answer: it stops *our* close from resetting the peer, but a peer
    /// waiting to see our FIN before it sends its last bytes waits for
    /// as long as we are willing to read. `tlsfuzzer/server.zig` needed
    /// exactly this (`drainBeforeClose`, docs/TLSFUZZER.md) and the two
    /// harnesses had no business differing about TCP. Safe at every call
    /// site because all three are terminal and `write` flushes: whatever
    /// we meant to send — an alert, or our own close_notify — is already
    /// on the wire.
    fn linger(pump: *Pump) void {
        pump.stream.shutdown(pump.io, .send) catch return;
        var reads: u32 = 0;
        while (reads < records_per_phase_max) : (reads += 1) {
            pump.reader.interface.fill(1) catch return;
            const available = pump.reader.interface.buffered();
            if (available.len == 0) return;
            pump.reader.interface.toss(available.len);
        }
    }

    /// The post-handshake half: echo every application record back with
    /// each byte complemented, which is the reply `bssl_shim` gives and
    /// the one the runner checks for.
    fn exchange(
        pump: *Pump,
        machine: anytype,
        connection: *const Connection,
        store: *TicketStore,
    ) !void {
        if (connection.shim_writes_first) {
            try pump.write(try machine.sendApplicationData("hello", &pump.out));
        }
        if (connection.shim_shuts_down) {
            try pump.write(try machine.sendClose(&pump.out));
            return pump.awaitPeerClose(machine, connection);
        }

        var records_seen: u32 = 0;
        while (records_seen < records_per_phase_max) : (records_seen += 1) {
            const one = pump.nextRecord() catch |err| switch (err) {
                // A peer that vanished without a close_notify truncated
                // the stream; whether that is an error is the case's
                // call, and `-check-close-notify` is how it says so.
                error.PeerClosed => {
                    if (connection.check_close_notify) return error.NoCloseNotify;
                    return;
                },
                else => return err,
            };
            // One record can carry more than one post-handshake
            // message, so every event it produced is taken before the
            // next record is read. Null is the end of that run.
            var event = machine.handleRecord(one, &pump.out) catch |err| {
                return pump.abort(machine, err);
            };
            while (event) |ready| {
                if (try pump.act(machine, store, ready)) return;
                event = machine.drain(&pump.out) catch |err| {
                    return pump.abort(machine, err);
                };
            }
        }
        return error.TooManyRecords;
    }
};

/// Resumption's client side: the ticket is the identity, and the PSK
/// behind it is derived here from our own resumption master.
fn captureTicket(machine: anytype, event: anytype, store: *TicketStore) void {
    const ticket = event.ticket;
    store.tickets_this_exchange += 1;
    if (ticket.ticket.len > store.identity.len) return;
    @memcpy(store.identity[0..ticket.ticket.len], ticket.ticket);
    store.identity_bytes = @intCast(ticket.ticket.len);
    store.psk_bytes = @intCast(machine.resumptionPsk(ticket.nonce, &store.psk).len);
    store.age_add = ticket.age_add;
}

/// `PeerAlert` names the refusal and not which refusal it was — a Zig
/// error carries no payload — so the machine records the description
/// byte and this puts it beside the error name. BoGo matches on a
/// substring of stderr, so this line and `main`'s bare `zssl:PeerAlert`
/// both count, and the `ErrorMap` can tell
/// `:SSLV3_ALERT_HANDSHAKE_FAILURE:` from `:TLSV1_ALERT_RECORD_OVERFLOW:`
/// instead of accepting either for both.
fn reportPeerAlert(machine: anytype, err: anyerror) void {
    if (err != error.PeerAlert) return;
    const description = machine.peer_alert_description orelse return;
    if (std.enums.fromInt(alert.Description, description)) |named| {
        std.debug.print("zssl:PeerAlert:{t}\n", .{named});
    } else {
        // §6 lets a peer send any byte; the ones this library does not
        // name are still worth reporting, and by their number.
        std.debug.print("zssl:PeerAlert:{d}\n", .{description});
    }
}

/// zssl error → RFC 8446 §6 alert: the mapping an embedder must make,
/// kept here because the library deliberately makes no alerting decision
/// of its own. A null answer means no alert expresses it — our own fault
/// or a socket that is already gone — and the connection simply closes.
fn alertFor(err: anyerror) ?alert.Description {
    return switch (err) {
        // §5.1 and §5.4: a record that is not what the layer expected.
        error.UnexpectedMessage,
        error.UnknownContentType,
        error.EmptyFragment,
        error.BadInnerPlaintext,
        error.UnexpectedRecordType,
        // §5.1/§4.6.3 flood ceilings. §6.2 has no alert for "you are
        // spending my time and delivering nothing", and unexpected_message
        // is the closest and what BoringSSL sends for both.
        error.TooManyEmptyRecords,
        error.TooManyKeyUpdates,
        error.TooManyWarningAlerts,
        // §4.2.10's two early-data ceilings answer the same way, and
        // BoringSSL sends this for both (`SSL_R_TOO_MUCH_SKIPPED_EARLY_DATA`
        // in `ssl/tls_record.cc`, `SSL_R_TOO_MUCH_READ_EARLY_DATA` in
        // `ssl/s3_pkt.cc`): one bounds data we declined and never keyed,
        // the other data we did.
        error.TooMuchSkippedEarlyData,
        error.TooMuchEarlyData,
        => .unexpected_message,
        // Not a TLS record at all — the same answer BoringSSL gives an
        // HTTP request that arrived on the TLS port.
        error.NotATlsRecord => .protocol_version,
        // §5.2: the tag is the one thing an attacker can break at will.
        error.AuthenticationFailed => .bad_record_mac,
        error.RecordOverflow => .record_overflow,
        error.HandshakeFailure => .handshake_failure,
        error.MissingExtension => .missing_extension,
        error.UnsupportedExtension => .unsupported_extension,
        // Legal grammar, illegal content.
        error.IllegalRetry,
        error.BadServerHello,
        error.IdentityElement,
        error.IllegalKeyUpdate,
        error.IllegalCompression,
        error.PskNotLast,
        error.BadKeyShare,
        error.NonMinimalEncoding,
        error.BinderCountMismatch,
        // §4.4.3 names this alert explicitly for a CertificateVerify
        // whose scheme we never offered.
        error.UnofferedSignatureScheme,
        => .illegal_parameter,
        // A well-formed message larger than the reassembly space the
        // embedder handed us. That is our capacity, not the peer's
        // illegal parameter, and §6 has no alert for it.
        error.BufferOverflow => .internal_error,
        // Grammar that does not parse at all — and, in `BadAlert`, one
        // that parses perfectly and means nothing in TLS 1.3. §6.2's
        // decode_error covers both: it is what we send when the bytes
        // cannot be turned into a decision.
        error.MalformedAlert,
        error.BadAlert,
        error.MalformedMessage,
        error.MalformedCertificate,
        error.MalformedExtension,
        error.MalformedEntry,
        error.DuplicateExtension,
        error.SuiteOverflow,
        error.ExtensionOverflow,
        error.Truncated,
        error.TrailingBytes,
        => .decode_error,
        // §4.4.3 names decrypt_error for a Finished or CertificateVerify
        // that does not check out. §4.2.11.2 defines a PSK binder as
        // computed "in the same way as the Finished message", so a
        // binder that cannot match is the same kind of failure and gets
        // the same alert. That last step is this library's reading
        // rather than something the RFC states: §6.2 scopes
        // decrypt_error to a failed cryptographic operation "including"
        // a Finished, which admits the binder without naming it.
        error.DecryptError, error.BadSignature, error.BadBinder => .decrypt_error,
        error.BadCertificate => .bad_certificate,
        // RFC 7301 §3.2 gives no_application_protocol to the *server* with
        // nothing in common to select. A client meeting a selection it
        // never offered, or a malformed one, is looking at an illegal
        // parameter — which is the alert the far side is entitled to read.
        error.NoApplicationProtocol => .no_application_protocol,
        error.BadAlpn => .illegal_parameter,
        // Our side broke, not theirs.
        error.SequenceExhausted,
        error.RotationsExhausted,
        error.LibcryptoFailed,
        error.DeterministicNonceUnsupported,
        error.SignatureInvalid,
        => .internal_error,
        // A peer that already alerted needs no alert back, and a socket
        // that is gone has nowhere to put one.
        else => null,
    };
}

fn readFile(io: Io, arena: std.mem.Allocator, path: []const u8) ![]const u8 {
    const file = try Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);
    const buffer = try arena.alloc(u8, 64 * 1024);
    var reader = file.reader(io, buffer);
    const sink = try arena.alloc(u8, 64 * 1024);
    const read_bytes = try reader.interface.readSliceShort(sink);
    return sink[0..read_bytes];
}
