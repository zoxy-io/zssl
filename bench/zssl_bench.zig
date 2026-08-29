//! zssl's half of the rustls comparison: the same scenario classes the
//! Rust harness in `bench/rustls-bench` runs, measured the same way.
//!
//! Everything here is in-process and in-memory. There is no socket, no
//! thread and no I/O in any measured region — both peers are driven by
//! handing one side's output buffer to the other's `handleRecord`, which
//! is what a sans-I/O library makes cheap and what makes the comparison
//! against rustls's own buffer-driven connections apples to apples.
//!
//! Results go to stdout as one JSON object per line, so `bench/compare.py`
//! can read this harness and the Rust one with the same parser.

const std = @import("std");
const assert = std.debug.assert;

const zssl = @import("zssl");
const ClientHandshake = zssl.ClientHandshake;
const Credentials = zssl.Credentials;
const ServerHandshake = zssl.ServerHandshake;
const backend = zssl.backend;
const cipher_suite = zssl.cipher_suite;
const protect = zssl.protect;
const record = zssl.record;
const CipherSuite = cipher_suite.CipherSuite;

// The fixtures are the tree's throwaway self-signed material, reached
// through build.zig's anonymous imports rather than copied: a hand-copied
// PEM is how a benchmark starts measuring a key the library dropped.
const cert_pem = @embedFile("cert_pem");
const key_pem = @embedFile("key_pem");

const client_x25519_private = [_]u8{0x31} ** 31 ++ [_]u8{0x07};
const server_key_share_private = [_]u8{0x93} ** 47 ++ [_]u8{0x0e};

// ---------------------------------------------------------------------
// Timing
// ---------------------------------------------------------------------

/// `rounds` independent rounds per scenario. The report carries the
/// fastest and the median round: a laptop produces a long right tail
/// whatever its governor says, the fastest round is the one least
/// contaminated by it, and the median says how wide the tail is.
const rounds: usize = 15;

const Sample = struct {
    name: []const u8,
    unit: []const u8,
    best_ns: f64,
    median_ns: f64,
    /// Plaintext bytes moved per operation; zero for scenarios counted
    /// in operations rather than throughput.
    bytes_per_op: u64,
    iterations: usize,
};

/// One line of JSON, written straight to fd 1. `std.Io.File.writer`
/// wants an `Io` instance, and a benchmark that prints eleven lines has
/// no business standing up an event loop to do it.
fn report(sample: Sample) void {
    var buffer: [512]u8 = undefined;
    const line = std.fmt.bufPrint(
        &buffer,
        "{{\"impl\":\"zssl\",\"name\":\"{s}\",\"unit\":\"{s}\"," ++
            "\"best_ns\":{d:.3},\"median_ns\":{d:.3}," ++
            "\"bytes_per_op\":{d},\"iterations\":{d}}}\n",
        .{
            sample.name,
            sample.unit,
            sample.best_ns,
            sample.median_ns,
            sample.bytes_per_op,
            sample.iterations,
        },
    ) catch @panic("bufPrint");
    var written: usize = 0;
    while (written < line.len) {
        const chunk = std.c.write(std.c.STDOUT_FILENO, line[written..].ptr, line.len - written);
        if (chunk <= 0) @panic("stdout");
        written += @intCast(chunk);
    }
}

fn lessThan(_: void, a: f64, b: f64) bool {
    return a < b;
}

/// Scenario selection, through `ZSSL_BENCH_ONLY` as a comma-separated
/// list; unset runs everything. This exists for the profiler: callgrind
/// is a ~50x slowdown, and a full run under it is an afternoon. The
/// environment rather than argv because Zig 0.16 retired `std.os.argv`
/// and the alternative reaches for an allocator this tree does not carry.
fn selected(name: []const u8) bool {
    const raw = std.c.getenv("ZSSL_BENCH_ONLY") orelse return true;
    var wanted = std.mem.tokenizeScalar(u8, std.mem.span(raw), ',');
    while (wanted.next()) |one| {
        if (std.mem.eql(u8, one, name)) return true;
    }
    return false;
}

/// The iteration count, scaled down by `ZSSL_BENCH_SCALE` when set. A
/// profiled run wants a hundredth of the work and the same code path.
fn scaled(iterations: usize) usize {
    const raw = std.c.getenv("ZSSL_BENCH_SCALE") orelse return iterations;
    const divisor = std.fmt.parseInt(usize, std.mem.span(raw), 10) catch return iterations;
    if (divisor == 0) return iterations;
    return @max(1, iterations / divisor);
}

/// `CLOCK_MONOTONIC` through libc, which the module already links.
/// Zig 0.16 retired `std.time.Timer` in favour of the `std.Io` clock, and
/// standing up an event loop to read a stopwatch is more machinery than a
/// benchmark loop should carry.
fn nanoTime() u64 {
    var now: std.c.timespec = undefined;
    if (std.c.clock_gettime(.MONOTONIC, &now) != 0) @panic("clock_gettime");
    const seconds: u64 = @intCast(now.sec);
    const nanoseconds: u64 = @intCast(now.nsec);
    return seconds * std.time.ns_per_s + nanoseconds;
}

/// Run `body` for `rounds` rounds of `iterations` each and report. The
/// value `body` returns is fed to `doNotOptimizeAway`, so a scenario
/// whose result nobody reads is not optimised into nothing.
fn measure(
    name: []const u8,
    unit: []const u8,
    bytes_per_op: u64,
    requested: usize,
    context: anytype,
    comptime body: fn (@TypeOf(context), usize) anyerror!u64,
) !void {
    if (!selected(name)) return;
    const iterations = scaled(requested);
    assert(iterations >= 1);
    // Warm up: the first touch pays for page faults, EVP table lookups
    // and a cold predictor, none of which the steady state pays again.
    var warm = try body(context, @max(1, iterations / 4));
    std.mem.doNotOptimizeAway(&warm);

    var per_round: [rounds]f64 = undefined;
    for (&per_round) |*slot| {
        const started = nanoTime();
        var sink = try body(context, iterations);
        const elapsed = nanoTime() - started;
        std.mem.doNotOptimizeAway(&sink);
        slot.* = @as(f64, @floatFromInt(elapsed)) / @as(f64, @floatFromInt(iterations));
    }
    var sorted = per_round;
    std.mem.sort(f64, &sorted, {}, lessThan);
    report(.{
        .name = name,
        .unit = unit,
        .best_ns = sorted[0],
        .median_ns = sorted[rounds / 2],
        .bytes_per_op = bytes_per_op,
        .iterations = iterations,
    });
}

// ---------------------------------------------------------------------
// Handshake — the production client against the production server
// ---------------------------------------------------------------------

const Buffers = struct {
    client_out: [2 * record.wire_record_bytes_max]u8 = undefined,
    server_out: [2 * record.wire_record_bytes_max]u8 = undefined,
    scratch: [2 * record.wire_record_bytes_max]u8 = undefined,
    reply: [2 * record.wire_record_bytes_max]u8 = undefined,
};

const TicketStore = struct {
    identity: [64]u8 = undefined,
    identity_bytes: u8 = 0,
    psk: [cipher_suite.hash_bytes_max]u8 = undefined,

    fn lookup(
        context: *anyopaque,
        identity: []const u8,
        obfuscated_age: u32,
        psk_out: *[cipher_suite.hash_bytes_max]u8,
    ) ?ServerHandshake.Psk {
        _ = obfuscated_age;
        const store: *TicketStore = @ptrCast(@alignCast(context));
        if (!std.mem.eql(u8, store.identity[0..store.identity_bytes], identity)) return null;
        psk_out.* = store.psk;
        return .{ .psk_bytes = 32, .kind = .resumption };
    }
};

const Pair = struct {
    server: ServerHandshake,
    client: ClientHandshake,
    server_reassembly: [8192]u8 = undefined,
    flight: [Credentials.chain_bytes_max + 1024]u8 = undefined,
    client_reassembly: [16384]u8 = undefined,

    fn init(
        pair: *Pair,
        credentials: *const Credentials,
        store: ?*TicketStore,
        resume_session: ?ClientHandshake.Resumption,
    ) void {
        pair.server = ServerHandshake.init(&.{
            .credentials = credentials,
            .server_random = .{0x6d} ** 32,
            .key_share_private = server_key_share_private,
            .alpn = "http/1.1",
            .reassembly = &pair.server_reassembly,
            .flight = &pair.flight,
            .psk_lookup = if (store) |context| .{
                .context = context,
                .lookup = TicketStore.lookup,
            } else null,
        });
        pair.client = ClientHandshake.init(&.{
            .client_random = .{0x1a} ** 32,
            .x25519_private = client_x25519_private,
            .session_id = &(.{0x44} ** 32),
            .server_name = "spike.zoxy.test",
            .alpn_protocols = &.{"http/1.1"},
            .certificate_policy = .leaf_signature,
            .resume_session = resume_session,
            .reassembly = &pair.client_reassembly,
        });
    }

    fn deinit(pair: *Pair) void {
        pair.client.deinit();
        pair.server.deinit();
    }

    /// Drive to `connected` on both machines. No HelloRetryRequest: the
    /// server accepts x25519, which is the share the client leads with.
    fn connect(pair: *Pair, buffers: *Buffers) !void {
        const hello = pair.client.start(&buffers.client_out);
        const flight = (try pair.server.handleRecord(hello, &buffers.server_out)) orelse
            return error.NoFlight;
        if (flight != .send) return error.NoFlight;

        var reply_bytes: usize = 0;
        var index: usize = 0;
        while (index < flight.send.len) {
            const one = recordAt(flight.send, index);
            if (try pair.client.handleRecord(one, &buffers.scratch)) |event| switch (event) {
                .connected => |bytes| {
                    @memcpy(buffers.reply[0..bytes.len], bytes);
                    reply_bytes = bytes.len;
                },
                else => return error.UnexpectedEvent,
            };
            index += one.len;
        }
        if (reply_bytes == 0) return error.NoClientFlight;

        index = 0;
        var final: ?ServerHandshake.Event = null;
        while (index < reply_bytes) {
            const one = recordAt(buffers.reply[0..reply_bytes], index);
            if (try pair.server.handleRecord(one, &buffers.server_out)) |event| final = event;
            index += one.len;
        }
        if (final == null or final.? != .connected) return error.ServerNotConnected;
        assert(pair.client.state == .connected);
        assert(pair.server.state == .connected);
    }
};

fn recordAt(bytes: []const u8, index: usize) []const u8 {
    const length = std.mem.readInt(u16, bytes[index + 3 ..][0..2], .big);
    return bytes[index..][0 .. record.header_bytes + length];
}

// A `Pair` is ~40 KiB; file scope is where it lives rather than a loop
// body's stack frame.
var pair_storage: Pair = undefined;
var buffers_storage: Buffers = .{};

const HandshakeContext = struct {
    credentials: *const Credentials,
    store: ?*TicketStore,
    resumption: ?ClientHandshake.Resumption,
};

fn handshakeBody(context: HandshakeContext, iterations: usize) anyerror!u64 {
    var accumulator: u64 = 0;
    for (0..iterations) |_| {
        pair_storage.init(context.credentials, context.store, context.resumption);
        try pair_storage.connect(&buffers_storage);
        accumulator +%= @intFromEnum(pair_storage.server.cipherSuite());
        pair_storage.deinit();
    }
    return accumulator;
}

// The four flights a full handshake is made of, timed separately inside
// one iteration. Reading the clock four times per handshake costs four
// vDSO calls against phases measured in tens of microseconds, which is
// noise the fourth decimal place would not show.
const phase_count = 4;
const phase_names = [phase_count][]const u8{
    "phase_client_hello",
    "phase_server_flight",
    "phase_client_finish",
    "phase_server_finish",
};
var phase_totals: [phase_count]u64 = .{0} ** phase_count;

fn handshakePhases(credentials: *const Credentials, buffers: *Buffers) !void {
    pair_storage.init(credentials, null, null);
    defer pair_storage.deinit();

    const start_hello = nanoTime();
    const hello = pair_storage.client.start(&buffers.client_out);
    const start_flight = nanoTime();

    const flight = (try pair_storage.server.handleRecord(hello, &buffers.server_out)) orelse
        return error.NoFlight;
    if (flight != .send) return error.NoFlight;
    const start_client_finish = nanoTime();

    var reply_bytes: usize = 0;
    var index: usize = 0;
    while (index < flight.send.len) {
        const one = recordAt(flight.send, index);
        if (try pair_storage.client.handleRecord(one, &buffers.scratch)) |event| switch (event) {
            .connected => |bytes| {
                @memcpy(buffers.reply[0..bytes.len], bytes);
                reply_bytes = bytes.len;
            },
            else => return error.UnexpectedEvent,
        };
        index += one.len;
    }
    if (reply_bytes == 0) return error.NoClientFlight;
    const start_server_finish = nanoTime();

    index = 0;
    var final: ?ServerHandshake.Event = null;
    while (index < reply_bytes) {
        const one = recordAt(buffers.reply[0..reply_bytes], index);
        if (try pair_storage.server.handleRecord(one, &buffers.server_out)) |event| final = event;
        index += one.len;
    }
    if (final == null or final.? != .connected) return error.ServerNotConnected;
    const done = nanoTime();

    phase_totals[0] += start_flight - start_hello;
    phase_totals[1] += start_client_finish - start_flight;
    phase_totals[2] += start_server_finish - start_client_finish;
    phase_totals[3] += done - start_server_finish;
}

/// The phase breakdown, run through the same rounds-and-median discipline
/// as `measure` but reporting four numbers per round instead of one.
fn measurePhases(credentials: *const Credentials, requested: usize) !void {
    if (!selected("phases")) return;
    const iterations = scaled(requested);
    for (0..@max(1, iterations / 4)) |_| try handshakePhases(credentials, &buffers_storage);

    var per_round: [phase_count][rounds]f64 = undefined;
    for (0..rounds) |round| {
        phase_totals = .{0} ** phase_count;
        for (0..iterations) |_| try handshakePhases(credentials, &buffers_storage);
        for (0..phase_count) |phase| {
            per_round[phase][round] = @as(f64, @floatFromInt(phase_totals[phase])) /
                @as(f64, @floatFromInt(iterations));
        }
    }
    for (0..phase_count) |phase| {
        var sorted = per_round[phase];
        std.mem.sort(f64, &sorted, {}, lessThan);
        report(.{
            .name = phase_names[phase],
            .unit = "flight",
            .best_ns = sorted[0],
            .median_ns = sorted[rounds / 2],
            .bytes_per_op = 0,
            .iterations = iterations,
        });
    }
}

/// Establish one session, take a ticket off it, and hand back what a
/// resumed session needs on both sides.
fn captureTicket(
    credentials: *const Credentials,
    store: *TicketStore,
    buffers: *Buffers,
) !ClientHandshake.Resumption {
    pair_storage.init(credentials, null, null);
    defer pair_storage.deinit();
    try pair_storage.connect(buffers);

    var psk_buffer: [cipher_suite.hash_bytes_max]u8 = undefined;
    const server_psk = pair_storage.server.resumptionPsk(&.{0x0a}, &psk_buffer);
    @memset(&store.psk, 0);
    @memcpy(store.psk[0..server_psk.len], server_psk);
    @memcpy(store.identity[0..13], "sealed-by-us!");
    store.identity_bytes = 13;

    const sealed = try pair_storage.server.sendNewSessionTicket(&.{
        .lifetime_s = 3600,
        .age_add = 0x5eed,
        .ticket_nonce = &.{0x0a},
        .ticket = "sealed-by-us!",
    }, &buffers.server_out);
    const ticket_event = (try pair_storage.client.handleRecord(sealed, &buffers.scratch)) orelse
        return error.NoTicket;
    if (ticket_event != .ticket) return error.NoTicket;

    var resumption: ClientHandshake.Resumption = .{
        .identity = "sealed-by-us!",
        .obfuscated_age = ticket_event.ticket.age_add,
        .psk = undefined,
        .psk_bytes = 32,
    };
    var client_psk_buffer: [cipher_suite.hash_bytes_max]u8 = undefined;
    const client_psk = pair_storage.client.resumptionPsk(ticket_event.ticket.nonce, &client_psk_buffer);
    @memset(&resumption.psk, 0);
    @memcpy(resumption.psk[0..client_psk.len], client_psk);
    return resumption;
}

// ---------------------------------------------------------------------
// Bulk transfer
// ---------------------------------------------------------------------

/// One full 16 KiB record's worth of plaintext: the largest §5.1 allows,
/// and what any sender moving bulk data emits.
const chunk_bytes: usize = record.plaintext_bytes_max;

var plaintext_storage: [chunk_bytes]u8 = undefined;
var wire_storage: [record.wire_record_bytes_max]u8 = undefined;
var opened_storage: [record.inner_plaintext_bytes_max]u8 = undefined;

/// The full application-data path: `sendApplicationData` on the server,
/// `handleRecord` on the client. State machine, sequence bookkeeping,
/// content-type stripping and the AEAD — what a caller actually pays.
fn transferBody(_: void, iterations: usize) anyerror!u64 {
    var accumulator: u64 = 0;
    for (0..iterations) |_| {
        const wire = try pair_storage.server.sendApplicationData(
            plaintext_storage[0..chunk_bytes],
            &buffers_storage.server_out,
        );
        const event = (try pair_storage.client.handleRecord(wire, &buffers_storage.scratch)) orelse
            return error.NoData;
        if (event != .application_data) return error.NoData;
        accumulator +%= event.application_data.len;
    }
    return accumulator;
}

const ProtectorPair = struct {
    sealer: protect.Protector,
    opener: protect.Protector,
};

var protector_storage: ProtectorPair = undefined;

/// The record layer alone: seal one 16 KiB record and open it again,
/// with no handshake state machine above. The ceiling `transfer_*` sits
/// under, and the line that isolates the AEAD from everything else.
fn recordBody(_: void, iterations: usize) anyerror!u64 {
    var accumulator: u64 = 0;
    for (0..iterations) |_| {
        const wire = try protector_storage.sealer.seal(
            .application_data,
            plaintext_storage[0..chunk_bytes],
            &wire_storage,
        );
        const opened = try protector_storage.opener.open(wire, &opened_storage);
        accumulator +%= opened.plaintext_bytes;
    }
    return accumulator;
}

fn resetProtectors(suite: CipherSuite) !void {
    const key = [_]u8{0xab} ** cipher_suite.key_bytes_max;
    const static_iv = [_]u8{0xcd} ** cipher_suite.nonce_bytes;
    protector_storage.sealer = try protect.Protector.init(suite, key[0..suite.keyBytes()], &static_iv);
    protector_storage.opener = try protect.Protector.init(suite, key[0..suite.keyBytes()], &static_iv);
}

// ---------------------------------------------------------------------
// Primitives — the libcrypto floor under everything above
// ---------------------------------------------------------------------

var aead_storage: backend.AeadKey = undefined;
var aead_scratch: [chunk_bytes]u8 = undefined;

fn aeadSealBody(_: void, iterations: usize) anyerror!u64 {
    var accumulator: u64 = 0;
    const nonce = [_]u8{0x11} ** cipher_suite.nonce_bytes;
    const aad = [_]u8{ 0x17, 0x03, 0x03, 0x40, 0x11 };
    var tag: [cipher_suite.tag_bytes]u8 = undefined;
    for (0..iterations) |_| {
        try aead_storage.seal(
            &nonce,
            &aad,
            plaintext_storage[0..chunk_bytes],
            aead_scratch[0..chunk_bytes],
            &tag,
        );
        accumulator +%= tag[0];
    }
    return accumulator;
}

/// Standing up one traffic key and tearing it down again. A TLS 1.3
/// handshake does this eight times — handshake and application keys, both
/// directions, both peers — and `AeadKey.init` reaches
/// `EVP_EncryptInit_ex` with the static `EVP_aes_128_gcm()`, which under
/// OpenSSL 3 is an *implicit* provider fetch rather than a table lookup.
/// This line is here to say what that costs.
fn aeadInitBody(suite: CipherSuite, iterations: usize) anyerror!u64 {
    var accumulator: u64 = 0;
    const key = [_]u8{0xab} ** cipher_suite.key_bytes_max;
    for (0..iterations) |_| {
        var aead = try backend.AeadKey.init(suite, key[0..suite.keyBytes()]);
        accumulator +%= aead.key_bytes;
        aead.deinit();
    }
    return accumulator;
}

var signer_storage: backend.Signer = undefined;
var signature_storage: [backend.signature_bytes_max]u8 = undefined;

const sign_content = [_]u8{0x20} ** 130;

fn signBody(_: void, iterations: usize) anyerror!u64 {
    var accumulator: u64 = 0;
    for (0..iterations) |_| {
        const signature = try signer_storage.sign(
            .ecdsa_secp256r1_sha256,
            &sign_content,
            &signature_storage,
        );
        accumulator +%= signature.len;
    }
    return accumulator;
}

fn verifyBody(signature_bytes: usize, iterations: usize) anyerror!u64 {
    for (0..iterations) |_| {
        try signer_storage.verify(
            .ecdsa_secp256r1_sha256,
            &sign_content,
            signature_storage[0..signature_bytes],
        );
    }
    return signature_bytes;
}

/// One peer's whole key-exchange cost: build the share it puts on the
/// wire, then agree against the other side's. This is the pairing
/// rustls's `x25519_keygen_agree` measures, and it is what a handshake
/// pays per peer.
fn x25519Body(peer: *const [32]u8, iterations: usize) anyerror!u64 {
    var accumulator: u64 = 0;
    var shared: [32]u8 = undefined;
    for (0..iterations) |_| {
        var share = try backend.KeyShare.init(.x25519, &client_x25519_private);
        _ = try share.agree(peer, &shared);
        accumulator +%= shared[0];
        share.deinit();
    }
    return accumulator;
}

/// The two halves of the above, separately, because a handshake pays them
/// at different moments: `KeyShare.init` when the ClientHello goes out,
/// `agree` three flights later when the peer's share arrives. They are
/// not the same scalar multiplication — OpenSSL routes the fixed-base one
/// through the C `ge_scalarmult_base` and only the variable-base one
/// through `x25519-x86_64.s`.
fn x25519PublicBody(_: void, iterations: usize) anyerror!u64 {
    var accumulator: u64 = 0;
    for (0..iterations) |_| {
        var share = try backend.KeyShare.init(.x25519, &client_x25519_private);
        accumulator +%= share.publicValue()[0];
        share.deinit();
    }
    return accumulator;
}

var agree_share: backend.KeyShare = undefined;

fn x25519SharedBody(peer: *const [32]u8, iterations: usize) anyerror!u64 {
    var accumulator: u64 = 0;
    var shared: [32]u8 = undefined;
    for (0..iterations) |_| {
        _ = try agree_share.agree(peer, &shared);
        accumulator +%= shared[0];
    }
    return accumulator;
}

/// What `agree` cost before it was handed the public half: the same
/// agreement through `x25519Shared`, which builds its key object with
/// `EVP_PKEY_new_raw_private_key` and so pays a fixed-base scalar
/// multiplication it discards. Kept as a standing row because it is the
/// measurement the `KeyShare` bundle rests on.
fn x25519SharedDeriveBody(peer: *const [32]u8, iterations: usize) anyerror!u64 {
    var accumulator: u64 = 0;
    var shared: [32]u8 = undefined;
    for (0..iterations) |_| {
        try backend.x25519Shared(&client_x25519_private, peer, &shared);
        accumulator +%= shared[0];
    }
    return accumulator;
}

/// The retired baseline: what a client's CertificateVerify check cost
/// when `ClientHandshake.verifyEcdsa` ran on `std.crypto`.
///
/// No code path reaches this any more — `ecdsa_p256_verify` above is the
/// verifier the library now calls. The row stays because it is the
/// measurement that argued for the move (DESIGN.md §2, bench/README.md),
/// and undoing the move should mean re-running it rather than re-deciding
/// on the strength of the original reasoning alone.
const P256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;

var std_public_sec1: [65]u8 = undefined;
var std_signature_der: [72]u8 = undefined;
var std_signature_bytes: usize = 0;

fn stdVerifyBody(_: void, iterations: usize) anyerror!u64 {
    for (0..iterations) |_| {
        const key = try P256.PublicKey.fromSec1(&std_public_sec1);
        const signature = try P256.Signature.fromDer(std_signature_der[0..std_signature_bytes]);
        try signature.verify(&sign_content, key);
    }
    return std_signature_bytes;
}

// ---------------------------------------------------------------------

var chain_storage: [Credentials.chain_bytes_max]u8 = undefined;

pub fn main() !void {
    for (&plaintext_storage, 0..) |*byte, index| byte.* = @truncate(index);

    // Nonces are libcrypto's here rather than RFC 6979's: that is the
    // shape a deployment ships, and it is what rustls's ECDSA signer
    // does, so the comparison is not against a knob only we turn.
    var credentials = try Credentials.load(cert_pem, key_pem, &chain_storage, false);
    defer credentials.deinit();

    try measure("handshake_full", "handshake", 0, 200, HandshakeContext{
        .credentials = &credentials,
        .store = null,
        .resumption = null,
    }, handshakeBody);

    try measurePhases(&credentials, 200);

    var store: TicketStore = .{};
    const resumption = try captureTicket(&credentials, &store, &buffers_storage);
    try measure("handshake_resume", "handshake", 0, 200, HandshakeContext{
        .credentials = &credentials,
        .store = &store,
        .resumption = resumption,
    }, handshakeBody);

    // Bulk needs a live pair; the handshake scenarios tore theirs down.
    pair_storage.init(&credentials, null, null);
    defer pair_storage.deinit();
    try pair_storage.connect(&buffers_storage);
    try measure("transfer_aes128", "byte", chunk_bytes, 4000, {}, transferBody);

    inline for (.{
        .{ CipherSuite.aes_128_gcm_sha256, "record_aes128" },
        .{ CipherSuite.aes_256_gcm_sha384, "record_aes256" },
        .{ CipherSuite.chacha20_poly1305_sha256, "record_chacha20" },
    }) |entry| {
        try resetProtectors(entry[0]);
        try measure(entry[1], "byte", chunk_bytes, 4000, {}, recordBody);
        protector_storage.sealer.deinit();
        protector_storage.opener.deinit();
    }

    inline for (.{
        .{ CipherSuite.aes_128_gcm_sha256, "aead_seal_aes128" },
        .{ CipherSuite.aes_256_gcm_sha384, "aead_seal_aes256" },
        .{ CipherSuite.chacha20_poly1305_sha256, "aead_seal_chacha20" },
    }) |entry| {
        const key = [_]u8{0xab} ** cipher_suite.key_bytes_max;
        aead_storage = try backend.AeadKey.init(entry[0], key[0..entry[0].keyBytes()]);
        try measure(entry[1], "byte", chunk_bytes, 8000, {}, aeadSealBody);
        aead_storage.deinit();
    }

    try measure("aead_key_init", "key", 0, 4000, CipherSuite.aes_128_gcm_sha256, aeadInitBody);

    signer_storage = try backend.Signer.fromPem(key_pem, false);
    defer signer_storage.deinit();
    try measure("ecdsa_p256_sign", "signature", 0, 2000, {}, signBody);
    // Re-signed *after* the signing scenario, not before it: `signBody`
    // writes into the same buffer, and a DER ECDSA signature is 70 to 72
    // bytes depending on the high bits of r and s. A length captured
    // before that loop describes a signature the loop has since replaced.
    const signature = try signer_storage.sign(
        .ecdsa_secp256r1_sha256,
        &sign_content,
        &signature_storage,
    );
    try measure("ecdsa_p256_verify", "verification", 0, 2000, signature.len, verifyBody);
    var peer_public: [32]u8 = undefined;
    try backend.x25519Public(&server_key_share_private[0..32].*, &peer_public);
    try measure("x25519_keygen_agree", "exchange", 0, 2000, &peer_public, x25519Body);
    try measure("x25519_public", "keygen", 0, 2000, {}, x25519PublicBody);
    agree_share = try backend.KeyShare.init(.x25519, &client_x25519_private);
    try measure("x25519_shared", "agreement", 0, 2000, &peer_public, x25519SharedBody);
    agree_share.deinit();
    try measure(
        "x25519_shared_rederive",
        "agreement",
        0,
        2000,
        &peer_public,
        x25519SharedDeriveBody,
    );

    // The client's real CertificateVerify path, priced against the
    // libcrypto verifier it does not use.
    const std_keys = P256.KeyPair.generateDeterministic(.{0x5c} ** 32) catch
        return error.KeyGeneration;
    std_public_sec1 = std_keys.public_key.toUncompressedSec1();
    const std_signature = try std_keys.sign(&sign_content, null);
    std_signature_bytes = std_signature.toDer(&std_signature_der).len;
    try measure("p256_verify_stdcrypto", "verification", 0, 500, {}, stdVerifyBody);
}
