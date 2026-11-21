//! RFC 9001 mode, end to end in memory.
//!
//! The server half is driven first by a hand-rolled peer: a ClientHello
//! from the production encoder, and everything after it — the shared
//! secret, the transcript, every traffic secret, the client's Finished —
//! derived here from `key_schedule` and `backend` directly, never by
//! asking the machine. So a secret the server hands the transport is
//! checked against the RFC 8446 §7.1 derivation it must equal, at the
//! transcript point §7.1 names, rather than against itself.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

const Credentials = @import("Credentials.zig");
const ServerHandshake = @import("ServerHandshake.zig");
const backend = @import("crypto/backend_openssl.zig");
const client_hello = @import("client_hello.zig");
const client_messages = @import("client_messages.zig");
const handshake = @import("handshake.zig");
const key_schedule = @import("key_schedule.zig");
const quic = @import("quic.zig");
const server_messages = @import("server_messages.zig");
const wire = @import("wire.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;
const Schedule = key_schedule.KeySchedule(.aes_128_gcm_sha256);

const client_x25519_private = @as([31]u8, @splat(0x21)) ++ [_]u8{0x40};
const server_key_share_private = @as([47]u8, @splat(0x93)) ++ [_]u8{0x0e};
/// Two transport-parameter bodies that are not each other, so a test can
/// tell which side's arrived where. The content is opaque to zssl; these
/// happen to be RFC 9000 §18 encodings (initial_max_data, max_idle_timeout).
const client_parameters = [_]u8{ 0x04, 0x04, 0x80, 0x10, 0x00, 0x00 };
const server_parameters = [_]u8{ 0x01, 0x02, 0x67, 0x10 };

const ServerHarness = struct {
    chain_storage: [Credentials.chain_bytes_max]u8,
    credentials: Credentials,
    reassembly: [8192]u8,
    flight: [ServerHandshake.quic_flight_bytes_min]u8,
    out: [ServerHandshake.quic_out_bytes_min]u8,
    server: ServerHandshake,

    const Options = struct {
        alpn: []const []const u8 = &.{"h3"},
        groups: []const u16 = &client_hello.groups_supported,
        client_auth: ?ServerHandshake.ClientAuth = null,
        psk_lookup: ?ServerHandshake.PskLookup = null,
    };

    fn init(harness: *ServerHarness, options: Options) !void {
        harness.credentials = try Credentials.load(
            @embedFile("testdata/cert.pem"),
            @embedFile("testdata/key.pem"),
            &harness.chain_storage,
            true,
        );
        harness.server = ServerHandshake.init(&.{
            .credentials = &harness.credentials,
            .server_random = @splat(0x5c),
            .key_share_private = server_key_share_private,
            .alpn_protocols = options.alpn,
            .groups = options.groups,
            .client_auth = options.client_auth,
            .psk_lookup = options.psk_lookup,
            .reassembly = &harness.reassembly,
            .flight = &harness.flight,
            .quic = .{ .transport_parameters = &server_parameters },
        });
    }

    fn deinit(harness: *ServerHarness) void {
        harness.server.deinit();
        harness.credentials.deinit();
    }
};

const HelloOptions = struct {
    session_id: []const u8 = &.{},
    alpn: []const []const u8 = &.{"h3"},
    parameters: ?[]const u8 = &client_parameters,
    share_group: u16 = client_hello.group_x25519,
    share_public: ?[]const u8 = null,
};

/// The production encoder's ClientHello, as a QUIC client would send it.
fn quicHello(out: []u8, options: HelloOptions) ![]const u8 {
    var x25519_public: [32]u8 = undefined;
    try backend.x25519Public(&client_x25519_private, &x25519_public);
    return client_messages.clientHello(out, &.{
        .random = &@as([32]u8, @splat(0x3c)),
        .session_id = options.session_id,
        .share_group = options.share_group,
        .share_public = options.share_public orelse &x25519_public,
        .signature_schemes = &client_messages.signature_schemes_default,
        .groups = &.{ client_hello.group_x25519, client_hello.group_secp256r1 },
        .server_name = "quic.zssl.test",
        .alpn_protocols = options.alpn,
        .quic_transport_parameters = options.parameters,
    });
}

/// Every event one `handleCrypto` and its drains produced, with the
/// borrowed bytes copied out so the next call cannot move them.
const Events = struct {
    kinds: [8]std.meta.Tag(ServerHandshake.QuicEvent) = undefined,
    levels: [8]?quic.Level = undefined,
    directions: [8]?quic.Direction = undefined,
    bytes: [8][]const u8 = undefined,
    storage: [16384]u8 = undefined,
    used: usize = 0,
    count: u8 = 0,

    fn record(events: *Events, event: ServerHandshake.QuicEvent) !void {
        try testing.expect(events.count < events.kinds.len);
        const index = events.count;
        events.kinds[index] = event;
        events.levels[index] = null;
        events.directions[index] = null;
        const borrowed: []const u8 = switch (event) {
            .crypto => |crypto| blk: {
                events.levels[index] = crypto.level;
                break :blk crypto.bytes;
            },
            .secret => |secret| blk: {
                events.levels[index] = secret.level;
                events.directions[index] = secret.direction;
                try testing.expectEqual(backend_suite, secret.suite);
                break :blk secret.bytes;
            },
            .transport_parameters => |body| body,
            .connected => &.{},
        };
        @memcpy(events.storage[events.used..][0..borrowed.len], borrowed);
        events.bytes[index] = events.storage[events.used..][0..borrowed.len];
        events.used += borrowed.len;
        events.count += 1;
    }

    /// Feed `bytes` at `level` in `chunks` pieces, recording every event.
    fn feed(events: *Events, harness: *ServerHarness, level: quic.Level, bytes: []const u8, chunks: u8) !void {
        assert(chunks >= 1);
        const step = std.math.divCeil(usize, bytes.len, chunks) catch unreachable;
        var offset: usize = 0;
        while (offset < bytes.len) {
            const end = @min(offset + step, bytes.len);
            var event = try harness.server.handleCrypto(level, bytes[offset..end], &harness.out);
            while (event) |ready| : (event = try harness.server.drainCrypto(&harness.out)) {
                try events.record(ready);
            }
            offset = end;
        }
    }
};

const backend_suite: @import("cipher_suite.zig").CipherSuite = .aes_128_gcm_sha256;

/// The client's side of RFC 8446 §7.1, computed here: what every secret
/// the server hands out must equal, given what crossed the wire.
const Derived = struct {
    client_handshake: [32]u8,
    server_handshake: [32]u8,
    client_application: [32]u8,
    server_application: [32]u8,
    client_finished: [36]u8,

    /// `prefix` is whatever §4.4.1 puts ahead of the ServerHello: the
    /// ClientHello alone, or message_hash(CH1), the retry and CH2.
    fn compute(prefix: []const u8, server_hello: []const u8, flight: []const u8, shared: []const u8) Derived {
        var derived: Derived = undefined;
        var transcript = Sha256.init(.{});
        transcript.update(prefix);
        transcript.update(server_hello);
        var hello_hash: [32]u8 = undefined;
        var copy = transcript;
        copy.final(&hello_hash);
        var schedule = Schedule.initEarly(null);
        schedule.advanceToHandshake(shared);
        derived.client_handshake = schedule.deriveAt(.handshake, "c hs traffic", &hello_hash);
        derived.server_handshake = schedule.deriveAt(.handshake, "s hs traffic", &hello_hash);
        transcript.update(flight);
        var flight_hash: [32]u8 = undefined;
        copy = transcript;
        copy.final(&flight_hash);
        schedule.advanceToMaster();
        derived.client_application = schedule.deriveAt(.master, "c ap traffic", &flight_hash);
        derived.server_application = schedule.deriveAt(.master, "s ap traffic", &flight_hash);
        const key = Schedule.finishedKey(&derived.client_handshake);
        const verify_data = Schedule.verifyData(&key, &flight_hash);
        derived.client_finished = [_]u8{ 20, 0, 0, 32 } ++ verify_data;
        return derived;
    }
};

/// The server's key_share value, read out of a ServerHello.
fn serverShare(server_hello: []const u8) ![]const u8 {
    var cursor = wire.Cursor.init(server_hello[handshake.header_bytes..]);
    _ = try cursor.takeU16();
    _ = try cursor.takeSlice(32);
    _ = try cursor.takeSlice(try cursor.takeByte());
    _ = try cursor.takeU16();
    _ = try cursor.takeByte();
    var extensions = wire.Cursor.init(try cursor.takeSlice(try cursor.takeU16()));
    while (extensions.remaining() > 0) {
        const extension_type = try extensions.takeU16();
        var body = wire.Cursor.init(try extensions.takeSlice(try extensions.takeU16()));
        if (extension_type != 51) continue;
        _ = try body.takeU16();
        return body.takeSlice(try body.takeU16());
    }
    return error.TestUnexpectedResult;
}

/// The one extension block of an EncryptedExtensions, and whether it
/// carries `extension_type` with `expected` as its body.
fn encryptedExtensionsCarries(flight: []const u8, extension_type: u16, expected: []const u8) !bool {
    try testing.expectEqual(@as(u8, 8), flight[0]); // EncryptedExtensions leads the flight.
    var cursor = wire.Cursor.init(flight[handshake.header_bytes..]);
    var extensions = wire.Cursor.init(try cursor.takeSlice(try cursor.takeU16()));
    while (extensions.remaining() > 0) {
        const found = try extensions.takeU16();
        const body = try extensions.takeSlice(try extensions.takeU16());
        if (found == extension_type) return std.mem.eql(u8, body, expected);
    }
    return false;
}

fn x25519Shared(server_hello: []const u8, out: *[32]u8) !void {
    const share = try serverShare(server_hello);
    try testing.expectEqual(@as(usize, 32), share.len);
    try backend.x25519Shared(&client_x25519_private, share[0..32], out);
}

test "QUIC server: a fragmented ClientHello earns §4.1.4's sequence, every secret checked" {
    var harness: ServerHarness = undefined;
    try harness.init(.{});
    defer harness.deinit();
    var hello_buffer: [client_messages.hello_bytes_max]u8 = undefined;
    const hello = try quicHello(&hello_buffer, .{});

    // Three fragments: the first two complete nothing and say so.
    var events: Events = .{};
    try events.feed(&harness, .initial, hello, 3);
    const expected = [_]std.meta.Tag(ServerHandshake.QuicEvent){
        .crypto, .transport_parameters, .secret, .secret, .crypto, .secret,
    };
    try testing.expectEqual(@as(u8, expected.len), events.count);
    try testing.expectEqualSlices(std.meta.Tag(ServerHandshake.QuicEvent), &expected, events.kinds[0..events.count]);
    try testing.expectEqual(quic.Level.initial, events.levels[0].?);
    try testing.expectEqual(quic.Level.handshake, events.levels[2].?);
    try testing.expectEqual(quic.Direction.receive, events.directions[2].?);
    try testing.expectEqual(quic.Direction.send, events.directions[3].?);
    try testing.expectEqual(quic.Level.handshake, events.levels[4].?);
    try testing.expectEqual(quic.Level.application, events.levels[5].?);
    try testing.expectEqual(quic.Direction.send, events.directions[5].?);
    // §8.2 both ways: the client's body out, ours in EncryptedExtensions.
    try testing.expectEqualSlices(u8, &client_parameters, events.bytes[1]);
    try testing.expect(try encryptedExtensionsCarries(events.bytes[4], quic.transport_parameters_extension, &server_parameters));
    try testing.expect(try encryptedExtensionsCarries(events.bytes[4], 16, &.{ 0, 3, 2, 'h', '3' }));

    // A bare ServerHello — no record header, no ChangeCipherSpec behind
    // it — whose declared length is exactly what was handed over.
    const server_hello = events.bytes[0];
    try testing.expectEqual(@as(u8, 2), server_hello[0]);
    try testing.expectEqual(server_hello.len, handshake.header_bytes + std.mem.readInt(u24, server_hello[1..4], .big));
    var shared: [32]u8 = undefined;
    try x25519Shared(server_hello, &shared);
    const derived = Derived.compute(hello, server_hello, events.bytes[4], &shared);
    try testing.expectEqualSlices(u8, &derived.client_handshake, events.bytes[2]);
    try testing.expectEqualSlices(u8, &derived.server_handshake, events.bytes[3]);
    try testing.expectEqualSlices(u8, &derived.server_application, events.bytes[5]);
    try testing.expectEqual(ServerHandshake.State.awaiting_finished, harness.server.state);

    // The client's Finished, at Handshake, in two pieces: 1-RTT receive
    // only now (§5.7), then the handshake completes.
    var finish: Events = .{};
    try finish.feed(&harness, .handshake, &derived.client_finished, 2);
    try testing.expectEqual(@as(u8, 2), finish.count);
    try testing.expectEqual(std.meta.Tag(ServerHandshake.QuicEvent).secret, finish.kinds[0]);
    try testing.expectEqual(quic.Level.application, finish.levels[0].?);
    try testing.expectEqual(quic.Direction.receive, finish.directions[0].?);
    try testing.expectEqualSlices(u8, &derived.client_application, finish.bytes[0]);
    try testing.expectEqual(std.meta.Tag(ServerHandshake.QuicEvent).connected, finish.kinds[1]);
    try testing.expectEqual(ServerHandshake.State.connected, harness.server.state);

    // A ticket goes out as a bare message, for the transport to send at
    // the application level, and the PSK behind it derives as over TCP.
    var nonce = [_]u8{0x01};
    var psk_buffer: [48]u8 = undefined;
    try testing.expectEqual(@as(usize, 32), harness.server.resumptionPsk(&nonce, &psk_buffer).len);
    const ticket = try harness.server.sendNewSessionTicket(&.{
        .lifetime_s = 3600,
        .age_add = 7,
        .ticket_nonce = &nonce,
        .ticket = "opaque-ticket",
    }, &harness.out);
    try testing.expectEqual(@as(u8, 4), ticket[0]);
    try testing.expectEqual(ticket.len, handshake.header_bytes + std.mem.readInt(u24, ticket[1..4], .big));
}

test "QUIC server: §6 refuses a KeyUpdate, and §4.8 maps it to 0x010a" {
    var harness: ServerHarness = undefined;
    try harness.init(.{});
    defer harness.deinit();
    var hello_buffer: [client_messages.hello_bytes_max]u8 = undefined;
    const hello = try quicHello(&hello_buffer, .{});
    var events: Events = .{};
    try events.feed(&harness, .initial, hello, 1);
    var shared: [32]u8 = undefined;
    try x25519Shared(events.bytes[0], &shared);
    const derived = Derived.compute(hello, events.bytes[0], events.bytes[4], &shared);
    var finish: Events = .{};
    try finish.feed(&harness, .handshake, &derived.client_finished, 1);
    try testing.expectEqual(ServerHandshake.State.connected, harness.server.state);

    // "Endpoints MUST treat the receipt of a TLS KeyUpdate message as a
    // connection error of type 0x010a."
    const key_update = [_]u8{ 24, 0, 0, 1, 0 };
    const refused = harness.server.handleCrypto(.application, &key_update, &harness.out);
    try testing.expectError(error.UnexpectedMessage, refused);
    try testing.expectEqual(@as(u64, 0x010a), quic.errorCode(error.UnexpectedMessage));
    try testing.expectEqual(ServerHandshake.State.failed, harness.server.state);
}

test "QUIC server: what RFC 9001 asks of a ClientHello, each refused as its rule says" {
    const Case = struct {
        name: []const u8,
        hello: HelloOptions,
        server_alpn: []const []const u8 = &.{"h3"},
        want: ServerHandshake.Error,
        code: u64,
    };
    for ([_]Case{
        // §8.4: compatibility mode is not QUIC, and §8.4 names
        // PROTOCOL_VIOLATION rather than an alert.
        .{ .name = "session id", .hello = .{ .session_id = &@as([32]u8, @splat(0xee)) }, .want = error.QuicProtocolViolation, .code = 0x0a },
        // §8.2: 0x016d, "equivalent to a fatal TLS missing_extension alert".
        .{ .name = "no transport parameters", .hello = .{ .parameters = null }, .want = error.MissingExtension, .code = 0x016d },
        // §8.1: 0x0178 for no ALPN at all, and for an offer with no overlap.
        .{ .name = "no ALPN", .hello = .{ .alpn = &.{} }, .want = error.NoApplicationProtocol, .code = 0x0178 },
        .{ .name = "ALPN mismatch", .hello = .{ .alpn = &.{"h3-29"} }, .want = error.NoApplicationProtocol, .code = 0x0178 },
        .{
            .name = "server prefers another",
            .hello = .{ .alpn = &.{"h3"} },
            .server_alpn = &.{"hq-interop"},
            .want = error.NoApplicationProtocol,
            .code = 0x0178,
        },
    }) |case| {
        var harness: ServerHarness = undefined;
        try harness.init(.{ .alpn = case.server_alpn });
        defer harness.deinit();
        var hello_buffer: [client_messages.hello_bytes_max]u8 = undefined;
        const hello = try quicHello(&hello_buffer, case.hello);
        const answer = harness.server.handleCrypto(.initial, hello, &harness.out);
        testing.expectError(case.want, answer) catch |err| {
            std.debug.print("case '{s}' did not refuse as expected\n", .{case.name});
            return err;
        };
        try testing.expectEqual(case.code, quic.errorCode(case.want));
        try testing.expectEqual(ServerHandshake.State.failed, harness.server.state);
    }
}

test "QUIC server: bytes at the wrong level are refused, and §4.1.3's leftovers too" {
    var hello_buffer: [client_messages.hello_bytes_max]u8 = undefined;
    const hello = try quicHello(&hello_buffer, .{});

    // A ClientHello at Handshake: there is no Handshake key it could
    // have arrived under.
    {
        var harness: ServerHarness = undefined;
        try harness.init(.{});
        defer harness.deinit();
        try testing.expectError(error.UnexpectedMessage, harness.server.handleCrypto(.handshake, hello, &harness.out));
    }
    // Half a ClientHello at Initial, then anything at Handshake: data a
    // lower level never finished, which §4.1.3 calls PROTOCOL_VIOLATION.
    {
        var harness: ServerHarness = undefined;
        try harness.init(.{});
        defer harness.deinit();
        try testing.expectEqual(@as(?ServerHandshake.QuicEvent, null), try harness.server.handleCrypto(.initial, hello[0..40], &harness.out));
        try testing.expectError(error.QuicProtocolViolation, harness.server.handleCrypto(.handshake, &.{ 20, 0, 0, 32 }, &harness.out));
    }
    // Bytes behind a whole ClientHello, at Initial: a client talking past
    // its own flight.
    {
        var harness: ServerHarness = undefined;
        try harness.init(.{});
        defer harness.deinit();
        var both: [client_messages.hello_bytes_max + 8]u8 = undefined;
        @memcpy(both[0..hello.len], hello);
        @memcpy(both[hello.len..][0..5], &[_]u8{ 1, 0, 0, 1, 0 });
        try testing.expectError(error.UnexpectedMessage, harness.server.handleCrypto(.initial, both[0 .. hello.len + 5], &harness.out));
    }
    // And Initial again once the hello is answered.
    {
        var harness: ServerHarness = undefined;
        try harness.init(.{});
        defer harness.deinit();
        var events: Events = .{};
        try events.feed(&harness, .initial, hello, 1);
        try testing.expectError(error.UnexpectedMessage, harness.server.handleCrypto(.initial, hello, &harness.out));
    }
}

test "QUIC server: a caller that stops draining is told so" {
    var harness: ServerHarness = undefined;
    try harness.init(.{});
    defer harness.deinit();
    var hello_buffer: [client_messages.hello_bytes_max]u8 = undefined;
    const hello = try quicHello(&hello_buffer, .{});
    const first = (try harness.server.handleCrypto(.initial, hello, &harness.out)).?;
    try testing.expectEqual(std.meta.Tag(ServerHandshake.QuicEvent).crypto, std.meta.activeTag(first));
    // Four events are still owed; new bytes before them are refused.
    try testing.expectError(error.EventsPending, harness.server.handleCrypto(.handshake, &.{ 20, 0 }, &harness.out));
}

test "QUIC server: a HelloRetryRequest at Initial, no ChangeCipherSpec, then the retry completes" {
    // Narrowed to secp256r1, so the x25519 share every hello here carries
    // earns a retry — §4.4.1's transcript surgery, over QUIC.
    var harness: ServerHarness = undefined;
    try harness.init(.{ .groups = &.{client_hello.group_secp256r1} });
    defer harness.deinit();
    var first_buffer: [client_messages.hello_bytes_max]u8 = undefined;
    const first = try quicHello(&first_buffer, .{});
    var retry: Events = .{};
    try retry.feed(&harness, .initial, first, 1);
    try testing.expectEqual(@as(u8, 1), retry.count);
    const hello_retry = retry.bytes[0];
    try testing.expectEqual(quic.Level.initial, retry.levels[0].?);
    try testing.expectEqualSlices(u8, &server_messages.hello_retry_magic, hello_retry[6..38]);
    // The message and nothing else: §8.4 has no compatibility record.
    try testing.expectEqual(hello_retry.len, handshake.header_bytes + std.mem.readInt(u24, hello_retry[1..4], .big));
    try testing.expectEqual(ServerHandshake.State.awaiting_retry_client_hello, harness.server.state);

    const scalar = @as([31]u8, @splat(0x52)) ++ [_]u8{0x01};
    var share = try backend.KeyShare.init(.secp256r1, &scalar);
    defer share.deinit();
    var second_buffer: [client_messages.hello_bytes_max]u8 = undefined;
    const second = try quicHello(&second_buffer, .{
        .share_group = client_hello.group_secp256r1,
        .share_public = share.publicValue(),
    });
    var answer: Events = .{};
    try answer.feed(&harness, .initial, second, 4);
    try testing.expectEqual(@as(u8, 6), answer.count);

    // The ServerHello's transcript is message_hash(CH1), the retry, CH2.
    var prefix: [4 + 32 + server_messages.server_hello_bytes_max + client_messages.hello_bytes_max]u8 = undefined;
    prefix[0..4].* = .{ 254, 0, 0, 32 };
    Sha256.hash(first, prefix[4..36], .{});
    @memcpy(prefix[36..][0..hello_retry.len], hello_retry);
    @memcpy(prefix[36 + hello_retry.len ..][0..second.len], second);
    const prefix_bytes = 36 + hello_retry.len + second.len;
    var shared_buffer: [48]u8 = undefined;
    const shared = try share.agree(try serverShare(answer.bytes[0]), &shared_buffer);
    const derived = Derived.compute(prefix[0..prefix_bytes], answer.bytes[0], answer.bytes[4], shared);
    try testing.expectEqualSlices(u8, &derived.client_handshake, answer.bytes[2]);
    try testing.expectEqualSlices(u8, &derived.server_handshake, answer.bytes[3]);
    try testing.expectEqualSlices(u8, &derived.server_application, answer.bytes[5]);
    var finish: Events = .{};
    try finish.feed(&harness, .handshake, &derived.client_finished, 1);
    try testing.expectEqual(std.meta.Tag(ServerHandshake.QuicEvent).connected, finish.kinds[1]);
    try testing.expectEqualSlices(u8, &derived.client_application, finish.bytes[0]);
}

// ---------------------------------------------------------------------
// The production client against the production server, both in QUIC mode.

const ClientHandshake = @import("ClientHandshake.zig");
const CipherSuite = @import("cipher_suite.zig").CipherSuite;

/// One direction's CRYPTO stream at one level, as a transport would hold
/// it between datagrams.
const Stream = struct {
    bytes: [16384]u8 = undefined,
    used: usize = 0,

    fn append(stream: *Stream, data: []const u8) !void {
        try testing.expect(stream.used + data.len <= stream.bytes.len);
        @memcpy(stream.bytes[stream.used..][0..data.len], data);
        stream.used += data.len;
    }
};

/// What one side's transport would have installed, by level and direction.
const Installed = struct {
    secrets: [3][2][48]u8 = undefined,
    lengths: [3][2]u8 = @splat(@splat(0)),
    parameters: [64]u8 = undefined,
    parameters_bytes: ?usize = null,
    connected: bool = false,

    fn install(installed: *Installed, handed: quic.Secret) !void {
        const level = @backingInt(handed.level);
        const direction = @backingInt(handed.direction);
        // Each secret is handed out once.
        try testing.expectEqual(@as(u8, 0), installed.lengths[level][direction]);
        try testing.expectEqual(handed.suite.hashBytes(), handed.bytes.len);
        @memcpy(installed.secrets[level][direction][0..handed.bytes.len], handed.bytes);
        installed.lengths[level][direction] = @intCast(handed.bytes.len);
    }

    fn has(installed: *const Installed, level: quic.Level, direction: quic.Direction) bool {
        return installed.lengths[@backingInt(level)][@backingInt(direction)] != 0;
    }

    fn secret(installed: *const Installed, level: quic.Level, direction: quic.Direction) []const u8 {
        const length = installed.lengths[@backingInt(level)][@backingInt(direction)];
        return installed.secrets[@backingInt(level)][@backingInt(direction)][0..length];
    }

    fn parametersSeen(installed: *Installed, body: []const u8) !void {
        try testing.expectEqual(@as(?usize, null), installed.parameters_bytes);
        @memcpy(installed.parameters[0..body.len], body);
        installed.parameters_bytes = body.len;
    }
};

const Pair = struct {
    server_side: ServerHarness,
    client: ClientHandshake,
    client_reassembly: [16384]u8,
    client_auth_flight: [Credentials.chain_bytes_max + 1024]u8,
    client_out: [ClientHandshake.quic_out_bytes_min]u8,
    to_server: [3]Stream,
    to_client: [3]Stream,
    server_installed: Installed,
    client_installed: Installed,
    tickets: u8,
    ticket_storage: [512]u8,
    ticket: ?ClientHandshake.Ticket,

    const Options = struct {
        server: ServerHarness.Options = .{},
        alpn: []const []const u8 = &.{"h3"},
        retry_private: ?[backend.group_private_bytes_max]u8 = null,
        resume_session: ?ClientHandshake.Resumption = null,
        client_credentials: ?*const Credentials = null,
    };

    fn init(pair: *Pair, options: Options) !void {
        try pair.server_side.init(options.server);
        pair.client = ClientHandshake.init(&.{
            .client_random = @splat(0x1a),
            .x25519_private = client_x25519_private,
            .retry_key_share_private = options.retry_private,
            .server_name = "quic.zssl.test",
            .alpn_protocols = options.alpn,
            .certificate_policy = .leaf_signature,
            .client_credentials = options.client_credentials,
            .client_auth_flight = &pair.client_auth_flight,
            .resume_session = options.resume_session,
            .reassembly = &pair.client_reassembly,
            .quic = .{ .transport_parameters = &client_parameters },
        });
        pair.to_server = @splat(.{});
        pair.to_client = @splat(.{});
        pair.server_installed = .{};
        pair.client_installed = .{};
        pair.tickets = 0;
        pair.ticket = null;
    }

    fn deinit(pair: *Pair) void {
        pair.client.deinit();
        pair.server_side.deinit();
    }

    /// Run the handshake to quiescence, delivering every level's bytes in
    /// pieces of at most `chunk`. A transport holds no key to read a
    /// level before the peer's TLS has handed it one, and this holds the
    /// machines to that: bytes at a level are delivered only once the
    /// receiving side has installed that level's receive secret.
    fn run(pair: *Pair, chunk: usize) !void {
        const hello = pair.client.startCrypto();
        try testing.expectEqual(quic.Level.initial, hello.level);
        try pair.to_server[0].append(hello.bytes);
        var rounds: u8 = 0;
        while (pair.pending()) : (rounds += 1) {
            try testing.expect(rounds < 16);
            for ([_]quic.Level{ .initial, .handshake, .application }) |level| {
                try pair.deliverToServer(level, chunk);
                try pair.deliverToClient(level, chunk);
            }
        }
    }

    fn pending(pair: *const Pair) bool {
        for (pair.to_server, pair.to_client) |server_stream, client_stream| {
            if (server_stream.used != 0 or client_stream.used != 0) return true;
        }
        return false;
    }

    fn deliverToServer(pair: *Pair, level: quic.Level, chunk: usize) !void {
        const stream = &pair.to_server[@backingInt(level)];
        if (stream.used == 0) return;
        if (level != .initial) try testing.expect(pair.server_installed.has(level, .receive));
        var offset: usize = 0;
        while (offset < stream.used) {
            const end = @min(offset + chunk, stream.used);
            const server = &pair.server_side.server;
            var event = try server.handleCrypto(level, stream.bytes[offset..end], &pair.server_side.out);
            while (event) |ready| : (event = try server.drainCrypto(&pair.server_side.out)) {
                switch (ready) {
                    .crypto => |crypto| try pair.to_client[@backingInt(crypto.level)].append(crypto.bytes),
                    .secret => |handed| try pair.server_installed.install(handed),
                    .transport_parameters => |body| try pair.server_installed.parametersSeen(body),
                    .connected => pair.server_installed.connected = true,
                }
            }
            offset = end;
        }
        stream.used = 0;
    }

    fn deliverToClient(pair: *Pair, level: quic.Level, chunk: usize) !void {
        const stream = &pair.to_client[@backingInt(level)];
        if (stream.used == 0) return;
        if (level != .initial) try testing.expect(pair.client_installed.has(level, .receive));
        var offset: usize = 0;
        while (offset < stream.used) {
            const end = @min(offset + chunk, stream.used);
            var event = try pair.client.handleCrypto(level, stream.bytes[offset..end], &pair.client_out);
            while (event) |ready| : (event = try pair.client.drainCrypto(&pair.client_out)) {
                switch (ready) {
                    .crypto => |crypto| try pair.to_server[@backingInt(crypto.level)].append(crypto.bytes),
                    .secret => |handed| try pair.client_installed.install(handed),
                    .transport_parameters => |body| try pair.client_installed.parametersSeen(body),
                    .connected => pair.client_installed.connected = true,
                    .ticket => |ticket| try pair.keepTicket(ticket),
                }
            }
            offset = end;
        }
        stream.used = 0;
    }

    fn keepTicket(pair: *Pair, ticket: ClientHandshake.Ticket) !void {
        pair.tickets += 1;
        try testing.expect(ticket.ticket.len + ticket.nonce.len <= pair.ticket_storage.len);
        @memcpy(pair.ticket_storage[0..ticket.ticket.len], ticket.ticket);
        @memcpy(pair.ticket_storage[ticket.ticket.len..][0..ticket.nonce.len], ticket.nonce);
        var kept = ticket;
        kept.ticket = pair.ticket_storage[0..ticket.ticket.len];
        kept.nonce = pair.ticket_storage[ticket.ticket.len..][0..ticket.nonce.len];
        pair.ticket = kept;
    }

    /// Both sides complete, every secret one side sends with is the one
    /// the other receives with, and each saw the other's parameters.
    fn expectAgreement(pair: *const Pair) !void {
        try testing.expect(pair.client_installed.connected);
        try testing.expect(pair.server_installed.connected);
        try testing.expectEqual(ServerHandshake.State.connected, pair.server_side.server.state);
        try testing.expectEqual(ClientHandshake.State.connected, pair.client.state);
        for ([_]quic.Level{ .handshake, .application }) |level| {
            const client_send = pair.client_installed.secret(level, .send);
            try testing.expect(client_send.len == 32 or client_send.len == 48);
            try testing.expectEqualSlices(u8, client_send, pair.server_installed.secret(level, .receive));
            try testing.expectEqualSlices(u8, pair.server_installed.secret(level, .send), pair.client_installed.secret(level, .receive));
            try testing.expect(!std.mem.eql(u8, client_send, pair.client_installed.secret(level, .receive)));
        }
        try testing.expectEqualSlices(u8, &client_parameters, pair.server_installed.parameters[0..pair.server_installed.parameters_bytes.?]);
        try testing.expectEqualSlices(u8, &server_parameters, pair.client_installed.parameters[0..pair.client_installed.parameters_bytes.?]);
        try testing.expectEqualSlices(u8, "h3", pair.client.alpnSelected().?);
        try testing.expectEqualSlices(u8, "h3", pair.server_side.server.alpnSelected().?);
    }

    /// The server issues one ticket at the application level and the
    /// client reads it there; both derive the same PSK from it.
    fn exchangeTicket(pair: *Pair, nonce: []const u8) !void {
        const ticket = try pair.server_side.server.sendNewSessionTicket(&.{
            .lifetime_s = 3600,
            .age_add = 0x01020304,
            .ticket_nonce = nonce,
            .ticket = "quic-ticket",
        }, &pair.server_side.out);
        try pair.to_client[@backingInt(quic.Level.application)].append(ticket);
        try pair.deliverToClient(.application, 5);
        try testing.expectEqual(@as(u8, 1), pair.tickets);
        try testing.expectEqualSlices(u8, "quic-ticket", pair.ticket.?.ticket);
        try testing.expectEqual(@as(?u32, null), pair.ticket.?.early_data_bytes_max);
        var server_psk: [48]u8 = undefined;
        var client_psk: [48]u8 = undefined;
        try testing.expectEqualSlices(
            u8,
            pair.server_side.server.resumptionPsk(nonce, &server_psk),
            pair.client.resumptionPsk(nonce, &client_psk),
        );
    }
};

test "QUIC end to end: every level fragmented every way, secrets and parameters agree" {
    for ([_]usize{ 1, 7, 64, 1000, std.math.maxInt(u16) }) |chunk| {
        var pair: Pair = undefined;
        try pair.init(.{});
        defer pair.deinit();
        pair.run(chunk) catch |err| {
            std.debug.print("chunk {d} failed\n", .{chunk});
            return err;
        };
        try pair.expectAgreement();
        try testing.expect(!pair.client.resumed);
        try testing.expect(pair.client.peer.verified);
        try pair.exchangeTicket(&.{ 0x00, 0x01 });
    }
}

test "QUIC end to end: a HelloRetryRequest is answered at Initial and the retry completes" {
    var pair: Pair = undefined;
    try pair.init(.{
        .server = .{ .groups = &.{client_hello.group_secp256r1} },
        .retry_private = @as([31]u8, @splat(0x52)) ++ [_]u8{0x01} ++ @as([16]u8, @splat(0)),
    });
    defer pair.deinit();
    try pair.run(100);
    try pair.expectAgreement();
    try testing.expect(pair.client.retried);
}

const QuicTicketStore = struct {
    psk: [32]u8,

    fn lookup(
        context: *anyopaque,
        identity: []const u8,
        obfuscated_age: u32,
        psk_out: *[48]u8,
    ) ?ServerHandshake.Psk {
        _ = obfuscated_age;
        const store: *QuicTicketStore = @ptrCast(@alignCast(context));
        if (!std.mem.eql(u8, identity, "quic-ticket")) return null;
        psk_out[0..32].* = store.psk;
        return .{ .psk_bytes = 32, .kind = .resumption };
    }
};

test "QUIC end to end: a ticket issued at the application level resumes the next connection" {
    var store: QuicTicketStore = undefined;
    var resumption: ClientHandshake.Resumption = undefined;
    {
        var pair: Pair = undefined;
        try pair.init(.{});
        defer pair.deinit();
        try pair.run(std.math.maxInt(u16));
        try pair.expectAgreement();
        const nonce = [_]u8{0x09};
        try pair.exchangeTicket(&nonce);
        var psk: [48]u8 = undefined;
        @memcpy(&store.psk, pair.client.resumptionPsk(&nonce, &psk));
        resumption = .{
            .identity = "quic-ticket",
            .obfuscated_age = 1000 +% pair.ticket.?.age_add,
            .psk = psk,
            .psk_bytes = 32,
        };
    }
    var pair: Pair = undefined;
    try pair.init(.{
        .server = .{ .psk_lookup = .{ .context = &store, .lookup = QuicTicketStore.lookup } },
        .resume_session = resumption,
    });
    defer pair.deinit();
    try pair.run(33);
    try pair.expectAgreement();
    try testing.expect(pair.client.resumed);
    try testing.expect(pair.server_side.server.resumed);
}

test "QUIC end to end: client certificates are asked for and proven, as over TCP" {
    var chain_storage: [Credentials.chain_bytes_max]u8 = undefined;
    var client_credentials = try Credentials.load(
        @embedFile("testdata/p384-cert.pem"),
        @embedFile("testdata/p384-key.pem"),
        &chain_storage,
        true,
    );
    defer client_credentials.deinit();
    var pair: Pair = undefined;
    try pair.init(.{
        .server = .{ .client_auth = .{ .require = true } },
        .client_credentials = &client_credentials,
    });
    defer pair.deinit();
    try pair.run(50);
    try pair.expectAgreement();
    try testing.expect(pair.server_side.server.peer.verified);
}

test "QUIC end to end: no overlap in ALPN is no_application_protocol, 0x0178" {
    var pair: Pair = undefined;
    try pair.init(.{ .server = .{ .alpn = &.{"hq-interop"} } });
    defer pair.deinit();
    try testing.expectError(error.NoApplicationProtocol, pair.run(1000));
    try testing.expectEqual(ServerHandshake.State.failed, pair.server_side.server.state);
    try testing.expectEqual(@as(u64, 0x0178), quic.errorCode(error.NoApplicationProtocol));
}

/// The client after a real ServerHello, so its Handshake keys exist and
/// the test can hand it an EncryptedExtensions of its own making.
fn clientAwaitingExtensions(pair: *Pair) !void {
    const hello = pair.client.startCrypto();
    try pair.to_server[0].append(hello.bytes);
    try pair.deliverToServer(.initial, 1 << 16);
    // Only the ServerHello: the flight stays undelivered.
    try pair.deliverToClient(.initial, 1 << 16);
    try testing.expectEqual(ClientHandshake.State.awaiting_encrypted_extensions, pair.client.state);
}

fn encryptedExtensions(out: []u8, extensions: []const u8) []const u8 {
    var builder = wire.Builder.init(out);
    const mark = handshake.beginMessage(&builder, .encrypted_extensions);
    builder.putU16(@intCast(extensions.len));
    builder.putSlice(extensions);
    handshake.endMessage(&builder, mark);
    return builder.written();
}

test "QUIC client: what RFC 9001 asks of an EncryptedExtensions, each refused as its rule says" {
    const alpn = [_]u8{ 0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, 'h', '3' };
    const parameters = [_]u8{ 0x00, 0x39, 0x00, 0x02, 0xab, 0xcd };
    const Case = struct { name: []const u8, extensions: []const u8, want: anyerror, code: u64 };
    for ([_]Case{
        // §8.2: no transport parameters, 0x016d.
        .{ .name = "no parameters", .extensions = &alpn, .want = error.MissingExtension, .code = 0x016d },
        // §8.1: no application protocol, 0x0178.
        .{ .name = "no ALPN", .extensions = &parameters, .want = error.NoApplicationProtocol, .code = 0x0178 },
        // §4.2: one of each — two bodies is a server contradicting itself.
        .{ .name = "parameters twice", .extensions = &(alpn ++ parameters ++ parameters), .want = error.DuplicateExtension, .code = 0x0132 },
    }) |case| {
        var pair: Pair = undefined;
        try pair.init(.{});
        defer pair.deinit();
        try clientAwaitingExtensions(&pair);
        var buffer: [64]u8 = undefined;
        const message = encryptedExtensions(&buffer, case.extensions);
        testing.expectError(case.want, pair.client.handleCrypto(.handshake, message, &pair.client_out)) catch |err| {
            std.debug.print("case '{s}' did not refuse as expected\n", .{case.name});
            return err;
        };
        try testing.expectEqual(case.code, quic.errorCode(@errorCast(case.want)));
        try testing.expectEqual(ClientHandshake.State.failed, pair.client.state);
    }
}

test "QUIC client: §6 refuses a KeyUpdate, §4.6.1 a ticket promising early data" {
    for ([_]bool{ false, true }) |key_update| {
        var pair: Pair = undefined;
        try pair.init(.{});
        defer pair.deinit();
        try pair.run(1 << 16);
        try pair.expectAgreement();
        if (key_update) {
            const message = [_]u8{ 24, 0, 0, 1, 1 };
            try testing.expectError(error.UnexpectedMessage, pair.client.handleCrypto(.application, &message, &pair.client_out));
            continue;
        }
        // A ticket whose early_data extension says anything but
        // 0xffffffff is PROTOCOL_VIOLATION; 0xffffffff itself is a
        // ticket like any other, surfaced with the number it carried.
        var buffer: [64]u8 = undefined;
        for ([_]u32{ std.math.maxInt(u32), 16384 }) |bytes_max| {
            const ticket = newSessionTicket(&buffer, bytes_max);
            if (bytes_max == std.math.maxInt(u32)) {
                const event = (try pair.client.handleCrypto(.application, ticket, &pair.client_out)).?;
                try testing.expectEqual(@as(?u32, bytes_max), event.ticket.early_data_bytes_max);
            } else {
                try testing.expectError(error.QuicProtocolViolation, pair.client.handleCrypto(.application, ticket, &pair.client_out));
                try testing.expectEqual(@as(u64, 0x0a), quic.errorCode(error.QuicProtocolViolation));
            }
        }
    }
}

fn newSessionTicket(out: []u8, early_data_bytes_max: u32) []const u8 {
    var builder = wire.Builder.init(out);
    const mark = handshake.beginMessage(&builder, .new_session_ticket);
    builder.putU32(3600);
    builder.putU32(0);
    builder.putByte(1);
    builder.putByte(0x07);
    builder.putU16(4);
    builder.putSlice("tick");
    builder.putU16(8);
    builder.putU16(42); // early_data, in its NewSessionTicket shape.
    builder.putU16(4);
    builder.putU32(early_data_bytes_max);
    handshake.endMessage(&builder, mark);
    return builder.written();
}

test "QUIC client: a level it holds no key for, and §4.1.3's leftovers" {
    var pair: Pair = undefined;
    try pair.init(.{});
    defer pair.deinit();
    _ = pair.client.startCrypto();
    // Handshake bytes before any ServerHello: nothing could have
    // protected them.
    try testing.expectError(error.UnexpectedMessage, pair.client.handleCrypto(.handshake, &.{ 8, 0, 0, 2, 0, 0 }, &pair.client_out));

    var second: Pair = undefined;
    try second.init(.{});
    defer second.deinit();
    try clientAwaitingExtensions(&second);
    // Half an EncryptedExtensions, then bytes at the application level.
    try testing.expectEqual(@as(?ClientHandshake.QuicEvent, null), try second.client.handleCrypto(.handshake, &.{ 8, 0, 0, 9 }, &second.client_out));
    try testing.expectError(error.QuicProtocolViolation, second.client.handleCrypto(.application, &.{ 4, 0 }, &second.client_out));
}

test "QUIC: nothing may ride behind a Finished at the Handshake level, on either side" {
    const trailing = [_]u8{ 4, 0, 0, 1, 0 };
    // The client: the server's whole flight with a message packed behind
    // its Finished, in one delivery.
    {
        var pair: Pair = undefined;
        try pair.init(.{});
        defer pair.deinit();
        try pair.to_server[0].append(pair.client.startCrypto().bytes);
        try pair.deliverToServer(.initial, 1 << 16);
        try pair.to_client[1].append(&trailing);
        try pair.deliverToClient(.initial, 1 << 16);
        try testing.expectError(error.UnexpectedMessage, pair.deliverToClient(.handshake, 1 << 16));
        try testing.expectEqual(ClientHandshake.State.failed, pair.client.state);
    }
    // The server: the client's Finished with the same message behind it.
    {
        var harness: ServerHarness = undefined;
        try harness.init(.{});
        defer harness.deinit();
        var hello_buffer: [client_messages.hello_bytes_max]u8 = undefined;
        const hello = try quicHello(&hello_buffer, .{});
        var events: Events = .{};
        try events.feed(&harness, .initial, hello, 1);
        var shared: [32]u8 = undefined;
        try x25519Shared(events.bytes[0], &shared);
        const derived = Derived.compute(hello, events.bytes[0], events.bytes[4], &shared);
        const both = derived.client_finished ++ trailing;
        try testing.expectError(error.UnexpectedMessage, harness.server.handleCrypto(.handshake, &both, &harness.out));
        try testing.expectEqual(ServerHandshake.State.failed, harness.server.state);
    }
}
