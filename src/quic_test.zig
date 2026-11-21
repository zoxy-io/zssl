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
