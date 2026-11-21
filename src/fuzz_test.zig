//! Coverage-guided fuzz targets (slice 5). One property everywhere:
//! parse or reject — no third outcome. Every assertion in the tree is a
//! claim about our own state, so arbitrary peer bytes must only ever
//! produce a value or an error; a fuzzer-reachable panic is precisely
//! the bug class the slice-4 review caught by hand, mechanized.
//!
//! `zig build test` runs each target once over its corpus; `zig build
//! test --fuzz` runs the coverage-guided search.

const std = @import("std");

const ClientHandshake = @import("ClientHandshake.zig");
const Credentials = @import("Credentials.zig");
const ServerHandshake = @import("ServerHandshake.zig");
const alert = @import("alert.zig");
const client_hello = @import("client_hello.zig");
const handshake = @import("handshake.zig");
const pem = @import("pem.zig");
const protect = @import("protect.zig");
const quic = @import("quic.zig");
const record = @import("record.zig");
const record_buffer = @import("record_buffer.zig");
const vectors = @import("rfc8448_vectors.zig");

/// Bridge a plain `[]const u8` target to std.testing.fuzz's Smith
/// interface: draw up to `buffer_bytes` of fuzzer input and hand it over.
fn adapt(
    comptime target: fn ([]const u8) anyerror!void,
    comptime buffer_bytes: usize,
) fn (void, *std.testing.Smith) anyerror!void {
    return struct {
        fn one(_: void, smith: *std.testing.Smith) anyerror!void {
            var buffer: [buffer_bytes]u8 = undefined;
            const input_bytes = smith.slice(&buffer);
            std.debug.assert(input_bytes <= buffer.len);
            try target(buffer[0..input_bytes]);
        }
    }.one;
}

fn fuzzRecordHeader(input: []const u8) !void {
    var header: [record.header_bytes]u8 = @splat(0);
    const take = @min(input.len, header.len);
    @memcpy(header[0..take], input[0..take]);
    const parsed = record.parseHeader(&header) catch return;
    // A header we accepted is one we can re-emit and re-accept, with the
    // same verdict on both passes.
    var reencoded: [record.header_bytes]u8 = undefined;
    record.writeHeader(.{ .content_type = parsed.content_type, .length = parsed.length }, &reencoded);
    const again = try record.parseHeader(&reencoded);
    try std.testing.expectEqual(parsed.content_type, again.content_type);
    try std.testing.expectEqual(parsed.length, again.length);
}

test "fuzz: record header — parse or reject" {
    try std.testing.fuzz({}, adapt(fuzzRecordHeader, 64), .{ .corpus = &.{
        "\x16\x03\x01\x00\xc4",
        "\x17\x03\x03\x41\x00",
        "\x15\x03\x03\x00\x02",
    } });
}

fn fuzzAlert(input: []const u8) !void {
    const parsed = alert.parse(input) catch return;
    _ = parsed.description();
    _ = parsed.isCloseNotify();
}

test "fuzz: alert — parse or reject" {
    try std.testing.fuzz({}, adapt(fuzzAlert, 16), .{ .corpus = &.{ "\x01\x00", "\x02\x28", "\x03\x00" } });
}

fn fuzzClientHello(input: []const u8) !void {
    const hello = client_hello.parse(input) catch return;
    // A hello we accepted must answer every query without incident.
    _ = hello.offersSuite(.aes_128_gcm_sha256);
    _ = hello.offersSuite(.chacha20_poly1305_sha256);
    _ = hello.supportsGroup(client_hello.group_x25519);
    _ = hello.offersScheme(0x0403);
    _ = hello.offersPskDheKe();
    _ = client_hello.parsePskOffer(&hello) catch return;
}

test "fuzz: ClientHello — parse or reject, then answer every query" {
    try std.testing.fuzz({}, adapt(fuzzClientHello, 2048), .{ .corpus = &.{
        &vectors.client_hello,
        &vectors.resumed_client_hello,
    } });
}

fn fuzzAssembler(input: []const u8) !void {
    var storage: [4096]u8 = undefined;
    var assembler = handshake.Assembler.init(&storage);
    var offset: usize = 0;
    var pushes: u16 = 0;
    // Each chunk consumes at least one byte, so the loop is structurally
    // bounded by the input; the counter states it anyway.
    while (offset < input.len) : (pushes += 1) {
        std.debug.assert(pushes <= input.len);
        const chunk_bytes = 1 + @as(usize, input[offset] % 97);
        const end = @min(offset + chunk_bytes, input.len);
        assembler.push(input[offset..end]) catch return;
        var drained: u16 = 0;
        while (assembler.next() catch return) |message| : (drained += 1) {
            std.debug.assert(drained < storage.len / handshake.header_bytes + 1);
            _ = message.messageType();
            _ = message.body();
        }
        offset = end;
    }
}

test "fuzz: handshake assembler — any chunking, no third outcome" {
    try std.testing.fuzz({}, adapt(fuzzAssembler, 4096), .{ .corpus = &.{
        &vectors.server_flight_plaintext,
        "\x14\x00\x00\x20",
    } });
}

fn fuzzRecordBuffer(input: []const u8) !void {
    var storage: [record.wire_record_bytes_max]u8 = undefined;
    var records = record_buffer.RecordBuffer.init(&storage);
    var offset: usize = 0;
    var pushes: u16 = 0;
    while (offset < input.len) : (pushes += 1) {
        std.debug.assert(pushes <= input.len);
        const chunk_bytes = 1 + @as(usize, input[offset] % 251);
        const end = @min(offset + chunk_bytes, input.len);
        records.push(input[offset..end]) catch return;
        var drained: u16 = 0;
        while (records.next() catch return) |one| : (drained += 1) {
            std.debug.assert(drained < storage.len / record.header_bytes + 1);
            std.debug.assert(one.len >= record.header_bytes);
        }
        offset = end;
    }
}

test "fuzz: record buffer — any chunking, headers policed on arrival" {
    try std.testing.fuzz({}, adapt(fuzzRecordBuffer, 17000), .{ .corpus = &.{
        &vectors.server_flight_record,
        &vectors.client_app_record,
    } });
}

fn fuzzPem(input: []const u8) !void {
    var storage: [4096]u8 = undefined;
    var iterator = pem.Iterator.init(input, &storage);
    var blocks: u8 = 0;
    while (iterator.next() catch return) |block| : (blocks += 1) {
        std.debug.assert(blocks < pem.blocks_max);
        std.debug.assert(block.der.len >= 1);
    }
}

test "fuzz: PEM — decode or reject" {
    try std.testing.fuzz({}, adapt(fuzzPem, 4096), .{ .corpus = &.{
        @embedFile("testdata/cert.pem"),
        "-----BEGIN X-----\nAAAA\n-----END X-----\n",
    } });
}

fn fuzzProtectorOpen(input: []const u8) !void {
    const key: [16]u8 = @splat(0x42);
    const static_iv: [12]u8 = @splat(0x24);
    var protector = protect.Protector.init(.aes_128_gcm_sha256, &key, &static_iv) catch return;
    defer protector.deinit();
    var wire: [record.wire_record_bytes_max]u8 = undefined;
    const body_bytes = @min(input.len, record.ciphertext_bytes_max);
    record.writeHeader(
        .{ .content_type = .application_data, .length = @intCast(body_bytes) },
        wire[0..record.header_bytes],
    );
    @memcpy(wire[record.header_bytes..][0..body_bytes], input[0..body_bytes]);
    var out: [record.wire_record_bytes_max]u8 = undefined;
    // Forged ciphertext must fail authentication; the property under
    // fuzz is only that it fails as an error.
    _ = protector.open(wire[0 .. record.header_bytes + body_bytes], &out) catch return;
}

test "fuzz: record protection open — forgeries fail closed" {
    try std.testing.fuzz({}, adapt(fuzzProtectorOpen, 17000), .{ .corpus = &.{
        vectors.server_app_record[record.header_bytes..],
    } });
}

/// RFC 9001 §5.3 from the receiving side: a packet whose first octet
/// says how much of it is header, opened under a key the input never
/// learned. The bytes are a peer's, so the only property is that a
/// forgery — or a packet too short to hold a tag — fails as an error.
fn fuzzPacketOpen(input: []const u8) !void {
    if (input.len == 0) return;
    const suites = [_]@import("cipher_suite.zig").CipherSuite{
        .aes_128_gcm_sha256,
        .aes_256_gcm_sha384,
        .chacha20_poly1305_sha256,
    };
    const suite = suites[input[0] % suites.len];
    const key: [32]u8 = @splat(0x5a);
    var packet_key = quic.PacketKey.init(suite, key[0..suite.keyBytes()], .open) catch return;
    defer packet_key.deinit();
    var buffer: [2048]u8 = undefined;
    const take = @min(input.len - 1, buffer.len);
    @memcpy(buffer[0..take], input[1..][0..take]);
    const header_bytes = @min(take, @as(usize, input[0] >> 2));
    const packet_nonce = quic.nonce(&@as([quic.nonce_bytes]u8, @splat(0x17)), take);
    _ = packet_key.open(&packet_nonce, buffer[0..header_bytes], buffer[header_bytes..take]) catch return;
}

/// A 22-octet header — A.2's shape — ahead of forty octets of ciphertext.
const packet_open_seed = "\x58\xc3".* ++ @as([60]u8, @splat(0));

test "fuzz: QUIC packet open — forgeries and truncations fail closed" {
    try std.testing.fuzz({}, adapt(fuzzPacketOpen, 2049), .{ .corpus = &.{
        &packet_open_seed,
        "\x01",
        "\x02\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff",
    } });
}

var fuzz_chain_storage: [Credentials.chain_bytes_max]u8 = undefined;
/// Loaded once and shared: parsing a key per iteration would spend the
/// fuzzer's budget in libcrypto rather than in our parsers. The lazy
/// init is unsynchronized, which is sound only because the test runner
/// drives targets sequentially — revisit if `--fuzz` ever parallelizes
/// iterations within a target.
var fuzz_credentials: ?Credentials = null;

fn fuzzCredentials() *const Credentials {
    if (fuzz_credentials == null) {
        fuzz_credentials = Credentials.load(
            @embedFile("testdata/cert.pem"),
            @embedFile("testdata/key.pem"),
            &fuzz_chain_storage,
            true,
        ) catch unreachable; // Fixture material, checked by the unit suite.
    }
    return &fuzz_credentials.?;
}

/// Feed arbitrary bytes to a machine as a record stream until the first
/// error. The machines promise error-then-failed, never a panic.
fn feedMachine(machine: anytype, input: []const u8) void {
    var stream_storage: [record.wire_record_bytes_max]u8 = undefined;
    var records = record_buffer.RecordBuffer.init(&stream_storage);
    var out: [record.wire_record_bytes_max]u8 = undefined;
    var offset: usize = 0;
    var pushes: u16 = 0;
    while (offset < input.len) : (pushes += 1) {
        std.debug.assert(pushes <= input.len);
        const end = @min(offset + 512, input.len);
        records.push(input[offset..end]) catch return;
        var drained: u8 = 0;
        while (records.next() catch return) |one| : (drained += 1) {
            // Every record carries a 5-byte header, and a protected one
            // needs a 16-byte tag and a content-type byte besides, so a
            // 512-byte push cannot yield more than ~23 records; 64 is
            // that with room to spare.
            std.debug.assert(drained < 64);
            _ = machine.handleRecord(one, &out) catch return;
        }
        offset = end;
    }
}

fn fuzzServerMachine(input: []const u8) !void {
    var reassembly: [8192]u8 = undefined;
    var flight: [Credentials.chain_bytes_max + 1024]u8 = undefined;
    var server = ServerHandshake.init(&.{
        .credentials = fuzzCredentials(),
        .server_random = @splat(0x5c),
        .key_share_private = @splat(0x77),
        .alpn_protocols = &.{"http/1.1"},
        .reassembly = &reassembly,
        .flight = &flight,
    });
    defer server.deinit();
    feedMachine(&server, input);
}

const client_hello_record = "\x16\x03\x01\x00\xc4".* ++ vectors.client_hello;
const server_hello_record = "\x16\x03\x03\x00\x5a".* ++ vectors.server_hello;
const resumed_hello_record = "\x16\x03\x03\x00\x60".* ++ vectors.resumed_server_hello;

test "fuzz: ServerHandshake — arbitrary records error, never panic" {
    try std.testing.fuzz({}, adapt(fuzzServerMachine, 8192), .{ .corpus = &.{
        &client_hello_record,
        "\x14\x03\x03\x00\x01\x01",
        "\x15\x03\x03\x00\x02\x02\x28",
    } });
}

/// Feed arbitrary bytes to a QUIC-mode machine as CRYPTO data: each
/// chunk is a level byte, a length byte, and that many bytes, which is
/// every way a transport could deliver them — any level, any
/// fragmentation, any order. The property is the TCP one: error, then
/// `failed`, and never a panic.
fn feedCrypto(machine: anytype, input: []const u8) void {
    var out: [ServerHandshake.quic_out_bytes_min]u8 = undefined;
    const levels = [_]quic.Level{ .initial, .handshake, .application };
    var offset: usize = 0;
    var chunks: u16 = 0;
    while (offset + 2 <= input.len) : (chunks += 1) {
        // Each chunk consumes at least its two header bytes.
        std.debug.assert(chunks <= input.len);
        const level = levels[input[offset] % levels.len];
        const end = @min(offset + 2 + input[offset + 1], input.len);
        var event = machine.handleCrypto(level, input[offset + 2 .. end], &out) catch return;
        var drained: u8 = 0;
        while (event) |_| : (drained += 1) {
            // A ClientHello's answer is six events, a Finished's two.
            std.debug.assert(drained < 8);
            event = machine.drainCrypto(&out) catch return;
        }
        offset = end;
    }
}

fn fuzzQuicServerMachine(input: []const u8) !void {
    var reassembly: [8192]u8 = undefined;
    var flight: [ServerHandshake.quic_flight_bytes_min]u8 = undefined;
    var server = ServerHandshake.init(&.{
        .credentials = fuzzCredentials(),
        .server_random = @splat(0x5c),
        .key_share_private = @splat(0x77),
        .alpn_protocols = &.{"h3"},
        .reassembly = &reassembly,
        .flight = &flight,
        .quic = .{ .transport_parameters = "\x04\x02\x40\x80" },
    });
    defer server.deinit();
    feedCrypto(&server, input);
}

/// RFC 8448's ClientHello with RFC 9001's two requirements appended to
/// its extension block — ALPN "h3" and an empty quic_transport_parameters
/// — and both length fields patched. Its session ID is already empty, so
/// the seed is a hello a QUIC server answers, and the search starts from
/// a working handshake rather than from noise.
const quic_client_hello = blk: {
    const extra = [_]u8{ 0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, 'h', '3', 0x00, 0x39, 0x00, 0x00 };
    var hello = vectors.client_hello ++ extra;
    // The u24 message length's low octet, then the u16 extension block's.
    hello[3] += extra.len;
    hello[50] += extra.len;
    break :blk hello;
};

/// One chunk at Initial: a level octet, a length octet, the hello.
const quic_client_hello_seed = [_]u8{ 0x00, quic_client_hello.len } ++ quic_client_hello;

test "the QUIC seed is a hello a QUIC server answers, so the search starts deep" {
    var reassembly: [8192]u8 = undefined;
    var flight: [ServerHandshake.quic_flight_bytes_min]u8 = undefined;
    var server = ServerHandshake.init(&.{
        .credentials = fuzzCredentials(),
        .server_random = @splat(0x5c),
        .key_share_private = @splat(0x77),
        .alpn_protocols = &.{"h3"},
        .reassembly = &reassembly,
        .flight = &flight,
        .quic = .{ .transport_parameters = "\x04\x02\x40\x80" },
    });
    defer server.deinit();
    var out: [ServerHandshake.quic_out_bytes_min]u8 = undefined;
    var events: u8 = 0;
    var event = try server.handleCrypto(.initial, &quic_client_hello, &out);
    while (event) |_| : (event = try server.drainCrypto(&out)) events += 1;
    try std.testing.expectEqual(@as(u8, 6), events);
    try std.testing.expectEqual(ServerHandshake.State.awaiting_finished, server.state);
}

test "fuzz: ServerHandshake QUIC mode — arbitrary CRYPTO bytes error, never panic" {
    try std.testing.fuzz({}, adapt(fuzzQuicServerMachine, 8192), .{ .corpus = &.{
        &quic_client_hello_seed,
        "\x00\x04\x01\x00\x00\xc4",
        "\x01\x04\x14\x00\x00\x20",
        "\x02\x05\x18\x00\x00\x01\x00",
    } });
}

fn fuzzClientMachine(input: []const u8) !void {
    var reassembly: [16384]u8 = undefined;
    var client = ClientHandshake.init(&.{
        .client_random = @splat(0x1a),
        .x25519_private = @splat(0x31),
        .server_name = "spike.zoxy.test",
        .alpn_protocols = &.{"http/1.1"},
        .certificate_policy = .leaf_signature,
        .reassembly = &reassembly,
    });
    defer client.deinit();
    var hello_out: [ClientHandshake.out_bytes_min]u8 = undefined;
    _ = client.start(&hello_out);
    feedMachine(&client, input);
}

test "fuzz: ClientHandshake — arbitrary records error, never panic" {
    try std.testing.fuzz({}, adapt(fuzzClientMachine, 8192), .{ .corpus = &.{
        &server_hello_record,
        &resumed_hello_record,
        "\x14\x03\x03\x00\x01\x01",
    } });
}
