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
    const key = [_]u8{0x42} ** 16;
    const static_iv = [_]u8{0x24} ** 12;
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
        .x25519_private = @splat(0x77),
        .alpn = "http/1.1",
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
