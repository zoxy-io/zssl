//! The README's usage examples, compiled.
//!
//! A README example that does not compile is worse than none: it is read
//! as documentation and discovered as a lie. These are the same snippets,
//! wrapped in just enough scaffolding to typecheck against the real API.
//! Change one and change the other.
//!
//! The one substitution: the README writes `io.random(&entropy)` for the
//! embedder's own `Io`, and these use `std.testing.io`, which is the
//! same call on the interface a test can reach.

const std = @import("std");
const zssl = @import("root.zig");

/// Stand-in for the embedder's socket and stream framing.
const Socket = struct {
    fn writeAll(_: Socket, bytes: []const u8) !void {
        std.debug.assert(bytes.len >= 1);
    }
};

fn onRequest(plaintext: []const u8) !void {
    std.debug.assert(plaintext.len <= zssl.record.plaintext_bytes_max);
}

fn onResponse(plaintext: []const u8) !void {
    std.debug.assert(plaintext.len <= zssl.record.plaintext_bytes_max);
}

fn store(ticket: zssl.ClientHandshake.Ticket) !void {
    std.debug.assert(ticket.ticket.len >= 1);
}

/// Stand-in for the embedder's trust store, and the chain check the
/// README hands to `chain_verifier`. Real ones build the chain and match
/// the name; this one only has to typecheck as one.
const TrustStore = struct { checked: usize = 0 };
var trust: TrustStore = .{};

fn yourChainCheck(context: *anyopaque, chain: zssl.certificate_list.CertificateList) bool {
    const store_ptr: *TrustStore = @ptrCast(@alignCast(context));
    var it = chain.iterator();
    while (it.next() catch return false) |_| store_ptr.checked += 1;
    return true;
}

test "README: terminating TLS" {
    const socket: Socket = .{};
    const cert_pem = @embedFile("testdata/cert.pem");
    const key_pem = @embedFile("testdata/key.pem");

    var chain_storage: [zssl.Credentials.chain_bytes_max]u8 = undefined;
    var credentials = try zssl.Credentials.load(cert_pem, key_pem, &chain_storage, false);
    defer credentials.deinit();

    var reassembly: [16 * 1024]u8 = undefined;
    var flight: [zssl.Credentials.chain_bytes_max + 1024]u8 = undefined;

    var entropy: [80]u8 = undefined;
    std.testing.io.random(&entropy);

    var server = zssl.ServerHandshake.init(&.{
        .credentials = &credentials,
        .server_random = entropy[0..32].*,
        .key_share_private = entropy[32..80].*,
        .alpn_protocols = &.{"http/1.1"},
        .reassembly = &reassembly,
        .flight = &flight,
    });
    defer server.deinit();

    var out: [zssl.ServerHandshake.out_bytes_min]u8 = undefined;
    var storage: [zssl.record.wire_record_bytes_max]u8 = undefined;
    var records = zssl.record_buffer.RecordBuffer.init(&storage);
    // The README's loop verbatim. Nothing has been pushed, so it runs
    // zero times; the point here is that it typechecks.
    stream: while (try records.next()) |wire_record| {
        var event = try server.handleRecord(wire_record, &out);
        while (event) |ready| : (event = try server.drain(&out)) {
            switch (ready) {
                .send => |bytes| try socket.writeAll(bytes),
                .connected => {},
                .application_data => |plaintext| try onRequest(plaintext),
                .early_data => return error.NoEarlyDataProfile,
                .closed => break :stream,
            }
        }
    }
}

test "README: originating TLS" {
    const socket: Socket = .{};
    var entropy: [80]u8 = undefined;
    std.testing.io.random(&entropy);
    var out: [zssl.ClientHandshake.out_bytes_min]u8 = undefined;

    var reassembly: [16 * 1024]u8 = undefined;
    var client = zssl.ClientHandshake.init(&.{
        .client_random = entropy[0..32].*,
        .x25519_private = entropy[32..64].*,
        .server_name = "origin.internal",
        .alpn_protocols = &.{ "h2", "http/1.1" },
        .certificate_policy = .leaf_signature,
        .chain_verifier = .{ .context = &trust, .verify = &yourChainCheck },
        .reassembly = &reassembly,
    });
    defer client.deinit();

    try socket.writeAll(client.start(&out));

    var storage: [zssl.record.wire_record_bytes_max]u8 = undefined;
    var records = zssl.record_buffer.RecordBuffer.init(&storage);
    stream: while (try records.next()) |wire_record| {
        var event = try client.handleRecord(wire_record, &out);
        while (event) |ready| : (event = try client.drain(&out)) {
            switch (ready) {
                .send, .connected => |bytes| try socket.writeAll(bytes),
                .application_data => |plaintext| try onResponse(plaintext),
                .ticket => |ticket| try store(ticket),
                .closed => break :stream,
            }
        }
    }
}

/// Stand-in for a QUIC transport's connection — h3's seam, shaped in
/// zssl's own vocabulary so the README's QUIC loop typechecks against
/// the real event types. Its CRYPTO stream starts empty.
const Connection = struct {
    received: []const u8 = &.{},
    confirmed: bool = false,

    fn cryptoOut(connection: *const Connection, level: zssl.quic.Level) []const u8 {
        std.debug.assert(level == .initial);
        return connection.received;
    }

    fn cryptoConsumed(connection: *Connection, level: zssl.quic.Level, octets: usize) void {
        std.debug.assert(level == .initial);
        connection.received = connection.received[octets..];
    }

    fn cryptoIn(_: *Connection, level: zssl.quic.Level, bytes: []const u8) !void {
        std.debug.assert(level != .initial or bytes.len >= 4);
    }

    fn installSecret(
        _: *Connection,
        level: zssl.quic.Level,
        direction: zssl.quic.Direction,
        secret: []const u8,
        suite: zssl.cipher_suite.CipherSuite,
    ) !void {
        std.debug.assert(level != .initial);
        _ = direction;
        std.debug.assert(secret.len == suite.hashBytes());
    }

    fn transportParametersIn(_: *Connection, body: []const u8) !void {
        std.debug.assert(body.len <= std.math.maxInt(u16));
    }

    fn confirmHandshake(connection: *Connection) void {
        connection.confirmed = true;
    }
};

test "README: QUIC" {
    const cert_pem = @embedFile("testdata/cert.pem");
    const key_pem = @embedFile("testdata/key.pem");
    var chain_storage: [zssl.Credentials.chain_bytes_max]u8 = undefined;
    var credentials = try zssl.Credentials.load(cert_pem, key_pem, &chain_storage, false);
    defer credentials.deinit();
    var reassembly: [16 * 1024]u8 = undefined;
    var entropy: [80]u8 = undefined;
    std.testing.io.random(&entropy);
    const transport_parameters = "\x04\x04\x80\x10\x00\x00";
    var connection: Connection = .{};
    const level: zssl.quic.Level = .initial;

    var flight: [zssl.ServerHandshake.quic_flight_bytes_min]u8 = undefined;
    var server = zssl.ServerHandshake.init(&.{
        .credentials = &credentials,
        .server_random = entropy[0..32].*,
        .key_share_private = entropy[32..80].*,
        .alpn_protocols = &.{"h3"}, // §8.1: mandatory over QUIC
        .reassembly = &reassembly,
        .flight = &flight,
        // §8.2: your transport's encoding, carried opaque.
        .quic = .{ .transport_parameters = transport_parameters },
    });
    defer server.deinit();

    var out: [zssl.ServerHandshake.quic_out_bytes_min]u8 = undefined;
    const bytes = connection.cryptoOut(level);
    var event = try server.handleCrypto(level, bytes, &out);
    connection.cryptoConsumed(level, bytes.len);
    while (event) |ready| : (event = try server.drainCrypto(&out)) {
        switch (ready) {
            .crypto => |crypto| try connection.cryptoIn(crypto.level, crypto.bytes),
            .secret => |secret| try connection.installSecret(secret.level, secret.direction, secret.bytes, secret.suite),
            .transport_parameters => |body| try connection.transportParametersIn(body),
            .connected => connection.confirmHandshake(),
        }
    }
    try std.testing.expect(!connection.confirmed);
}
