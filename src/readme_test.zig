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

test "README: terminating TLS" {
    const socket: Socket = .{};
    const cert_pem = @embedFile("testdata/cert.pem");
    const key_pem = @embedFile("testdata/key.pem");

    var chain_storage: [zssl.Credentials.chain_bytes_max]u8 = undefined;
    var credentials = try zssl.Credentials.load(cert_pem, key_pem, &chain_storage, false);
    defer credentials.deinit();

    var reassembly: [16 * 1024]u8 = undefined;
    var flight: [zssl.Credentials.chain_bytes_max + 1024]u8 = undefined;

    var entropy: [64]u8 = undefined;
    std.testing.io.random(&entropy);

    var server = zssl.ServerHandshake.init(&.{
        .credentials = &credentials,
        .server_random = entropy[0..32].*,
        .x25519_private = entropy[32..64].*,
        .alpn = "http/1.1",
        .reassembly = &reassembly,
        .flight = &flight,
    });
    defer server.deinit();

    var out: [zssl.ServerHandshake.out_bytes_min]u8 = undefined;
    var storage: [zssl.record.wire_record_bytes_max]u8 = undefined;
    var records = zssl.record_buffer.RecordBuffer.init(&storage);
    // The README's loop verbatim. Nothing has been pushed, so it runs
    // zero times; the point here is that it typechecks.
    while (try records.next()) |wire_record| {
        switch (try server.handleRecord(wire_record, &out)) {
            .send => |bytes| try socket.writeAll(bytes),
            .connected => {},
            .application_data => |plaintext| try onRequest(plaintext),
            .closed => break,
            .none => {},
        }
    }
}

test "README: originating TLS" {
    const socket: Socket = .{};
    var entropy: [64]u8 = undefined;
    std.testing.io.random(&entropy);
    var out: [zssl.ClientHandshake.out_bytes_min]u8 = undefined;

    var reassembly: [16 * 1024]u8 = undefined;
    var client = zssl.ClientHandshake.init(&.{
        .client_random = entropy[0..32].*,
        .x25519_private = entropy[32..64].*,
        .server_name = "origin.internal",
        .alpn = "http/1.1",
        .certificate_policy = .ecdsa_leaf_signature,
        .reassembly = &reassembly,
    });
    defer client.deinit();

    try socket.writeAll(client.start(&out));

    var storage: [zssl.record.wire_record_bytes_max]u8 = undefined;
    var records = zssl.record_buffer.RecordBuffer.init(&storage);
    while (try records.next()) |wire_record| {
        switch (try client.handleRecord(wire_record, &out)) {
            .send, .connected => |bytes| try socket.writeAll(bytes),
            .application_data => |plaintext| try onResponse(plaintext),
            .ticket => |ticket| try store(ticket),
            .closed => break,
            .none => {},
        }
    }
}
