//! Interop with `std.crypto.tls.Client` — an implementation sharing no
//! code with zssl — over an in-memory duplex.
//!
//! This is the strongest oracle in the tree: std's client generates its
//! own ephemeral keys, checks the certificate's self-signature with its
//! own X.509 and ECDSA, verifies our CertificateVerify and Finished with
//! its own schedule, and then trades application bytes. Agreement here is
//! zoxy's Tier-0.5 argument, brought forward into a unit test.

const std = @import("std");
const testing = std.testing;

const Credentials = @import("Credentials.zig");
const ServerHandshake = @import("ServerHandshake.zig");
const record = @import("record.zig");
const record_buffer = @import("record_buffer.zig");

/// The client side of the pipe: std's Writer drains straight into the
/// server machine; std's Reader streams from whatever the server queued.
/// Strictly turn-based, like the protocol itself — the queue is never
/// empty when the client legitimately reads.
const Duplex = struct {
    server: *ServerHandshake,
    reader: std.Io.Reader,
    writer: std.Io.Writer,
    from_client: record_buffer.RecordBuffer,
    to_client: [8 * record.wire_record_bytes_max]u8,
    to_client_start: usize,
    to_client_used: usize,
    from_client_storage: [2 * record.wire_record_bytes_max]u8,
    reader_storage: [2 * record.wire_record_bytes_max]u8,
    writer_storage: [2 * record.wire_record_bytes_max]u8,
    server_out: [2 * record.wire_record_bytes_max]u8,
    application_received: [256]u8,
    application_received_bytes: usize,
    server_connected: bool,
    server_failure: ?anyerror,

    const reader_vtable: std.Io.Reader.VTable = .{ .stream = stream };
    const writer_vtable: std.Io.Writer.VTable = .{ .drain = drain };

    fn setUp(duplex: *Duplex, server: *ServerHandshake) void {
        duplex.server = server;
        duplex.from_client = record_buffer.RecordBuffer.init(&duplex.from_client_storage);
        duplex.to_client_start = 0;
        duplex.to_client_used = 0;
        duplex.application_received_bytes = 0;
        duplex.server_connected = false;
        duplex.server_failure = null;
        duplex.reader = .{ .vtable = &reader_vtable, .buffer = &duplex.reader_storage, .seek = 0, .end = 0 };
        duplex.writer = .{ .vtable = &writer_vtable, .buffer = &duplex.writer_storage, .end = 0 };
    }

    fn enqueue(duplex: *Duplex, bytes: []const u8) void {
        std.debug.assert(bytes.len >= 1);
        if (duplex.to_client.len - duplex.to_client_used < bytes.len) {
            std.mem.copyForwards(
                u8,
                duplex.to_client[0 .. duplex.to_client_used - duplex.to_client_start],
                duplex.to_client[duplex.to_client_start..duplex.to_client_used],
            );
            duplex.to_client_used -= duplex.to_client_start;
            duplex.to_client_start = 0;
        }
        std.debug.assert(duplex.to_client.len - duplex.to_client_used >= bytes.len);
        @memcpy(duplex.to_client[duplex.to_client_used..][0..bytes.len], bytes);
        duplex.to_client_used += bytes.len;
    }

    fn feedServer(duplex: *Duplex, bytes: []const u8) !void {
        if (bytes.len == 0) return;
        try duplex.from_client.push(bytes);
        var records_seen: u8 = 0;
        while (try duplex.from_client.next()) |one| : (records_seen += 1) {
            std.debug.assert(records_seen < 16);
            const event = try duplex.server.handleRecord(one, &duplex.server_out);
            switch (event) {
                .none => {},
                .send => |reply| duplex.enqueue(reply),
                .connected => duplex.server_connected = true,
                .application_data => |plaintext| {
                    const target = duplex.application_received[duplex.application_received_bytes..];
                    std.debug.assert(plaintext.len <= target.len);
                    @memcpy(target[0..plaintext.len], plaintext);
                    duplex.application_received_bytes += plaintext.len;
                },
                .closed => {},
            }
        }
    }

    fn drain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const duplex: *Duplex = @alignCast(@fieldParentPtr("writer", w));
        duplex.feedServer(w.buffer[0..w.end]) catch |err| {
            duplex.server_failure = err;
            return error.WriteFailed;
        };
        w.end = 0;
        var consumed: usize = 0;
        for (data, 0..) |slice, index| {
            const repeats: usize = if (index == data.len - 1) splat else 1;
            var repeat: usize = 0;
            while (repeat < repeats) : (repeat += 1) {
                duplex.feedServer(slice) catch |err| {
                    duplex.server_failure = err;
                    return error.WriteFailed;
                };
            }
            consumed += slice.len * repeats;
        }
        return consumed;
    }

    fn stream(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        const duplex: *Duplex = @alignCast(@fieldParentPtr("reader", r));
        const available = duplex.to_client_used - duplex.to_client_start;
        if (available == 0) return error.EndOfStream;
        const count = limit.minInt(available);
        const written = w.write(duplex.to_client[duplex.to_client_start..][0..count]) catch
            return error.WriteFailed;
        duplex.to_client_start += written;
        return written;
    }
};

test "std.crypto.tls.Client: full handshake and data, no shared code" {
    var chain_storage: [Credentials.chain_bytes_max]u8 = undefined;
    var credentials = try Credentials.load(
        @embedFile("testdata/cert.pem"),
        @embedFile("testdata/key.pem"),
        &chain_storage,
        false,
    );
    defer credentials.deinit();
    var reassembly: [8192]u8 = undefined;
    var flight: [Credentials.chain_bytes_max + 1024]u8 = undefined;
    var server = ServerHandshake.init(&.{
        .credentials = &credentials,
        .server_random = .{0x2f} ** 32,
        .key_share_private = .{0x77} ** 47 ++ .{0x01},
        .reassembly = &reassembly,
        .flight = &flight,
    });
    defer server.deinit();

    var duplex: Duplex = undefined;
    duplex.setUp(&server);

    // Fixed "entropy": fine for a test, and §Config's whole point is that
    // randomness comes from outside the library under test.
    var entropy: [std.crypto.tls.Client.Options.entropy_len]u8 = undefined;
    for (&entropy, 0..) |*byte, index| byte.* = @truncate(index *% 149 + 11);
    var tls_read_buffer: [std.crypto.tls.Client.min_buffer_len + 256]u8 = undefined;
    var tls_write_buffer: [std.crypto.tls.Client.min_buffer_len + 256]u8 = undefined;

    var client = try std.crypto.tls.Client.init(&duplex.reader, &duplex.writer, .{
        .host = .no_verification,
        // .self_signed makes std verify the fixture's own signature with
        // its own X.509 + ECDSA — our Certificate message, checked by a
        // stranger.
        .ca = .self_signed,
        .read_buffer = &tls_read_buffer,
        .write_buffer = &tls_write_buffer,
        .entropy = &entropy,
        // 2026-08-27, inside the fixture's validity window.
        .realtime_now = .fromNanoseconds(1_787_000_000 * std.time.ns_per_s),
    });
    try testing.expectEqual(@as(?anyerror, null), duplex.server_failure);

    // Client → server application data (the flush also delivers the
    // client Finished if init left it buffered).
    try client.writer.writeAll("hello zssl, from std");
    try client.writer.flush();
    // The tls writer seals records into the transport writer's buffer;
    // the transport itself flushes separately, as over a real socket.
    try duplex.writer.flush();
    try testing.expect(duplex.server_connected);
    try testing.expectEqual(ServerHandshake.State.connected, server.state);
    try testing.expectEqualSlices(
        u8,
        "hello zssl, from std",
        duplex.application_received[0..duplex.application_received_bytes],
    );

    // Server → client.
    var send_buffer: [record.wire_record_bytes_max]u8 = undefined;
    const reply = try server.sendApplicationData("zssl greets std", &send_buffer);
    duplex.enqueue(reply);
    // A clean shutdown after the data: std's client reads greedily, and
    // an end-of-stream without close_notify is (rightly) truncation.
    var close_buffer: [record.wire_record_bytes_max]u8 = undefined;
    const close_record = try server.sendClose(&close_buffer);
    duplex.enqueue(close_record);
    var received: [64]u8 = undefined;
    const received_bytes = try client.reader.readSliceShort(&received);
    try testing.expectEqualSlices(u8, "zssl greets std", received[0..received_bytes]);
    try testing.expectEqual(ServerHandshake.State.closed, server.state);
}
