//! Minimal PEM armor decoding (RFC 7468): labeled base64 blocks to DER,
//! into caller-owned storage. Enough to read a certificate chain and
//! nothing more — key PEM goes to libcrypto whole, and writing PEM is a
//! job nobody here has.

const std = @import("std");
const assert = std.debug.assert;

pub const Error = error{ MalformedPem, BufferTooSmall };

/// A chain file is a handful of certificates; past this is not a chain.
pub const blocks_max: u8 = 8;

pub const Block = struct {
    label: []const u8,
    der: []const u8,
};

const begin_marker = "-----BEGIN ";
const end_marker = "-----END ";
const marker_tail = "-----";

pub const Iterator = struct {
    rest: []const u8,
    storage: []u8,
    storage_used: usize,
    blocks_seen: u8,

    pub fn init(pem: []const u8, storage: []u8) Iterator {
        assert(storage.len >= 1);
        return .{ .rest = pem, .storage = storage, .storage_used = 0, .blocks_seen = 0 };
    }

    /// The next armored block, decoded into storage. Returns null when no
    /// BEGIN marker remains; text outside markers (comments, whitespace)
    /// is skipped, matching what every PEM consumer tolerates.
    pub fn next(self: *Iterator) Error!?Block {
        assert(self.blocks_seen <= blocks_max);
        if (self.blocks_seen == blocks_max) return error.MalformedPem;
        const begin_at = std.mem.indexOf(u8, self.rest, begin_marker) orelse return null;
        const after_begin = self.rest[begin_at + begin_marker.len ..];
        const label_end = std.mem.indexOf(u8, after_begin, marker_tail) orelse
            return error.MalformedPem;
        const label = after_begin[0..label_end];
        if (label.len == 0) return error.MalformedPem;

        const body_start = after_begin[label_end + marker_tail.len ..];
        const end_at = std.mem.indexOf(u8, body_start, end_marker) orelse
            return error.MalformedPem;
        const base64_body = body_start[0..end_at];
        self.rest = body_start[end_at + end_marker.len ..];
        self.blocks_seen += 1;

        const decoder = std.base64.Base64DecoderWithIgnore.init(
            std.base64.standard_alphabet_chars,
            '=',
            " \t\r\n",
        );
        const bound = decoder.calcSizeUpperBound(base64_body.len);
        if (bound > self.storage.len - self.storage_used) return error.BufferTooSmall;
        const target = self.storage[self.storage_used..];
        const der_bytes = decoder.decode(target, base64_body) catch
            return error.MalformedPem;
        if (der_bytes == 0) return error.MalformedPem;
        self.storage_used += der_bytes;
        assert(self.storage_used <= self.storage.len);
        return .{ .label = label, .der = target[0..der_bytes] };
    }
};

test "decodes the fixture chain and stops cleanly" {
    const cert_pem = @embedFile("testdata/cert.pem");
    var storage: [4096]u8 = undefined;
    var iterator = Iterator.init(cert_pem, &storage);
    const block = (try iterator.next()).?;
    try std.testing.expectEqualSlices(u8, "CERTIFICATE", block.label);
    // DER SEQUENCE tag: every certificate starts 0x30.
    try std.testing.expectEqual(@as(u8, 0x30), block.der[0]);
    try std.testing.expectEqual(@as(?Block, null), try iterator.next());
}

test "armor without an END marker is malformed, not a crash" {
    var storage: [64]u8 = undefined;
    var iterator = Iterator.init("-----BEGIN THING-----\nAAAA\n", &storage);
    try std.testing.expectError(error.MalformedPem, iterator.next());
    var empty_label = Iterator.init("-----BEGIN -----\nAAAA\n-----END -----\n", &storage);
    try std.testing.expectError(error.MalformedPem, empty_label.next());
}
