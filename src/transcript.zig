//! The handshake transcript hash (RFC 8446 §4.4.1).
//!
//! A running hash over every handshake message in order, *including* each
//! message's 4-byte header, *excluding* record framing. The schedule asks
//! for the hash at several points mid-stream, so `currentHash` snapshots a
//! copy instead of finalizing the running state.

const std = @import("std");
const assert = std.debug.assert;

/// A handshake message begins with a 1-byte type and a u24 length.
pub const message_header_bytes: u8 = 4;

pub fn Transcript(comptime Hash: type) type {
    return struct {
        state: Hash,
        messages_seen: u32,

        const Self = @This();

        /// RFC 8446 caps a handshake message body at 2^24-1 by its u24
        /// length; no legitimate flight carries more than a handful of
        /// messages, and the bound turns a feed loop gone wrong into an
        /// assertion instead of silence.
        pub const messages_max: u32 = 32;

        pub const empty: Self = .{ .state = Hash.init(.{}), .messages_seen = 0 };

        /// Absorb one complete handshake message, header included.
        pub fn update(self: *Self, message: []const u8) void {
            assert(message.len >= message_header_bytes);
            assert(message.len < (1 << 24) + @as(usize, message_header_bytes));
            assert(self.messages_seen < messages_max);
            const declared = std.mem.readInt(u24, message[1..4], .big);
            assert(message.len == @as(usize, declared) + message_header_bytes);
            self.state.update(message);
            self.messages_seen += 1;
        }

        /// The hash of everything absorbed so far; the running state is
        /// untouched, so this is callable at every schedule point.
        pub fn currentHash(self: *const Self) [Hash.digest_length]u8 {
            assert(self.messages_seen <= messages_max);
            var snapshot = self.state;
            var digest: [Hash.digest_length]u8 = undefined;
            snapshot.final(&digest);
            return digest;
        }
    };
}

test "empty transcript hashes like the empty string" {
    const Sha256 = std.crypto.hash.sha2.Sha256;
    const transcript: Transcript(Sha256) = .empty;
    var expected: [32]u8 = undefined;
    Sha256.hash(&.{}, &expected, .{});
    try std.testing.expectEqualSlices(u8, &expected, &transcript.currentHash());
}

test "currentHash is a snapshot, not a finalization" {
    const Sha256 = std.crypto.hash.sha2.Sha256;
    const vectors = @import("rfc8448_vectors.zig");
    var transcript: Transcript(Sha256) = .empty;
    transcript.update(&vectors.client_hello);
    const after_hello = transcript.currentHash();
    // A second read answers the same bytes, and the state still advances.
    try std.testing.expectEqualSlices(u8, &after_hello, &transcript.currentHash());
    transcript.update(&vectors.server_hello);
    try std.testing.expect(!std.mem.eql(u8, &after_hello, &transcript.currentHash()));
    try std.testing.expectEqual(@as(u32, 2), transcript.messages_seen);
}
