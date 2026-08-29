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

        /// The same hash with `tail` on the end, absorbing nothing.
        ///
        /// §4.2.11.2's binder covers a *truncated* ClientHello — the
        /// message minus its binders section — and that is not a
        /// complete handshake message: its length header still counts
        /// the bytes that were cut. `update` refuses it for exactly that
        /// reason, and rightly, since the truncation must never join the
        /// running state; the whole hello does, later. So this is the
        /// one read that takes an argument.
        ///
        /// On a first ClientHello the caller has nothing absorbed and
        /// this is the truncation's own hash. After a HelloRetryRequest
        /// §4.4.1 has already put message_hash(CH1) and the retry in
        /// front of it, which is the entire difficulty of a binder on a
        /// second hello and is why it is the transcript that answers.
        pub fn hashWith(self: *const Self, tail: []const u8) [Hash.digest_length]u8 {
            assert(self.messages_seen <= messages_max);
            assert(tail.len >= message_header_bytes);
            var snapshot = self.state;
            snapshot.update(tail);
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

test "hashWith covers the prefix and the tail, absorbing neither" {
    const Sha256 = std.crypto.hash.sha2.Sha256;
    const vectors = @import("rfc8448_vectors.zig");
    var transcript: Transcript(Sha256) = .empty;
    // With nothing absorbed it is the tail's own hash — the first
    // ClientHello's binder, where §4.4.1 has added nothing yet.
    var bare: [32]u8 = undefined;
    Sha256.hash(&vectors.client_hello, &bare, .{});
    try std.testing.expectEqualSlices(u8, &bare, &transcript.hashWith(&vectors.client_hello));
    // With a prefix absorbed it is the concatenation's, and the state is
    // where it was: a second read answers the same bytes.
    transcript.update(&vectors.client_hello);
    const with_prefix = transcript.hashWith(&vectors.server_hello);
    try std.testing.expectEqualSlices(u8, &with_prefix, &transcript.hashWith(&vectors.server_hello));
    try std.testing.expectEqual(@as(u32, 1), transcript.messages_seen);
    // And it equals absorbing the tail for real, which is the property
    // the binder depends on: the server hashes the same bytes the client
    // did, one having absorbed them and the other not.
    transcript.update(&vectors.server_hello);
    try std.testing.expectEqualSlices(u8, &with_prefix, &transcript.currentHash());
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
