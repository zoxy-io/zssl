//! Post-handshake connection keys, shared by both machines: the live
//! application traffic secrets, the protectors under them, §4.6.3 key
//! rotation, and the kTLS export view. Written once here because a
//! KeyUpdate implemented twice is a KeyUpdate that diverges.

const std = @import("std");
const assert = std.debug.assert;

const cipher_suite = @import("cipher_suite.zig");
const key_schedule = @import("key_schedule.zig");
const ktls = @import("ktls.zig");
const protect = @import("protect.zig");
const record = @import("record.zig");
const CipherSuite = cipher_suite.CipherSuite;

pub const Direction = enum { transmit, receive };

/// A generous ceiling on generations per connection: each rotation resets
/// the record sequence space, so nothing legitimate approaches this — but
/// a peer requesting updates in a loop must hit a wall, not a spin.
pub const rotations_max: u32 = 1 << 16;

pub const Error = protect.Error || error{
    TooManyKeyUpdates,
    /// A KeyUpdate whose body breaks §4.6.3's one-byte grammar.
    IllegalKeyUpdate,
};

pub fn SessionKeys(comptime suite: CipherSuite) type {
    const Schedule = key_schedule.KeySchedule(suite);
    const hash_bytes = CipherSuite.HashType(suite).digest_length;

    return struct {
        transmit_secret: [hash_bytes]u8,
        receive_secret: [hash_bytes]u8,
        transmit_keys: Schedule.TrafficKeys,
        receive_keys: Schedule.TrafficKeys,
        send: protect.Protector,
        recv: protect.Protector,
        rotations: u32,

        const Self = @This();

        pub fn init(
            transmit_secret: *const [hash_bytes]u8,
            receive_secret: *const [hash_bytes]u8,
        ) Error!Self {
            assert(!std.mem.allEqual(u8, transmit_secret, 0));
            assert(!std.mem.allEqual(u8, receive_secret, 0));
            var keys: Self = .{
                .transmit_secret = transmit_secret.*,
                .receive_secret = receive_secret.*,
                .transmit_keys = Schedule.trafficKeys(transmit_secret),
                .receive_keys = Schedule.trafficKeys(receive_secret),
                .send = undefined,
                .recv = undefined,
                .rotations = 0,
            };
            keys.send = try protect.Protector.init(suite, &keys.transmit_keys.key, &keys.transmit_keys.iv);
            errdefer keys.send.deinit();
            keys.recv = try protect.Protector.init(suite, &keys.receive_keys.key, &keys.receive_keys.iv);
            return keys;
        }

        pub fn deinit(self: *Self) void {
            assert(self.rotations <= rotations_max);
            self.send.deinit();
            self.recv.deinit();
            std.crypto.secureZero(u8, &self.transmit_secret);
            std.crypto.secureZero(u8, &self.receive_secret);
            std.crypto.secureZero(u8, std.mem.asBytes(&self.transmit_keys));
            std.crypto.secureZero(u8, std.mem.asBytes(&self.receive_keys));
            self.* = undefined;
        }

        /// §7.2: application_traffic_secret_N+1, with fresh keys and a
        /// protector whose sequence restarts at zero.
        fn rotate(
            self: *Self,
            secret: *[hash_bytes]u8,
            keys: *Schedule.TrafficKeys,
            protector: *protect.Protector,
        ) Error!void {
            assert(!std.mem.allEqual(u8, secret, 0));
            assert(protector.sequence <= protect.records_per_key_max);
            if (self.rotations == rotations_max) return error.TooManyKeyUpdates;
            self.rotations += 1;
            var next: [hash_bytes]u8 = undefined;
            @import("hkdf.zig").Hkdf(CipherSuite.HashType(suite)).expandLabel(secret, "traffic upd", &.{}, &next);
            std.crypto.secureZero(u8, secret);
            secret.* = next;
            std.crypto.secureZero(u8, &next);
            keys.* = Schedule.trafficKeys(secret);
            protector.deinit();
            protector.* = try protect.Protector.init(suite, &keys.key, &keys.iv);
            assert(protector.sequence == 0);
        }

        /// The sender of a KeyUpdate rotates its own transmit side after
        /// the update message goes out (§4.6.3).
        pub fn rotateTransmit(self: *Self) Error!void {
            assert(!std.mem.allEqual(u8, &self.transmit_secret, 0));
            return self.rotate(&self.transmit_secret, &self.transmit_keys, &self.send);
        }

        /// The receiver of a KeyUpdate rotates its receive side on
        /// processing it (§4.6.3).
        pub fn rotateReceive(self: *Self) Error!void {
            assert(!std.mem.allEqual(u8, &self.receive_secret, 0));
            return self.rotate(&self.receive_secret, &self.receive_keys, &self.recv);
        }

        /// §4.6.3, receive side: rotate our receive keys on the peer's
        /// KeyUpdate; when it requested an update back, the response goes
        /// out under the *current* transmit generation and transmit
        /// rotates after — returned sealed, or null when no response is
        /// due. Identical for both roles, which is why it lives here.
        pub fn processKeyUpdate(self: *Self, body: []const u8, out: []u8) Error!?[]const u8 {
            assert(out.len >= record.wire_record_bytes_max);
            if (body.len != 1) return error.IllegalKeyUpdate;
            const request_update = switch (body[0]) {
                0 => false,
                1 => true,
                else => return error.IllegalKeyUpdate,
            };
            const generations_before = self.rotations;
            try self.rotateReceive();
            assert(self.rotations == generations_before + 1);
            if (!request_update) return null;
            var message_buffer: [8]u8 = undefined;
            const response = @import("server_messages.zig").keyUpdate(&message_buffer, false);
            const sealed = try self.send.seal(.handshake, response, out);
            try self.rotateTransmit();
            return sealed;
        }

        /// §4.6.3, send side: emit a KeyUpdate under the current keys,
        /// then move our transmit side to the next generation.
        pub fn initiateKeyUpdate(self: *Self, request_update: bool, out: []u8) Error![]const u8 {
            assert(self.rotations <= rotations_max);
            var message_buffer: [8]u8 = undefined;
            const message = @import("server_messages.zig").keyUpdate(&message_buffer, request_update);
            const sealed = try self.send.seal(.handshake, message, out);
            try self.rotateTransmit();
            return sealed;
        }

        /// The kTLS hand-over view of one direction: key, static IV, and
        /// the next record sequence, current as of this generation.
        pub fn exportMaterial(self: *const Self, direction: Direction) ktls.KeyMaterial {
            const keys = switch (direction) {
                .transmit => &self.transmit_keys,
                .receive => &self.receive_keys,
            };
            const protector = switch (direction) {
                .transmit => &self.send,
                .receive => &self.recv,
            };
            assert(protector.sequence < protect.records_per_key_max);
            var material: ktls.KeyMaterial = .{
                .suite = suite,
                .key = undefined,
                .key_bytes = comptime suite.keyBytes(),
                .static_iv = keys.iv,
                .next_sequence = protector.sequence,
            };
            @memset(&material.key, 0);
            @memcpy(material.key[0..keys.key.len], &keys.key);
            return material;
        }
    };
}

test "rotation changes both key material and generation, deterministically" {
    const Keys = SessionKeys(.aes_128_gcm_sha256);
    const transmit_secret = [_]u8{0x42} ** 32;
    const receive_secret = [_]u8{0x24} ** 32;
    var ours = try Keys.init(&transmit_secret, &receive_secret);
    defer ours.deinit();
    var theirs = try Keys.init(&receive_secret, &transmit_secret);
    defer theirs.deinit();

    const before = ours.exportMaterial(.transmit);
    try ours.rotateTransmit();
    try theirs.rotateReceive();
    const after = ours.exportMaterial(.transmit);
    // The generations differ, and both sides land on the same next keys.
    try std.testing.expect(!std.mem.eql(u8, before.key[0..16], after.key[0..16]));
    const their_view = theirs.exportMaterial(.receive);
    try std.testing.expectEqualSlices(u8, after.key[0..16], their_view.key[0..16]);
    try std.testing.expectEqualSlices(u8, &after.static_iv, &their_view.static_iv);
    try std.testing.expectEqual(@as(u32, 1), ours.rotations);

    // A record sealed under generation 1 opens under generation 1.
    var wire: [record.wire_record_bytes_max]u8 = undefined;
    var out: [record.wire_record_bytes_max]u8 = undefined;
    const sealed = try ours.send.seal(.application_data, "post-rotation", &wire);
    const opened = try theirs.recv.open(sealed, &out);
    try std.testing.expectEqualSlices(u8, "post-rotation", out[0..opened.plaintext_bytes]);
}

test "the rotation ceiling is an error, not a spin" {
    const Keys = SessionKeys(.aes_128_gcm_sha256);
    const secret = [_]u8{0x11} ** 32;
    var keys = try Keys.init(&secret, &secret);
    defer keys.deinit();
    keys.rotations = rotations_max;
    try std.testing.expectError(error.TooManyKeyUpdates, keys.rotateTransmit());
}
