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
///
/// This is not the limit that stops a KeyUpdate flood; `flood.Guard`
/// does that, 32 consecutive updates in. A connection reaches this one
/// only by rotating legitimately, interleaved with real traffic, tens of
/// thousands of times — which is why exhausting it is our budget ending
/// rather than the peer misbehaving, and why the two carry different
/// errors and different alerts.
pub const rotations_max: u32 = 1 << 16;

pub const Error = protect.Error || error{
    /// No further generation can be derived: `rotations_max` is spent.
    /// Named for the budget rather than for the peer, beside
    /// `protect.Error.SequenceExhausted`, because an embedder reading
    /// this has run out of room and has not been attacked.
    RotationsExhausted,
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
        /// Whether a KeyUpdate we sent in answer to an update_requested
        /// is still the most recent thing on our write side — that is,
        /// whether it still precedes our next application record. While
        /// it does, §4.6.3 is satisfied and a further request needs no
        /// further answer. Cleared by `sealApplicationData`.
        answered_update_request: bool,

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
                .answered_update_request = false,
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
            if (self.rotations == rotations_max) return error.RotationsExhausted;
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
            // §4.6.3 ties the obligation to the *next application record*,
            // not to each request: "the receiver MUST send a KeyUpdate of
            // its own ... prior to sending its next Application Data
            // record." One answer therefore discharges a whole run of
            // requests that arrive with no application data between them,
            // because that one answer still precedes whatever we send
            // next. Answering each of them instead would put KeyUpdates
            // on the wire the peer never asked for, which is what BoGo's
            // `KeyUpdate-Requested` refuses — its runner sends five and
            // says in as many words that "the shim should respond only
            // once". Returning before any rotation matters: rotating our
            // transmit side without telling the peer would desynchronise
            // the very keys this message exists to agree on.
            if (self.answered_update_request) return null;
            var message_buffer: [8]u8 = undefined;
            const response = @import("server_messages.zig").keyUpdate(&message_buffer, false);
            const sealed = try self.send.seal(.handshake, response, out);
            try self.rotateTransmit();
            self.answered_update_request = true;
            return sealed;
        }

        /// Application data, and the moment §4.6.3's obligation is
        /// discharged: any KeyUpdate we owed has now preceded an
        /// application record, so the next request needs its own answer.
        /// Sealing goes through here rather than through `send` directly
        /// so that the flag cannot be left behind by a caller who forgot
        /// it — there is one way to send application data.
        pub fn sealApplicationData(self: *Self, bytes: []const u8, out: []u8) Error![]const u8 {
            assert(bytes.len <= record.plaintext_bytes_max);
            const sealed = try self.send.seal(.application_data, bytes, out);
            self.answered_update_request = false;
            assert(!self.answered_update_request);
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
    try std.testing.expectError(error.RotationsExhausted, keys.rotateTransmit());
}

test "§4.6.3: a run of update requests is answered once, until application data" {
    const Keys = SessionKeys(.aes_128_gcm_sha256);
    const secret = [_]u8{0x22} ** 32;
    var keys = try Keys.init(&secret, &secret);
    defer keys.deinit();
    var out: [record.wire_record_bytes_max]u8 = undefined;

    // update_requested. The first is answered.
    const answer = (try keys.processKeyUpdate(&.{1}, &out)) orelse
        return error.TestExpectedResponse;
    try std.testing.expect(answer.len > 0);
    try std.testing.expect(keys.answered_update_request);

    // Four more with nothing sent between them. §4.6.3 asks for a
    // KeyUpdate "prior to sending its next Application Data record", and
    // the first answer still is — so these need no answer of their own,
    // and answering them would put KeyUpdates on the wire the peer never
    // requested.
    const rotations_after_first = keys.rotations;
    for (0..4) |_| {
        try std.testing.expectEqual(
            @as(?[]const u8, null),
            try keys.processKeyUpdate(&.{1}, &out),
        );
    }
    // Our receive side still rotated once per message — those are the
    // peer's generations and have nothing to do with our answer.
    try std.testing.expectEqual(rotations_after_first + 4, keys.rotations);

    // Application data discharges it: our answer no longer precedes what
    // we send next, so the following request needs its own.
    _ = try keys.sealApplicationData("hello", &out);
    try std.testing.expect(!keys.answered_update_request);
    try std.testing.expect((try keys.processKeyUpdate(&.{1}, &out)) != null);
    try std.testing.expect(keys.answered_update_request);
}

test "§4.6.3: update_not_requested is never answered, and clears nothing" {
    const Keys = SessionKeys(.aes_128_gcm_sha256);
    const secret = [_]u8{0x33} ** 32;
    var keys = try Keys.init(&secret, &secret);
    defer keys.deinit();
    var out: [record.wire_record_bytes_max]u8 = undefined;

    try std.testing.expectEqual(
        @as(?[]const u8, null),
        try keys.processKeyUpdate(&.{0}, &out),
    );
    try std.testing.expect(!keys.answered_update_request);
    // And one that does ask still gets its answer afterwards.
    try std.testing.expect((try keys.processKeyUpdate(&.{1}, &out)) != null);
}
