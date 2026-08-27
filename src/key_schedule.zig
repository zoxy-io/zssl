//! The TLS 1.3 key schedule (RFC 8446 §7.1-§7.3).
//!
//! One secret at a time: the schedule is a strict three-stage ladder
//! (early → handshake → master) and the type carries the stage so a
//! derivation against the wrong rung is an assertion failure, not a subtly
//! wrong key. Everything is fixed-size and caller-owned; the only heap in
//! sight is the one this module never touches.

const std = @import("std");
const assert = std.debug.assert;

const cipher_suite = @import("cipher_suite.zig");
const hkdf = @import("hkdf.zig");
const CipherSuite = cipher_suite.CipherSuite;

pub fn KeySchedule(comptime suite: CipherSuite) type {
    const Hash = CipherSuite.HashType(suite);
    const Kdf = hkdf.Hkdf(Hash);
    const hash_bytes = Hash.digest_length;
    const key_bytes = comptime suite.keyBytes();

    return struct {
        stage: Stage,
        secret: [hash_bytes]u8,

        const Self = @This();

        pub const Stage = enum(u8) { early, handshake, master, wiped };

        /// One direction's record-protection material (RFC 8446 §7.3).
        pub const TrafficKeys = struct {
            key: [key_bytes]u8,
            iv: [cipher_suite.nonce_bytes]u8,
        };

        /// Extract the early secret. A resumption PSK is exactly one hash
        /// long; absent a PSK the ikm is that many zero bytes (§7.1).
        pub fn initEarly(psk: ?[]const u8) Self {
            if (psk) |bytes| assert(bytes.len == hash_bytes);
            const zeros = [_]u8{0} ** hash_bytes;
            const ikm = psk orelse &zeros;
            const schedule: Self = .{ .stage = .early, .secret = Kdf.extract(&.{}, ikm) };
            assert(!std.mem.allEqual(u8, &schedule.secret, 0));
            return schedule;
        }

        /// early → handshake: mix in the (EC)DHE shared secret (§7.1).
        pub fn advanceToHandshake(self: *Self, ecdhe_shared: []const u8) void {
            assert(self.stage == .early);
            assert(ecdhe_shared.len == 32 or ecdhe_shared.len == 48);
            const derived = self.deriveSecret("derived", &emptyTranscriptHash());
            self.secret = Kdf.extract(&derived, ecdhe_shared);
            self.stage = .handshake;
            assert(!std.mem.allEqual(u8, &self.secret, 0));
        }

        /// handshake → master: the final extract takes zero ikm (§7.1).
        pub fn advanceToMaster(self: *Self) void {
            assert(self.stage == .handshake);
            const derived = self.deriveSecret("derived", &emptyTranscriptHash());
            const zeros = [_]u8{0} ** hash_bytes;
            self.secret = Kdf.extract(&derived, &zeros);
            self.stage = .master;
            assert(!std.mem.allEqual(u8, &self.secret, 0));
        }

        /// Derive-Secret(current, label, transcript-hash) — §7.1. The
        /// caller names the rung it believes it is on, so a schedule driven
        /// out of order fails here rather than at the peer.
        pub fn deriveAt(
            self: *const Self,
            expected_stage: Stage,
            label: []const u8,
            transcript_hash: *const [hash_bytes]u8,
        ) [hash_bytes]u8 {
            assert(self.stage == expected_stage);
            return self.deriveSecret(label, transcript_hash);
        }

        fn deriveSecret(
            self: *const Self,
            label: []const u8,
            transcript_hash: *const [hash_bytes]u8,
        ) [hash_bytes]u8 {
            assert(label.len >= 1);
            assert(label.len <= hkdf.label_bytes_max);
            var out: [hash_bytes]u8 = undefined;
            Kdf.expandLabel(&self.secret, label, transcript_hash, &out);
            return out;
        }

        /// Traffic secret → write key and IV (§7.3).
        pub fn trafficKeys(traffic_secret: *const [hash_bytes]u8) TrafficKeys {
            assert(!std.mem.allEqual(u8, traffic_secret, 0));
            var keys: TrafficKeys = undefined;
            Kdf.expandLabel(traffic_secret, "key", &.{}, &keys.key);
            Kdf.expandLabel(traffic_secret, "iv", &.{}, &keys.iv);
            assert(!std.mem.allEqual(u8, &keys.iv, 0));
            return keys;
        }

        /// Base-key → finished_key (§4.4.4).
        pub fn finishedKey(base_secret: *const [hash_bytes]u8) [hash_bytes]u8 {
            assert(!std.mem.allEqual(u8, base_secret, 0));
            var out: [hash_bytes]u8 = undefined;
            Kdf.expandLabel(base_secret, "finished", &.{}, &out);
            return out;
        }

        /// Finished.verify_data = HMAC(finished_key, transcript-hash) (§4.4.4).
        pub fn verifyData(
            finished_key: *const [hash_bytes]u8,
            transcript_hash: *const [hash_bytes]u8,
        ) [hash_bytes]u8 {
            assert(!std.mem.allEqual(u8, finished_key, 0));
            var out: [hash_bytes]u8 = undefined;
            std.crypto.auth.hmac.Hmac(Hash).create(&out, transcript_hash, finished_key);
            return out;
        }

        /// §4.2.11.2: the PSK binder — binder_key off the early secret,
        /// its finished key, and the HMAC over the truncated-ClientHello
        /// transcript hash. Only meaningful while the schedule stands at
        /// early, before the (EC)DHE mix.
        pub fn resumptionBinder(
            self: *const Self,
            truncated_hash: *const [hash_bytes]u8,
        ) [hash_bytes]u8 {
            assert(self.stage == .early);
            assert(!std.mem.allEqual(u8, &self.secret, 0));
            var empty_hash: [hash_bytes]u8 = undefined;
            Hash.hash(&.{}, &empty_hash, .{});
            const binder_key = self.deriveSecret("res binder", &empty_hash);
            const binder_finished_key = finishedKey(&binder_key);
            return verifyData(&binder_finished_key, truncated_hash);
        }

        /// resumption_master_secret + ticket_nonce → the PSK a ticket
        /// stands for (§4.6.1).
        pub fn resumptionPsk(
            resumption_master: *const [hash_bytes]u8,
            ticket_nonce: []const u8,
        ) [hash_bytes]u8 {
            assert(ticket_nonce.len <= 255);
            assert(!std.mem.allEqual(u8, resumption_master, 0));
            var out: [hash_bytes]u8 = undefined;
            Kdf.expandLabel(resumption_master, "resumption", ticket_nonce, &out);
            return out;
        }

        /// Erase the current secret and move to the terminal stage. Every
        /// derivation and advance asserts the stage it expects, so a
        /// schedule used after `wipe` fails an assertion instead of
        /// deriving from zeroed bytes.
        pub fn wipe(self: *Self) void {
            assert(self.stage != .wiped);
            std.crypto.secureZero(u8, &self.secret);
            self.stage = .wiped;
            assert(std.mem.allEqual(u8, &self.secret, 0));
        }

        fn emptyTranscriptHash() [hash_bytes]u8 {
            var digest: [hash_bytes]u8 = undefined;
            Hash.hash(&.{}, &digest, .{});
            return digest;
        }
    };
}

test "the three-stage ladder refuses to skip a rung" {
    const Schedule = KeySchedule(.aes_128_gcm_sha256);
    var schedule = Schedule.initEarly(null);
    try std.testing.expectEqual(Schedule.Stage.early, schedule.stage);
    const shared = [_]u8{0x42} ** 32;
    schedule.advanceToHandshake(&shared);
    try std.testing.expectEqual(Schedule.Stage.handshake, schedule.stage);
    schedule.advanceToMaster();
    try std.testing.expectEqual(Schedule.Stage.master, schedule.stage);
    schedule.wipe();
    try std.testing.expectEqual(Schedule.Stage.wiped, schedule.stage);
    try std.testing.expect(std.mem.allEqual(u8, &schedule.secret, 0));
}
