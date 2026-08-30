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

/// Where a PSK came from, which §4.2.11.2 makes a cryptographic
/// question rather than bookkeeping: `binder_key` is derived under
/// "ext binder" for a key established out of band and "res binder" for
/// one a NewSessionTicket stands for. Get it wrong and the binder
/// simply does not verify, which reads as a bad key rather than as the
/// two sides disagreeing about what kind of key it is.
pub const PskKind = enum {
    resumption,
    external,

    /// §4.2.11.2's two labels, and the only place either is written.
    fn binderLabel(kind: PskKind) []const u8 {
        return switch (kind) {
            .resumption => "res binder",
            .external => "ext binder",
        };
    }
};

/// Re-exported so an embedder bounding its own label buffer has one
/// name to reach for, and does not have to know the derivation runs on
/// `hkdf`'s wire limit.
pub const exporter_label_bytes_max = hkdf.exporter_label_bytes_max;

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

        /// Extract the early secret. A resumption PSK is exactly one
        /// hash long, because §4.6.1 derives it that way; an external one
        /// is whatever the two peers agreed out of band, and §4.2.11
        /// associates a *hash* with it without constraining its length.
        /// HKDF-Extract takes either as ikm without caring. Absent a PSK
        /// the ikm is a hash length of zero bytes (§7.1).
        ///
        /// The bound is a range rather than an equality because the
        /// length now comes from an embedder answering `psk_lookup`, and
        /// the identity that prompted the answer is the peer's. A caller
        /// handing this an empty slice is the one mistake worth
        /// asserting: `Kdf.extract` would happily accept it and derive a
        /// schedule from nothing.
        pub fn initEarly(psk: ?[]const u8) Self {
            if (psk) |bytes| assert(bytes.len >= 1 and bytes.len <= cipher_suite.hash_bytes_max);
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
        ///
        /// `kind` picks the label, and it is the caller's to know: the
        /// wire carries an identity, not a provenance, so only whoever
        /// answered for that identity can say which of the two it is.
        pub fn pskBinder(
            self: *const Self,
            kind: PskKind,
            truncated_hash: *const [hash_bytes]u8,
        ) [hash_bytes]u8 {
            assert(self.stage == .early);
            assert(!std.mem.allEqual(u8, &self.secret, 0));
            var empty_hash: [hash_bytes]u8 = undefined;
            Hash.hash(&.{}, &empty_hash, .{});
            const binder_key = self.deriveSecret(kind.binderLabel(), &empty_hash);
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

        /// §7.5's TLS-Exporter, in the two steps the RFC writes it as:
        ///
        ///     HKDF-Expand-Label(Derive-Secret(Secret, label, ""),
        ///                       "exporter", Hash(context_value),
        ///                       key_length)
        ///
        /// `Secret` is the exporter_master the caller already derived,
        /// so this is a pure function of it — no stage to assert,
        /// because the schedule it came from may be long wiped by the
        /// time an application asks.
        ///
        /// The inner Derive-Secret uses the *empty* transcript, not the
        /// handshake's: §7.5's context is hashed and goes in the outer
        /// call, and the two are easy to swap. Only the outer expansion
        /// may exceed one hash length.
        pub fn exporter(
            exporter_master: *const [hash_bytes]u8,
            label: []const u8,
            context: []const u8,
            out: []u8,
        ) void {
            // Empty labels admitted; see `hkdf.expandLabelLong`.
            assert(label.len <= hkdf.exporter_label_bytes_max);
            assert(out.len >= 1);
            assert(!std.mem.allEqual(u8, exporter_master, 0));
            var base: [hash_bytes]u8 = undefined;
            defer std.crypto.secureZero(u8, &base);
            Kdf.expandLabelLong(exporter_master, label, &emptyTranscriptHash(), &base);
            var context_hash: [hash_bytes]u8 = undefined;
            Hash.hash(context, &context_hash, .{});
            Kdf.expandLabelLong(&base, "exporter", &context_hash, out);
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

test "§4.2.11.2: the two PSK kinds derive different binders" {
    const Schedule = KeySchedule(.aes_128_gcm_sha256);
    const psk = [_]u8{0xab} ** 32;
    var truncated_hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("truncated ClientHello", &truncated_hash, .{});

    var schedule = Schedule.initEarly(&psk);
    defer schedule.wipe();
    const resumption = schedule.pskBinder(.resumption, &truncated_hash);
    const external = schedule.pskBinder(.external, &truncated_hash);

    // The whole point of carrying the kind. Same PSK, same transcript,
    // different binder — which is why an external PSK verified under
    // "res binder" fails with `decrypt_error` and looks like a key
    // mismatch rather than a label disagreement (docs/TLSFUZZER.md
    // finding 12).
    try std.testing.expect(!std.mem.eql(u8, &resumption, &external));

    // And each is stable: the label is the only input that moved.
    var again = Schedule.initEarly(&psk);
    defer again.wipe();
    try std.testing.expectEqualSlices(u8, &resumption, &again.pskBinder(.resumption, &truncated_hash));
    try std.testing.expectEqualSlices(u8, &external, &again.pskBinder(.external, &truncated_hash));
}

test "an external PSK need not be a hash length" {
    const Schedule = KeySchedule(.aes_128_gcm_sha256);
    var truncated_hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("truncated ClientHello", &truncated_hash, .{});

    // §4.2.11 associates a hash with an external PSK and says nothing
    // about its length; HKDF-Extract takes any ikm. One byte and a full
    // hash length both produce a schedule, and different ones.
    var short = Schedule.initEarly(&[_]u8{0x01});
    defer short.wipe();
    var long = Schedule.initEarly(&([_]u8{0x01} ** 32));
    defer long.wipe();
    try std.testing.expect(!std.mem.eql(
        u8,
        &short.pskBinder(.external, &truncated_hash),
        &long.pskBinder(.external, &truncated_hash),
    ));
}
