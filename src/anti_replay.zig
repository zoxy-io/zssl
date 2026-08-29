//! RFC 8446 §8's anti-replay for 0-RTT: the two halves zssl can carry
//! itself, and neither of them is §8.1.
//!
//! §8.1 is single-use tickets, which needs the ticket store — the
//! embedder's by design, since sealing and lookup live behind
//! `ServerHandshake.PskLookup`. The other two we can do here:
//!
//!   - **§8.2** records a unique value from every ClientHello that
//!     carried early data, and refuses a repeat.
//!   - **§8.3** refuses a hello whose claimed age is not close to the
//!     age we measured.
//!
//! They are one mechanism in two halves and neither is any use alone.
//! Without §8.3 the register would have to remember forever; without
//! §8.2 an attacker replays freely inside whatever window §8.3 allows.
//! This module is where the two meet, and the window one keeps is
//! derived from the tolerance the other admits rather than picked.
//!
//! Nothing here reads a clock. `now_ms` arrives from the embedder
//! through `ServerHandshake.Config` — CLAUDE.md's invariant, and the
//! reason a seeded simulation replays this the way it replays the rest.

const std = @import("std");
const assert = std.debug.assert;

/// §8.3's tolerance, in either direction. BoringSSL's
/// `kMaxTicketAgeSkewSeconds` (`ssl/tls13_server.cc`), whose comment is
/// the justification: it "covers transmission delays in ClientHello and
/// NewSessionTicket, as well as drift between client and server clock
/// rate since the ticket was issued".
pub const age_skew_ms_max: u64 = 60 * 1000;

/// How long §8.2 must remember a hello, derived rather than chosen.
///
/// A replay passes §8.3 only while its *claimed* age — fixed in the
/// hello, and unchanged by being replayed — stays within
/// `age_skew_ms_max` of the age we measure, which grows. The original
/// may arrive already `age_skew_ms_max` early, and a replay stays
/// plausible until it is that far late, so the last moment a replay can
/// work is two tolerances after the first sighting. Remembering for
/// less would leave a gap; remembering for more would cost entries for
/// hellos §8.3 already refuses.
///
/// Both boundaries here are inclusive, and they have to agree about it.
/// §8.3 accepts a skew *equal* to the tolerance, so a replay arriving
/// exactly `window_ms` after the first sighting is still plausible — and
/// an entry expiring in that same instant hands it straight back. That
/// is the one-instant gap this comment used to claim could not exist;
/// `admit` expires on a strict `<` so the record outlives the last
/// moment a replay could use it.
pub const window_ms: u64 = 2 * age_skew_ms_max;

/// §8.3: is the age the client claims close enough to the one we
/// measured?
///
/// §4.2.11.1 obfuscates the age by adding `age_add` modulo 2^32, so the
/// subtraction below wraps by design — that *is* the obfuscation, not an
/// overflow to be guarded. What comes out is milliseconds since the
/// client learned the ticket, which a u32 holds for about seven weeks.
pub fn ageIsPlausible(offer: *const struct {
    obfuscated_age: u32,
    age_add: u32,
    issued_at_ms: u64,
    now_ms: u64,
}) bool {
    const claimed_ms: u64 = offer.obfuscated_age -% offer.age_add;
    // The subtraction above is u32 and only then widened, which is the
    // whole of §4.2.11.1: what a client claims is milliseconds, and a
    // u32 of them is about seven weeks. Asserted rather than assumed,
    // because widening first would make every wrong `age_add` look like
    // an age of billions of years rather than a wrong one.
    assert(claimed_ms <= std.math.maxInt(u32));
    // Saturating: a clock that went backwards is the embedder's fault,
    // and the answer to it is a measured age of zero — which fails the
    // comparison for any claim above the tolerance rather than passing
    // everything.
    const measured_ms = offer.now_ms -| offer.issued_at_ms;
    const skew = if (claimed_ms > measured_ms)
        claimed_ms - measured_ms
    else
        measured_ms - claimed_ms;
    return skew <= age_skew_ms_max;
}

/// §8.2's record of ClientHellos already seen, in caller-owned storage —
/// the shape `reassembly` and `flight` arrive in, because zssl allocates
/// nothing.
pub const StrikeRegister = struct {
    /// A power of two, so the index below is a mask rather than a
    /// division. Sizing it is the embedder's call and it is a real one:
    /// too small and 0-RTT is refused under load, which costs a round
    /// trip and nothing else.
    ///
    /// "Under load" includes load a peer arranges. Someone holding
    /// enough valid tickets can aim their binders at one probe window
    /// and fill it, denying 0-RTT to whoever else hashes there for
    /// `window_ms`. That is a fallback to a full handshake rather than a
    /// bypass — refusing is the safe direction — but it is something an
    /// attacker can cause on purpose and not only a capacity accident.
    entries: []Entry,

    /// The longest key `admit` will take — a §4.2.11.2 binder, which is
    /// one hash long.
    pub const key_bytes_max: u8 = 48;

    /// Slots examined before `admit` gives up. Bounded because the
    /// alternative is a scan whose length the embedder chose and the
    /// peer triggers.
    pub const probe_max: usize = 8;

    pub const Entry = struct {
        key: [key_bytes_max]u8,
        /// Zero for a slot that has never been written.
        key_bytes: u8,
        /// When this record stops mattering, because §8.3 refuses the
        /// hello behind it from then on.
        expires_at_ms: u64,

        pub const free: Entry = .{ .key = undefined, .key_bytes = 0, .expires_at_ms = 0 };
    };

    /// Record `key` and answer whether it had not been seen.
    ///
    /// False is a refusal and covers two things deliberately: the value
    /// is already recorded and unexpired, or every slot it could go in
    /// holds something that is. Both mean "do not accept early data on
    /// this hello", and the second must never evict to make room —
    /// evicting is exactly how a strike register quietly becomes a
    /// replay window. A refusal costs the client a round trip; an
    /// eviction costs the guarantee the register exists for.
    /// `key` must already be length-checked: the two assertions below
    /// are about the caller, and handing them a raw `PskBinderEntry` off
    /// the wire — whose length a peer chooses — would turn them into a
    /// remote abort. `ServerHandshake` passes a binder it has already
    /// held to the negotiated hash's length.
    pub fn admit(self: *StrikeRegister, key: []const u8, now_ms: u64) bool {
        assert(key.len >= 8);
        assert(key.len <= key_bytes_max);
        assert(self.entries.len >= probe_max);
        assert(std.math.isPowerOfTwo(self.entries.len));
        const mask = self.entries.len - 1;
        // The key is a MAC, so any eight bytes of it are as good an
        // index as any other.
        const start: usize = @as(usize, @truncate(std.mem.readInt(u64, key[0..8], .big))) & mask;
        var free_slot: ?usize = null;
        var probe: usize = 0;
        while (probe < probe_max) : (probe += 1) {
            const index = (start + probe) & mask;
            const entry = &self.entries[index];
            if (entry.key_bytes == 0 or entry.expires_at_ms < now_ms) {
                if (free_slot == null) free_slot = index;
                continue;
            }
            // Plain equality, not a constant-time one: this key is a
            // value the peer just sent us in the clear, so there is no
            // secret here for a timing channel to leak.
            if (entry.key_bytes == key.len and
                std.mem.eql(u8, entry.key[0..entry.key_bytes], key))
            {
                return false;
            }
        }
        const index = free_slot orelse return false;
        const entry = &self.entries[index];
        @memcpy(entry.key[0..key.len], key);
        entry.key_bytes = @intCast(key.len);
        entry.expires_at_ms = now_ms +| window_ms;
        return true;
    }
};

test "§8.3: the claimed age has to be near the measured one" {
    const issued_at_ms: u64 = 1_000_000;
    const age_add: u32 = 0x5eed_face;
    // A client that learned the ticket 10s ago, arriving 10s after we
    // issued it: no skew at all.
    try std.testing.expect(ageIsPlausible(&.{
        .obfuscated_age = 10_000 +% age_add,
        .age_add = age_add,
        .issued_at_ms = issued_at_ms,
        .now_ms = issued_at_ms + 10_000,
    }));
    // The tolerance, both edges, both directions.
    for ([_]u64{ age_skew_ms_max, age_skew_ms_max + 1 }) |skew| {
        const within = skew <= age_skew_ms_max;
        try std.testing.expectEqual(within, ageIsPlausible(&.{
            .obfuscated_age = @as(u32, @intCast(10_000 + skew)) +% age_add,
            .age_add = age_add,
            .issued_at_ms = issued_at_ms,
            .now_ms = issued_at_ms + 10_000,
        }));
        try std.testing.expectEqual(within, ageIsPlausible(&.{
            .obfuscated_age = 10_000 +% age_add,
            .age_add = age_add,
            .issued_at_ms = issued_at_ms,
            .now_ms = issued_at_ms + 10_000 + skew,
        }));
    }
    // The wrong `age_add` is what an attacker guessing at the
    // obfuscation has: §4.2.11.1's whole point is that it does not
    // survive being wrong.
    try std.testing.expect(!ageIsPlausible(&.{
        .obfuscated_age = 10_000 +% age_add,
        .age_add = age_add +% 1_000_000,
        .issued_at_ms = issued_at_ms,
        .now_ms = issued_at_ms + 10_000,
    }));
}

test "§8.2: a hello is admitted once, and a full window refuses rather than evicts" {
    var storage: [StrikeRegister.probe_max]StrikeRegister.Entry = @splat(.free);
    var register: StrikeRegister = .{ .entries = &storage };
    const now: u64 = 5_000_000;

    var key = [_]u8{0xa5} ** 32;
    try std.testing.expect(register.admit(&key, now));
    try std.testing.expect(!register.admit(&key, now));
    // A different value is a different hello, and still admitted.
    var other = [_]u8{0xa5} ** 32;
    other[31] = 0x5a;
    try std.testing.expect(register.admit(&other, now));

    // Past the window the record no longer matters: §8.3 refuses the
    // hello behind it from then on, so the slot is reusable.
    try std.testing.expect(register.admit(&key, now + window_ms + 1));

    // Fill every slot this key can reach with live records, then ask
    // again. The answer must be a refusal, not an eviction — so the
    // record already there survives, which is the property being
    // pinned.
    var full_storage: [StrikeRegister.probe_max]StrikeRegister.Entry = @splat(.free);
    var full: StrikeRegister = .{ .entries = &full_storage };
    var filler = [_]u8{0} ** 32;
    var placed: usize = 0;
    var candidate: u8 = 0;
    while (placed < StrikeRegister.probe_max) : (candidate += 1) {
        filler[0] = candidate;
        if (full.admit(&filler, now)) placed += 1;
        if (candidate == 255) break;
    }
    try std.testing.expectEqual(StrikeRegister.probe_max, placed);
    var late = [_]u8{0xff} ** 32;
    try std.testing.expect(!full.admit(&late, now));
    // And nothing it could have displaced was displaced.
    filler[0] = 0;
    try std.testing.expect(!full.admit(&filler, now));
}

test "§8.2: the record outlives the last instant a replay could still pass §8.3" {
    // The boundary the two halves have to agree about, and where they
    // did not. §8.3 accepts a skew equal to the tolerance, so a hello
    // that arrived a full tolerance early is still plausible exactly
    // `window_ms` later — and the register used to call its record
    // expired in that same instant and admit the replay.
    const issued_at_ms: u64 = 1_000_000;
    const age_add: u32 = 0x1234_5678;
    // The worst case: claimed age runs a full tolerance ahead of
    // measured, which §8.3 admits.
    const first_seen_ms = issued_at_ms + 10_000;
    const claimed_ms: u32 = @intCast(10_000 + age_skew_ms_max);
    try std.testing.expect(ageIsPlausible(&.{
        .obfuscated_age = claimed_ms +% age_add,
        .age_add = age_add,
        .issued_at_ms = issued_at_ms,
        .now_ms = first_seen_ms,
    }));

    var storage: [StrikeRegister.probe_max]StrikeRegister.Entry = @splat(.free);
    var register: StrikeRegister = .{ .entries = &storage };
    const key = [_]u8{0xc3} ** 32;
    try std.testing.expect(register.admit(&key, first_seen_ms));

    // A replay at exactly the last instant §8.3 still admits: plausible,
    // and therefore the register must refuse it.
    const last_plausible_ms = first_seen_ms + window_ms;
    try std.testing.expect(ageIsPlausible(&.{
        .obfuscated_age = claimed_ms +% age_add,
        .age_add = age_add,
        .issued_at_ms = issued_at_ms,
        .now_ms = last_plausible_ms,
    }));
    try std.testing.expect(!register.admit(&key, last_plausible_ms));

    // One millisecond later §8.3 refuses on its own, so the register is
    // free to forget — and does, which is what keeps the window from
    // being longer than it has to be.
    try std.testing.expect(!ageIsPlausible(&.{
        .obfuscated_age = claimed_ms +% age_add,
        .age_add = age_add,
        .issued_at_ms = issued_at_ms,
        .now_ms = last_plausible_ms + 1,
    }));
    try std.testing.expect(register.admit(&key, last_plausible_ms + 1));
}

test "§8.2: a table wider than one probe window still finds what it recorded" {
    // The deployment shape: most of the table is never touched by any
    // one key, so `start` has to put a key back where it left it. A
    // register sized to exactly `probe_max` cannot show that — the probe
    // covers everything either way.
    var storage: [64]StrikeRegister.Entry = @splat(.free);
    var register: StrikeRegister = .{ .entries = &storage };
    const now: u64 = 9_000_000;

    var keys: [32][32]u8 = undefined;
    for (&keys, 0..) |*key, index| {
        key.* = @splat(0x40);
        // Vary the first eight bytes, which is what the index reads.
        key[0] = @intCast(index);
        key[7] = @truncate(index *% 17);
        try std.testing.expect(register.admit(key, now));
    }
    // Every one of them is remembered, and none was displaced by a
    // later key landing in a neighbouring bucket.
    for (&keys) |*key| {
        try std.testing.expect(!register.admit(key, now));
    }
    // A value never seen is still admitted: the table is far from full,
    // and a busy neighbour must not refuse an unrelated hello.
    var fresh = [_]u8{0x40} ** 32;
    fresh[0] = 0xfe;
    fresh[7] = 0xfe;
    try std.testing.expect(register.admit(&fresh, now));
}
