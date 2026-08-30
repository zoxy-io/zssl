//! HKDF-Extract and HKDF-Expand-Label (RFC 5869, RFC 8446 §7.1).
//!
//! Pure Zig over `std.crypto` HMAC — the primitives policy draws its line
//! at constant-time *asymmetric* and AEAD work (those go to libcrypto);
//! HMAC-SHA2 over public-length inputs is not where the sharp edges are,
//! and this is the choice ztls made and zoxy audited.
//!
//! Every RFC 8446 use of Expand-Label asks for at most one hash block of
//! output (keys are 16 or 32 bytes, IVs 12, derived secrets and finished
//! keys one hash length), so `expandLabel` is written as the single-block
//! special case and *asserts* that bound instead of carrying the generic
//! multi-block loop nobody calls.

const std = @import("std");
const assert = std.debug.assert;

/// The longest label RFC 8446 defines is "res binder"/"c ap traffic"-class;
/// "e exp master" at 12 bytes is the maximum. Headroom to 18 admits every
/// registered label without admitting arbitrary strings.
pub const label_bytes_max: u8 = 18;

/// Context is always a transcript hash here: at most 48 bytes (SHA-384).
pub const context_bytes_max: u8 = 48;

const label_prefix = "tls13 ";

/// §7.5's exporter labels are the *application's*, not RFC 8446's
/// registry: "EXPORTER-Channel-Binding" alone is 24 bytes, so
/// `label_bytes_max` cannot hold them. The bound here is the wire's own
/// — HkdfLabel's field is `opaque label<7..255>` and the prefix eats six
/// of those — which is the only bound there is once the strings stop
/// coming from a list we control.
pub const exporter_label_bytes_max: u8 = 255 - label_prefix.len;

/// The HkdfLabel of §7.1, written into `info`, returned as the prefix
/// actually used. One definition of the wire format, shared by both
/// expanders below so they cannot drift.
fn writeHkdfLabel(label: []const u8, context: []const u8, out_bytes: usize, info: []u8) []const u8 {
    assert(out_bytes >= 1);
    assert(out_bytes <= std.math.maxInt(u16));
    assert(info.len >= 2 + 1 + label_prefix.len + label.len + 1 + context.len);
    std.mem.writeInt(u16, info[0..2], @intCast(out_bytes), .big);
    info[2] = @intCast(label_prefix.len + label.len);
    var used: usize = 3;
    @memcpy(info[used..][0..label_prefix.len], label_prefix);
    used += label_prefix.len;
    @memcpy(info[used..][0..label.len], label);
    used += label.len;
    info[used] = @intCast(context.len);
    used += 1;
    @memcpy(info[used..][0..context.len], context);
    used += context.len;
    assert(used >= 4);
    return info[0..used];
}

pub fn Hkdf(comptime Hash: type) type {
    const Hmac = std.crypto.auth.hmac.Hmac(Hash);
    return struct {
        pub const prk_bytes: u8 = Hmac.mac_length;

        comptime {
            assert(prk_bytes == 32 or prk_bytes == 48);
            assert(prk_bytes <= context_bytes_max);
        }

        /// HKDF-Extract(salt, ikm) — HMAC keyed by the salt (RFC 5869 §2.2).
        pub fn extract(salt: []const u8, ikm: []const u8) [prk_bytes]u8 {
            assert(salt.len <= prk_bytes);
            assert(ikm.len >= 1);
            assert(ikm.len <= 64);
            var prk: [prk_bytes]u8 = undefined;
            Hmac.create(&prk, ikm, salt);
            return prk;
        }

        /// HKDF-Expand-Label(prk, label, context, out.len) — RFC 8446 §7.1.
        /// `label` is the bare label; the "tls13 " prefix is applied here.
        pub fn expandLabel(
            prk: *const [prk_bytes]u8,
            label: []const u8,
            context: []const u8,
            out: []u8,
        ) void {
            assert(label.len >= 1);
            assert(label.len <= label_bytes_max);
            assert(context.len <= context_bytes_max);
            assert(out.len >= 1);
            // The single-block bound: T(1) alone must cover the request.
            assert(out.len <= prk_bytes);

            // HkdfLabel: u16 length, opaque label<7..255>, opaque context<0..255>.
            const info_bytes_max = 2 + 1 + label_prefix.len + label_bytes_max + 1 + context_bytes_max;
            var info: [info_bytes_max]u8 = undefined;
            const written = writeHkdfLabel(label, context, out.len, &info);

            // T(1) = HMAC(prk, info || 0x01), truncated to out.len.
            var block: [prk_bytes]u8 = undefined;
            var mac = Hmac.init(prk);
            mac.update(written);
            mac.update(&[1]u8{0x01});
            mac.final(&block);
            @memcpy(out, block[0..out.len]);
            std.crypto.secureZero(u8, &block);
        }

        /// The same construction with RFC 5869 §2.3's full T(1)..T(N)
        /// ladder, and an application's label rather than one of ours.
        ///
        /// Only §7.5's exporter reaches this. Every other use of
        /// Expand-Label in RFC 8446 asks for at most one hash length,
        /// which is why `expandLabel` above is the special case and says
        /// so in an assertion — an exporter is the first caller that can
        /// ask for a megabyte, and the first whose label this library
        /// does not choose.
        ///
        /// Kept separate rather than folded together because the info
        /// buffer differs by a factor of four, and every key-schedule
        /// derivation would otherwise carry the exporter's stack cost.
        pub fn expandLabelLong(
            prk: *const [prk_bytes]u8,
            label: []const u8,
            context: []const u8,
            out: []u8,
        ) void {
            // No lower bound, unlike `expandLabel`. §7.1's struct
            // writes the label as `opaque label<7..255>` and the "tls13 "
            // prefix is six of those, so an *empty* application label
            // encodes a 6-byte field the grammar does not admit. It is
            // still what every implementation does: HkdfLabel is hashed,
            // never transmitted, so nothing parses it against that
            // grammar, and BoGo drives two cases with an empty label
            // against runners that accept it. Refusing would leave us
            // deriving different bytes from everyone else, which is the
            // one thing an exporter must not do.
            assert(label.len <= exporter_label_bytes_max);
            assert(context.len <= context_bytes_max);
            assert(out.len >= 1);
            // RFC 5869 §2.3: N = ceil(L / HashLen) and the counter is one
            // byte, so 255 blocks is the construction's own ceiling.
            assert(out.len <= 255 * @as(usize, prk_bytes));

            const info_bytes_max =
                2 + 1 + label_prefix.len + exporter_label_bytes_max + 1 + context_bytes_max;
            var info: [info_bytes_max]u8 = undefined;
            const written = writeHkdfLabel(label, context, out.len, &info);

            var block: [prk_bytes]u8 = undefined;
            defer std.crypto.secureZero(u8, &block);
            var filled: usize = 0;
            // `u16`, not the `u8` it is written as. The continue
            // expression runs once more after the block that fills
            // `out`, so a request needing exactly 255 blocks took the
            // counter to 256 and trapped — at precisely the ceiling the
            // assertion above calls legal. An assertion that promises
            // what the loop cannot deliver is worse than none.
            var counter: u16 = 1;
            while (filled < out.len) : (counter += 1) {
                assert(counter <= 255);
                var mac = Hmac.init(prk);
                // T(0) is empty; every later block feeds back the last.
                if (counter > 1) mac.update(&block);
                mac.update(written);
                mac.update(&[1]u8{@intCast(counter)});
                mac.final(&block);
                const take = @min(@as(usize, prk_bytes), out.len - filled);
                @memcpy(out[filled..][0..take], block[0..take]);
                filled += take;
            }
        }
    };
}

pub const HkdfSha256 = Hkdf(std.crypto.hash.sha2.Sha256);
pub const HkdfSha384 = Hkdf(std.crypto.hash.sha2.Sha384);

test "extract matches RFC 8448 early secret" {
    // Early secret = Extract(salt: 0, ikm: 32 zero bytes) — RFC 8448 §3.
    const vectors = @import("rfc8448_vectors.zig");
    const zeros = [_]u8{0} ** 32;
    const early = HkdfSha256.extract(&.{}, &zeros);
    try std.testing.expectEqualSlices(u8, &vectors.early_secret, &early);
}

test "§7.5: the multi-block ladder agrees with std's HKDF-Expand" {
    // The single-block path has RFC 8448 to answer to. This one does not
    // — no traced vector in this tree asks Expand-Label for more than a
    // hash length — so the oracle is `std.crypto.kdf.hkdf`, a second
    // RFC 5869 implementation sharing no code with ours. We build §7.1's
    // HkdfLabel and hand it over as the `info` std takes raw.
    //
    // Every length here is chosen to land somewhere different in the
    // loop: one block exactly, one byte over, and a partial tail.
    const vectors = @import("rfc8448_vectors.zig");
    var context: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("context", &context, .{});
    const label = "EXPORTER-Channel-Binding";

    for ([_]usize{ 1, 31, 32, 33, 64, 100, 1024 }) |bytes| {
        var ours: [1024]u8 = undefined;
        HkdfSha256.expandLabelLong(&vectors.early_secret, label, &context, ours[0..bytes]);

        var info: [512]u8 = undefined;
        const written = writeHkdfLabel(label, &context, bytes, &info);
        var theirs: [1024]u8 = undefined;
        std.crypto.kdf.hkdf.HkdfSha256.expand(theirs[0..bytes], written, vectors.early_secret);

        try std.testing.expectEqualSlices(u8, theirs[0..bytes], ours[0..bytes]);
    }
}

test "§7.5: the ladder reaches the ceiling its assertion claims" {
    // 255 blocks exactly — `255 * prk_bytes` is what `expandLabelLong`
    // asserts is legal, and the loop's counter used to trap one
    // increment past the last block it needed. Three lengths, because
    // the bug lived in the boundary rather than in the arithmetic.
    const vectors = @import("rfc8448_vectors.zig");
    var empty_hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&.{}, &empty_hash, .{});
    var out: [255 * 32]u8 = undefined;
    for ([_]usize{ 255 * 32, 255 * 32 - 1, 254 * 32 + 1 }) |bytes| {
        HkdfSha256.expandLabelLong(&vectors.early_secret, "label", &empty_hash, out[0..bytes]);
        try std.testing.expect(!std.mem.allEqual(u8, out[0..bytes], 0));
    }
}

test "§7.5: one block of the long ladder is the single-block path" {
    // The two expanders must not drift. Where both are legal — a short
    // label, one hash length out — they are the same function, and this
    // is what says so.
    const vectors = @import("rfc8448_vectors.zig");
    var empty_hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&.{}, &empty_hash, .{});
    var short: [32]u8 = undefined;
    var long: [32]u8 = undefined;
    HkdfSha256.expandLabel(&vectors.early_secret, "derived", &empty_hash, &short);
    HkdfSha256.expandLabelLong(&vectors.early_secret, "derived", &empty_hash, &long);
    try std.testing.expectEqualSlices(u8, &vectors.derived_for_handshake, &long);
    try std.testing.expectEqualSlices(u8, &short, &long);
}

test "expandLabel matches RFC 8448 derived secret" {
    // Derive-Secret(early, "derived", "") uses the hash of the empty
    // transcript as context — RFC 8446 §7.1, traced in RFC 8448 §3.
    const vectors = @import("rfc8448_vectors.zig");
    var empty_hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&.{}, &empty_hash, .{});
    var derived: [32]u8 = undefined;
    HkdfSha256.expandLabel(&vectors.early_secret, "derived", &empty_hash, &derived);
    try std.testing.expectEqualSlices(u8, &vectors.derived_for_handshake, &derived);
}
