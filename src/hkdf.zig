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
            std.mem.writeInt(u16, info[0..2], @intCast(out.len), .big);
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
            assert(used <= info_bytes_max);
            assert(used >= 4);

            // T(1) = HMAC(prk, info || 0x01), truncated to out.len.
            var block: [prk_bytes]u8 = undefined;
            var mac = Hmac.init(prk);
            mac.update(info[0..used]);
            mac.update(&[1]u8{0x01});
            mac.final(&block);
            @memcpy(out, block[0..out.len]);
            std.crypto.secureZero(u8, &block);
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
