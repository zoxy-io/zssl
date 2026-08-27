//! TLS 1.3 cipher suites (RFC 8446 §B.4).
//!
//! Exactly the three suites RFC 8446 defines for TLS 1.3 and nothing else:
//! zssl is 1.3-only, so the 1.2 suite space does not exist here, and an
//! unknown wire value is a negotiation fact (`null`), never a crash.

const std = @import("std");
const assert = std.debug.assert;

/// Every suite carries the same AEAD shape: a 12-byte per-record nonce and
/// a 16-byte tag (RFC 8446 §5.2-§5.3).
pub const nonce_bytes: u8 = 12;
pub const tag_bytes: u8 = 16;

/// The largest key and hash any suite uses — sizing constants for buffers
/// that must hold whichever suite was negotiated at runtime.
pub const key_bytes_max: u8 = 32;
pub const hash_bytes_max: u8 = 48;

pub const CipherSuite = enum(u16) {
    aes_128_gcm_sha256 = 0x1301,
    aes_256_gcm_sha384 = 0x1302,
    chacha20_poly1305_sha256 = 0x1303,

    /// Classify a wire code point. `null` is the answer for everything
    /// outside the three TLS 1.3 suites — including every TLS 1.2 suite a
    /// compatibility-minded client offers alongside them.
    pub fn fromWire(wire: u16) ?CipherSuite {
        return switch (wire) {
            0x1301 => .aes_128_gcm_sha256,
            0x1302 => .aes_256_gcm_sha384,
            0x1303 => .chacha20_poly1305_sha256,
            else => null,
        };
    }

    /// Transcript-hash and HKDF output length (RFC 8446 §7.1).
    pub fn hashBytes(suite: CipherSuite) u8 {
        const bytes: u8 = switch (suite) {
            .aes_128_gcm_sha256 => 32,
            .aes_256_gcm_sha384 => 48,
            .chacha20_poly1305_sha256 => 32,
        };
        assert(bytes == 32 or bytes == 48);
        assert(bytes <= hash_bytes_max);
        return bytes;
    }

    /// AEAD key length (RFC 8446 §7.3).
    pub fn keyBytes(suite: CipherSuite) u8 {
        const bytes: u8 = switch (suite) {
            .aes_128_gcm_sha256 => 16,
            .aes_256_gcm_sha384 => 32,
            .chacha20_poly1305_sha256 => 32,
        };
        assert(bytes == 16 or bytes == 32);
        assert(bytes <= key_bytes_max);
        return bytes;
    }

    /// The transcript/HKDF hash function behind the suite, as a type — a
    /// comptime fact, because the key schedule is instantiated per hash.
    pub fn HashType(comptime suite: CipherSuite) type {
        return switch (suite) {
            .aes_128_gcm_sha256 => std.crypto.hash.sha2.Sha256,
            .aes_256_gcm_sha384 => std.crypto.hash.sha2.Sha384,
            .chacha20_poly1305_sha256 => std.crypto.hash.sha2.Sha256,
        };
    }
};

test "fromWire admits exactly the three 1.3 code points" {
    try std.testing.expectEqual(CipherSuite.aes_128_gcm_sha256, CipherSuite.fromWire(0x1301).?);
    try std.testing.expectEqual(CipherSuite.aes_256_gcm_sha384, CipherSuite.fromWire(0x1302).?);
    try std.testing.expectEqual(CipherSuite.chacha20_poly1305_sha256, CipherSuite.fromWire(0x1303).?);
    // Negative space: the 1.2 workhorse suite and the adjacent code points.
    try std.testing.expectEqual(@as(?CipherSuite, null), CipherSuite.fromWire(0xc02f));
    try std.testing.expectEqual(@as(?CipherSuite, null), CipherSuite.fromWire(0x1300));
    try std.testing.expectEqual(@as(?CipherSuite, null), CipherSuite.fromWire(0x1304));
}

test "dimension agreement between hash type and hashBytes" {
    inline for ([_]CipherSuite{ .aes_128_gcm_sha256, .aes_256_gcm_sha384, .chacha20_poly1305_sha256 }) |suite| {
        try std.testing.expectEqual(
            @as(usize, suite.hashBytes()),
            CipherSuite.HashType(suite).digest_length,
        );
    }
}
