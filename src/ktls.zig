//! Linux kernel TLS (kTLS) crypto_info payloads — the key-export seam.
//!
//! Pure data from `include/uapi/linux/tls.h`: no syscalls and no Linux
//! dependency, so the packing compiles and is testable everywhere; only
//! `setsockopt(SOL_TLS, TLS_TX/RX, ...)` is Linux's. This seam existing in
//! slice 1 is the point of zssl: record offload needs the traffic keys
//! *handed out* in kernel layout, and a TLS library designed around
//! opaque sessions has to be pried open to do it.
//!
//! The kernel reconstructs the RFC 8446 §5.3 nonce itself: for AES-GCM the
//! 12-byte static IV splits into `salt` (first 4) and `iv` (last 8);
//! ChaCha20-Poly1305 keeps the full 12 bytes in `iv`. `rec_seq` is the
//! next record sequence number, big-endian.

const std = @import("std");
const assert = std.debug.assert;

const cipher_suite = @import("cipher_suite.zig");
const CipherSuite = cipher_suite.CipherSuite;

/// Kernel UAPI constants, names kept verbatim for grep-ability against
/// include/uapi/linux/tls.h.
pub const SOL_TCP: u32 = 6;
pub const TCP_ULP: u32 = 31;
pub const SOL_TLS: u32 = 282;
pub const TLS_TX: u32 = 1;
pub const TLS_RX: u32 = 2;
pub const TLS_1_3_VERSION: u16 = 0x0304;
pub const TLS_CIPHER_AES_GCM_128: u16 = 51;
pub const TLS_CIPHER_AES_GCM_256: u16 = 52;
pub const TLS_CIPHER_CHACHA20_POLY1305: u16 = 54;

/// `struct tls_crypto_info`.
pub const TlsCryptoInfo = extern struct {
    version: u16,
    cipher_type: u16,
};

/// `struct tls12_crypto_info_aes_gcm_128`.
pub const AesGcm128Info = extern struct {
    info: TlsCryptoInfo,
    iv: [8]u8,
    key: [16]u8,
    salt: [4]u8,
    rec_seq: [8]u8,
};

/// `struct tls12_crypto_info_aes_gcm_256`.
pub const AesGcm256Info = extern struct {
    info: TlsCryptoInfo,
    iv: [8]u8,
    key: [32]u8,
    salt: [4]u8,
    rec_seq: [8]u8,
};

/// `struct tls12_crypto_info_chacha20_poly1305`.
pub const ChaCha20Poly1305Info = extern struct {
    info: TlsCryptoInfo,
    iv: [12]u8,
    key: [32]u8,
    rec_seq: [8]u8,
};

comptime {
    // The kernel reads these as raw bytes; a padding surprise here would
    // corrupt keys silently, so the sizes are pinned to the UAPI layout.
    assert(@sizeOf(TlsCryptoInfo) == 4);
    assert(@sizeOf(AesGcm128Info) == 40);
    assert(@sizeOf(AesGcm256Info) == 56);
    assert(@sizeOf(ChaCha20Poly1305Info) == 56);
}

/// One direction's exported key material, in zssl terms: what a
/// handshake hands over when the record layer moves into the kernel.
pub const KeyMaterial = struct {
    suite: CipherSuite,
    key: [cipher_suite.key_bytes_max]u8,
    key_bytes: u8,
    static_iv: [cipher_suite.nonce_bytes]u8,
    /// The sequence number of the *next* record in this direction.
    next_sequence: u64,
};

pub const PackedInfo = union(CipherSuite) {
    aes_128_gcm_sha256: AesGcm128Info,
    aes_256_gcm_sha384: AesGcm256Info,
    chacha20_poly1305_sha256: ChaCha20Poly1305Info,

    /// The bytes `setsockopt` wants.
    pub fn bytes(self: *const PackedInfo) []const u8 {
        return switch (self.*) {
            .aes_128_gcm_sha256 => |*info| std.mem.asBytes(info),
            .aes_256_gcm_sha384 => |*info| std.mem.asBytes(info),
            .chacha20_poly1305_sha256 => |*info| std.mem.asBytes(info),
        };
    }
};

/// Fold key material into the kernel's per-cipher layout.
pub fn pack(material: *const KeyMaterial) PackedInfo {
    assert(material.key_bytes == material.suite.keyBytes());
    assert(!std.mem.allEqual(u8, &material.static_iv, 0));
    var sequence_be: [8]u8 = undefined;
    std.mem.writeInt(u64, &sequence_be, material.next_sequence, .big);
    return switch (material.suite) {
        .aes_128_gcm_sha256 => .{ .aes_128_gcm_sha256 = .{
            .info = .{ .version = TLS_1_3_VERSION, .cipher_type = TLS_CIPHER_AES_GCM_128 },
            .iv = material.static_iv[4..12].*,
            .key = material.key[0..16].*,
            .salt = material.static_iv[0..4].*,
            .rec_seq = sequence_be,
        } },
        .aes_256_gcm_sha384 => .{ .aes_256_gcm_sha384 = .{
            .info = .{ .version = TLS_1_3_VERSION, .cipher_type = TLS_CIPHER_AES_GCM_256 },
            .iv = material.static_iv[4..12].*,
            .key = material.key[0..32].*,
            .salt = material.static_iv[0..4].*,
            .rec_seq = sequence_be,
        } },
        .chacha20_poly1305_sha256 => .{ .chacha20_poly1305_sha256 = .{
            .info = .{ .version = TLS_1_3_VERSION, .cipher_type = TLS_CIPHER_CHACHA20_POLY1305 },
            .iv = material.static_iv,
            .key = material.key[0..32].*,
            .rec_seq = sequence_be,
        } },
    };
}

test "pack splits the RFC 8448 server IV the way the kernel rebuilds it" {
    const vectors = @import("rfc8448_vectors.zig");
    var material: KeyMaterial = .{
        .suite = .aes_128_gcm_sha256,
        .key = undefined,
        .key_bytes = 16,
        .static_iv = vectors.server_ap_iv,
        .next_sequence = 2,
    };
    @memset(&material.key, 0);
    @memcpy(material.key[0..16], &vectors.server_ap_key);
    const info = pack(&material);
    const gcm = info.aes_128_gcm_sha256;
    try std.testing.expectEqualSlices(u8, vectors.server_ap_iv[0..4], &gcm.salt);
    try std.testing.expectEqualSlices(u8, vectors.server_ap_iv[4..12], &gcm.iv);
    try std.testing.expectEqualSlices(u8, &vectors.server_ap_key, &gcm.key);
    try std.testing.expectEqual(@as(u8, 2), gcm.rec_seq[7]);
    try std.testing.expectEqual(@as(usize, 40), info.bytes().len);
}
