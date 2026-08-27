//! The libcrypto primitive backend: AEAD record protection and X25519.
//!
//! This file and `c.zig` are the codebase's entire C surface. The division
//! of trust is DESIGN.md §2: constant-time primitives come from the
//! most-watched assembly available; every protocol decision stays above
//! this boundary in Zig. Nothing here parses attacker bytes — callers hand
//! in already-framed slices with asserted lengths.
//!
//! Allocation: `EVP_CIPHER_CTX_new` and the X25519 `EVP_PKEY` objects go
//! through libcrypto's allocator, which the embedder redirects to a fixed
//! heap via `mem_hooks` at startup. AEAD contexts are created once per
//! traffic key and reused per record; the X25519 objects live only for the
//! duration of one handshake's key agreement.

const std = @import("std");
const assert = std.debug.assert;

const c = @import("c.zig").c;
const cipher_suite = @import("../cipher_suite.zig");
const CipherSuite = cipher_suite.CipherSuite;

pub const Error = error{
    /// The library refused an operation that carries no protocol meaning —
    /// setup, allocation, or an internal failure. Terminal: never retried.
    LibcryptoFailed,
    /// AEAD tag mismatch. The one error an attacker can cause at will.
    AuthenticationFailed,
    /// A degenerate key-agreement result (RFC 8446 §7.4.2's all-zero abort).
    IdentityElement,
};

pub const nonce_bytes = cipher_suite.nonce_bytes;
pub const tag_bytes = cipher_suite.tag_bytes;

fn aeadCipher(suite: CipherSuite) *const c.EVP_CIPHER {
    return switch (suite) {
        .aes_128_gcm_sha256 => c.EVP_aes_128_gcm(),
        .aes_256_gcm_sha384 => c.EVP_aes_256_gcm(),
        .chacha20_poly1305_sha256 => c.EVP_chacha20_poly1305(),
    } orelse unreachable; // The three statically-linked ciphers always exist.
}

/// One traffic key's pair of AEAD contexts, initialized once and reused
/// for every record under that key. Sealing and opening under the same
/// key (as a test harness does) is why both directions exist even though
/// production traffic keys are unidirectional.
pub const AeadKey = struct {
    enc: *c.EVP_CIPHER_CTX,
    dec: *c.EVP_CIPHER_CTX,
    key_bytes: u8,

    pub fn init(suite: CipherSuite, key: []const u8) Error!AeadKey {
        assert(key.len == suite.keyBytes());
        assert(key.len == 16 or key.len == 32);
        const cipher = aeadCipher(suite);

        const enc = c.EVP_CIPHER_CTX_new() orelse return error.LibcryptoFailed;
        errdefer c.EVP_CIPHER_CTX_free(enc);
        const dec = c.EVP_CIPHER_CTX_new() orelse return error.LibcryptoFailed;
        errdefer c.EVP_CIPHER_CTX_free(dec);

        if (c.EVP_EncryptInit_ex(enc, cipher, null, null, null) != 1) return error.LibcryptoFailed;
        if (c.EVP_CIPHER_CTX_ctrl(enc, c.EVP_CTRL_AEAD_SET_IVLEN, nonce_bytes, null) != 1) return error.LibcryptoFailed;
        if (c.EVP_EncryptInit_ex(enc, null, null, key.ptr, null) != 1) return error.LibcryptoFailed;

        if (c.EVP_DecryptInit_ex(dec, cipher, null, null, null) != 1) return error.LibcryptoFailed;
        if (c.EVP_CIPHER_CTX_ctrl(dec, c.EVP_CTRL_AEAD_SET_IVLEN, nonce_bytes, null) != 1) return error.LibcryptoFailed;
        if (c.EVP_DecryptInit_ex(dec, null, null, key.ptr, null) != 1) return error.LibcryptoFailed;

        return .{ .enc = enc, .dec = dec, .key_bytes = @intCast(key.len) };
    }

    pub fn deinit(self: *AeadKey) void {
        assert(self.key_bytes == 16 or self.key_bytes == 32);
        c.EVP_CIPHER_CTX_free(self.enc);
        c.EVP_CIPHER_CTX_free(self.dec);
        self.* = undefined;
    }

    /// AEAD-seal: `ciphertext` receives exactly `plaintext.len` bytes, the
    /// tag goes out separately so the record layer decides the wire layout.
    pub fn seal(
        self: *AeadKey,
        nonce: *const [nonce_bytes]u8,
        additional_data: []const u8,
        plaintext: []const u8,
        ciphertext: []u8,
        tag: *[tag_bytes]u8,
    ) Error!void {
        assert(ciphertext.len == plaintext.len);
        assert(additional_data.len >= 1);
        var written: c_int = 0;
        if (c.EVP_EncryptInit_ex(self.enc, null, null, null, nonce) != 1) return error.LibcryptoFailed;
        if (c.EVP_EncryptUpdate(self.enc, null, &written, additional_data.ptr, @intCast(additional_data.len)) != 1) return error.LibcryptoFailed;
        if (c.EVP_EncryptUpdate(self.enc, ciphertext.ptr, &written, plaintext.ptr, @intCast(plaintext.len)) != 1) return error.LibcryptoFailed;
        const body_written: usize = @intCast(written);
        if (c.EVP_EncryptFinal_ex(self.enc, ciphertext.ptr + body_written, &written) != 1) return error.LibcryptoFailed;
        assert(body_written + @as(usize, @intCast(written)) == plaintext.len);
        if (c.EVP_CIPHER_CTX_ctrl(self.enc, c.EVP_CTRL_AEAD_GET_TAG, tag_bytes, tag) != 1) return error.LibcryptoFailed;
    }

    /// AEAD-open. `plaintext` holds *unauthenticated* bytes until this
    /// returns without error — the caller must not read it on failure,
    /// which the error return already makes hard to do by accident.
    pub fn open(
        self: *AeadKey,
        nonce: *const [nonce_bytes]u8,
        additional_data: []const u8,
        ciphertext: []const u8,
        tag: *const [tag_bytes]u8,
        plaintext: []u8,
    ) Error!void {
        assert(plaintext.len == ciphertext.len);
        assert(additional_data.len >= 1);
        var written: c_int = 0;
        if (c.EVP_DecryptInit_ex(self.dec, null, null, null, nonce) != 1) return error.LibcryptoFailed;
        if (c.EVP_DecryptUpdate(self.dec, null, &written, additional_data.ptr, @intCast(additional_data.len)) != 1) return error.LibcryptoFailed;
        if (c.EVP_DecryptUpdate(self.dec, plaintext.ptr, &written, ciphertext.ptr, @intCast(ciphertext.len)) != 1) return error.AuthenticationFailed;
        const body_written: usize = @intCast(written);
        // SET_TAG reads through the mutable pointer the control API demands.
        if (c.EVP_CIPHER_CTX_ctrl(self.dec, c.EVP_CTRL_AEAD_SET_TAG, tag_bytes, @constCast(tag)) != 1) return error.LibcryptoFailed;
        if (c.EVP_DecryptFinal_ex(self.dec, plaintext.ptr + body_written, &written) != 1) return error.AuthenticationFailed;
        assert(body_written + @as(usize, @intCast(written)) == ciphertext.len);
    }
};

pub const x25519_key_bytes: u8 = 32;

/// X25519(private, peer_public) → shared secret (RFC 7748), with RFC 8446
/// §7.4.2's all-zero abort. The EVP_PKEY objects live only inside the call.
pub fn x25519Shared(
    private_key: *const [x25519_key_bytes]u8,
    peer_public: *const [x25519_key_bytes]u8,
    out: *[x25519_key_bytes]u8,
) Error!void {
    const pkey = c.EVP_PKEY_new_raw_private_key(c.EVP_PKEY_X25519, null, private_key, x25519_key_bytes) orelse
        return error.LibcryptoFailed;
    defer c.EVP_PKEY_free(pkey);
    const peer = c.EVP_PKEY_new_raw_public_key(c.EVP_PKEY_X25519, null, peer_public, x25519_key_bytes) orelse
        return error.LibcryptoFailed;
    defer c.EVP_PKEY_free(peer);
    const ctx = c.EVP_PKEY_CTX_new(pkey, null) orelse return error.LibcryptoFailed;
    defer c.EVP_PKEY_CTX_free(ctx);

    if (c.EVP_PKEY_derive_init(ctx) != 1) return error.LibcryptoFailed;
    if (c.EVP_PKEY_derive_set_peer(ctx, peer) != 1) return error.IdentityElement;
    var shared_len: usize = x25519_key_bytes;
    if (c.EVP_PKEY_derive(ctx, out, &shared_len) != 1) return error.IdentityElement;
    if (shared_len != x25519_key_bytes) return error.LibcryptoFailed;
    // libcrypto already rejects the low-order result; asserting the
    // negative space here keeps the §7.4.2 guarantee ours, not OpenSSL's.
    if (std.mem.allEqual(u8, out, 0)) return error.IdentityElement;
}

/// Recover the public half of an X25519 private key.
pub fn x25519Public(
    private_key: *const [x25519_key_bytes]u8,
    out: *[x25519_key_bytes]u8,
) Error!void {
    const pkey = c.EVP_PKEY_new_raw_private_key(c.EVP_PKEY_X25519, null, private_key, x25519_key_bytes) orelse
        return error.LibcryptoFailed;
    defer c.EVP_PKEY_free(pkey);
    var public_len: usize = x25519_key_bytes;
    if (c.EVP_PKEY_get_raw_public_key(pkey, out, &public_len) != 1) return error.LibcryptoFailed;
    if (public_len != x25519_key_bytes) return error.LibcryptoFailed;
    assert(!std.mem.allEqual(u8, out, 0));
}

test "AEAD differential against std.crypto, all three suites" {
    // Two implementations sharing no code agreeing on the same bytes is
    // the cheapest strong oracle available offline. Lengths cover empty,
    // sub-block, block-straddling, and a full record's order of magnitude.
    const lengths = [_]usize{ 0, 1, 16, 17, 1000 };
    var plaintext: [1000]u8 = undefined;
    for (&plaintext, 0..) |*byte, index| byte.* = @truncate(index *% 31);
    const additional_data = "zssl differential aad";
    const nonce = [_]u8{0xa5} ** 12;

    inline for (.{
        .{ CipherSuite.aes_128_gcm_sha256, std.crypto.aead.aes_gcm.Aes128Gcm },
        .{ CipherSuite.aes_256_gcm_sha384, std.crypto.aead.aes_gcm.Aes256Gcm },
        .{ CipherSuite.chacha20_poly1305_sha256, std.crypto.aead.chacha_poly.ChaCha20Poly1305 },
    }) |pair| {
        const suite = pair[0];
        const Std = pair[1];
        var key: [suite.keyBytes()]u8 = undefined;
        for (&key, 0..) |*byte, index| byte.* = @truncate(index + 7);

        var aead = try AeadKey.init(suite, &key);
        defer aead.deinit();

        for (lengths) |length| {
            var ours: [1000]u8 = undefined;
            var ours_tag: [tag_bytes]u8 = undefined;
            try aead.seal(&nonce, additional_data, plaintext[0..length], ours[0..length], &ours_tag);

            var theirs: [1000]u8 = undefined;
            var theirs_tag: [Std.tag_length]u8 = undefined;
            Std.encrypt(theirs[0..length], &theirs_tag, plaintext[0..length], additional_data, nonce, key);

            try std.testing.expectEqualSlices(u8, theirs[0..length], ours[0..length]);
            try std.testing.expectEqualSlices(u8, &theirs_tag, &ours_tag);

            // Round-trip, then the negative space: a flipped tag bit fails.
            var opened: [1000]u8 = undefined;
            try aead.open(&nonce, additional_data, ours[0..length], &ours_tag, opened[0..length]);
            try std.testing.expectEqualSlices(u8, plaintext[0..length], opened[0..length]);
            ours_tag[0] ^= 1;
            try std.testing.expectError(
                error.AuthenticationFailed,
                aead.open(&nonce, additional_data, ours[0..length], &ours_tag, opened[0..length]),
            );
        }
    }
}

test "x25519 matches RFC 8448 and refuses the identity" {
    const vectors = @import("../rfc8448_vectors.zig");
    var shared: [32]u8 = undefined;
    try x25519Shared(&vectors.client_x25519_private, &vectors.server_x25519_public, &shared);
    try std.testing.expectEqualSlices(u8, &vectors.ecdhe_shared_secret, &shared);
    // The same agreement from the server's side.
    try x25519Shared(&vectors.server_x25519_private, &vectors.client_x25519_public, &shared);
    try std.testing.expectEqualSlices(u8, &vectors.ecdhe_shared_secret, &shared);
    // Public-key recovery agrees with the trace.
    var public: [32]u8 = undefined;
    try x25519Public(&vectors.client_x25519_private, &public);
    try std.testing.expectEqualSlices(u8, &vectors.client_x25519_public, &public);
    // Negative space: the all-zero point is an abort, not a shared secret.
    const zero_point = [_]u8{0} ** 32;
    try std.testing.expectError(
        error.IdentityElement,
        x25519Shared(&vectors.client_x25519_private, &zero_point, &shared),
    );
}
