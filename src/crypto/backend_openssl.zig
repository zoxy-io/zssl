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

/// libcrypto records every failure on a per-thread error queue, and
/// nothing above this boundary ever reads it: zssl reports failures as
/// Zig errors, and the queue's string data is a diagnostic for programs
/// that call `ERR_print_errors`. Left alone, the entries sit in the
/// embedder's fixed heap — bounded, because the queue is a ring of
/// `ERR_NUM_ERRORS` (16) slots per thread, but never handed back, so a
/// heap sized with no slack keeps them for the life of the process.
///
/// Every public entry point below clears the queue on the way out of a
/// failure. An `errdefer` rather than a call per failing branch: the
/// branches are many and each one is a chance to forget, while the
/// function has exactly one error exit to guard.
fn clearErrorQueue() void {
    c.ERR_clear_error();
}

pub const SignError = Error || error{
    /// The key is not an ECDSA P-256/P-384 key — a policy refusal at load,
    /// so the handshake never discovers it mid-flight.
    UnsupportedKey,
    /// RFC 6979 nonces were requested and this libcrypto cannot honor the
    /// "nonce-type" parameter (pre-3.2). A loud error, because the silent
    /// alternative is a random nonce — exactly what the option forbids.
    DeterministicNonceUnsupported,
    /// The peer's (or our own round-tripped) signature does not verify.
    SignatureInvalid,
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
        errdefer clearErrorQueue();
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
        errdefer clearErrorQueue();
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
        errdefer clearErrorQueue();
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
    errdefer clearErrorQueue();
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
    errdefer clearErrorQueue();
    const pkey = c.EVP_PKEY_new_raw_private_key(c.EVP_PKEY_X25519, null, private_key, x25519_key_bytes) orelse
        return error.LibcryptoFailed;
    defer c.EVP_PKEY_free(pkey);
    var public_len: usize = x25519_key_bytes;
    if (c.EVP_PKEY_get_raw_public_key(pkey, out, &public_len) != 1) return error.LibcryptoFailed;
    if (public_len != x25519_key_bytes) return error.LibcryptoFailed;
    assert(!std.mem.allEqual(u8, out, 0));
}

/// The two signature schemes zssl will ever hold a private key for
/// (RFC 8446 §4.2.3 code points). RSA is a policy exclusion, not a gap.
pub const SignatureScheme = enum(u16) {
    ecdsa_secp256r1_sha256 = 0x0403,
    ecdsa_secp384r1_sha384 = 0x0503,

    fn digest(scheme: SignatureScheme) *const c.EVP_MD {
        return switch (scheme) {
            .ecdsa_secp256r1_sha256 => c.EVP_sha256(),
            .ecdsa_secp384r1_sha384 => c.EVP_sha384(),
        } orelse unreachable; // Statically-linked digests always exist.
    }
};

/// A DER ECDSA-Sig-Value is at most 72 bytes for P-256 and 104 for P-384;
/// 112 leaves headroom without inviting nonsense.
pub const signature_bytes_max: u16 = 112;

/// An ECDSA signing key held as a libcrypto `EVP_PKEY`. Lives from
/// credential load to shutdown; each `sign` call creates and frees one
/// digest context through the hooked allocator — handshake-time cost,
/// never per-record.
pub const Signer = struct {
    pkey: *c.EVP_PKEY,
    scheme: SignatureScheme,
    /// Opt-in RFC 6979 nonces make the signature — and through DER
    /// integer trimming, the flight length — a pure function of key and
    /// transcript, which is what seeded-simulation replay needs. Off in
    /// production: hedged random nonces are the conservative default.
    deterministic_nonces: bool,

    /// Load a PEM private key and classify it. Anything but EC P-256 or
    /// P-384 is refused here, at load, where the operator can read the
    /// error.
    pub fn fromPem(key_pem: []const u8, deterministic_nonces: bool) SignError!Signer {
        errdefer clearErrorQueue();
        assert(key_pem.len >= 1);
        assert(key_pem.len <= 1 << 20);
        const bio = c.BIO_new_mem_buf(key_pem.ptr, @intCast(key_pem.len)) orelse
            return error.LibcryptoFailed;
        defer _ = c.BIO_free(bio);
        const pkey = c.PEM_read_bio_PrivateKey(bio, null, null, null) orelse
            return error.UnsupportedKey;
        errdefer c.EVP_PKEY_free(pkey);

        if (c.EVP_PKEY_is_a(pkey, "EC") != 1) return error.UnsupportedKey;
        const bits = c.EVP_PKEY_get_bits(pkey);
        const scheme: SignatureScheme = switch (bits) {
            256 => .ecdsa_secp256r1_sha256,
            384 => .ecdsa_secp384r1_sha384,
            else => return error.UnsupportedKey,
        };
        return .{ .pkey = pkey, .scheme = scheme, .deterministic_nonces = deterministic_nonces };
    }

    pub fn deinit(self: *Signer) void {
        c.EVP_PKEY_free(self.pkey);
        self.* = undefined;
    }

    /// Sign `content` (the full CertificateVerify content structure — the
    /// digest happens inside). Returns the DER signature written into `out`.
    pub fn sign(self: *const Signer, content: []const u8, out: []u8) SignError![]const u8 {
        errdefer clearErrorQueue();
        assert(content.len >= 1);
        assert(out.len >= signature_bytes_max);
        const ctx = c.EVP_MD_CTX_new() orelse return error.LibcryptoFailed;
        defer c.EVP_MD_CTX_free(ctx);

        var pkey_ctx: ?*c.EVP_PKEY_CTX = null;
        if (c.EVP_DigestSignInit(ctx, &pkey_ctx, self.scheme.digest(), null, self.pkey) != 1)
            return error.LibcryptoFailed;
        if (self.deterministic_nonces) try requireDeterministicNonce(pkey_ctx);
        if (c.EVP_DigestSignUpdate(ctx, content.ptr, content.len) != 1) return error.LibcryptoFailed;

        var required: usize = 0;
        if (c.EVP_DigestSignFinal(ctx, null, &required) != 1) return error.LibcryptoFailed;
        if (required > out.len) return error.LibcryptoFailed;
        var written: usize = out.len;
        if (c.EVP_DigestSignFinal(ctx, out.ptr, &written) != 1) return error.LibcryptoFailed;
        assert(written >= 8);
        assert(written <= signature_bytes_max);
        return out[0..written];
    }

    /// Verify a DER signature over `content` against this key's public
    /// half. Test-side tooling: the independent verification paths are
    /// `std.crypto` in the test client and real peers in interop.
    pub fn verify(self: *const Signer, content: []const u8, signature: []const u8) SignError!void {
        errdefer clearErrorQueue();
        assert(content.len >= 1);
        assert(signature.len >= 8);
        const ctx = c.EVP_MD_CTX_new() orelse return error.LibcryptoFailed;
        defer c.EVP_MD_CTX_free(ctx);
        var pkey_ctx: ?*c.EVP_PKEY_CTX = null;
        if (c.EVP_DigestVerifyInit(ctx, &pkey_ctx, self.scheme.digest(), null, self.pkey) != 1)
            return error.LibcryptoFailed;
        if (c.EVP_DigestVerifyUpdate(ctx, content.ptr, content.len) != 1) return error.LibcryptoFailed;
        if (c.EVP_DigestVerifyFinal(ctx, signature.ptr, signature.len) != 1)
            return error.SignatureInvalid;
    }
};

/// The settable-params probe first: `EVP_PKEY_CTX_set_params` can succeed
/// while the provider ignores an unknown key, and a silently random nonce
/// is precisely the failure the option exists to prevent.
fn requireDeterministicNonce(pkey_ctx: ?*c.EVP_PKEY_CTX) SignError!void {
    // DigestSignInit populated this or failed; a null here would probe
    // the provider's global params and "succeed" vacuously.
    assert(pkey_ctx != null);
    const settable = c.EVP_PKEY_CTX_settable_params(pkey_ctx);
    if (c.OSSL_PARAM_locate_const(settable, c.OSSL_SIGNATURE_PARAM_NONCE_TYPE) == null)
        return error.DeterministicNonceUnsupported;
    var nonce_type: c_uint = 1; // 1 = deterministic-k (RFC 6979).
    var params = [_]c.OSSL_PARAM{
        c.OSSL_PARAM_construct_uint(c.OSSL_SIGNATURE_PARAM_NONCE_TYPE, &nonce_type),
        c.OSSL_PARAM_construct_end(),
    };
    if (c.EVP_PKEY_CTX_set_params(pkey_ctx, &params) != 1) return error.LibcryptoFailed;
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

test "signer: classification, round-trip, and RFC 6979 determinism" {
    const key_pem = @embedFile("../testdata/key.pem");
    const content = "TLS 1.3 test content, signed twice";

    var deterministic = try Signer.fromPem(key_pem, true);
    defer deterministic.deinit();
    try std.testing.expectEqual(SignatureScheme.ecdsa_secp256r1_sha256, deterministic.scheme);

    var first_buffer: [signature_bytes_max]u8 = undefined;
    var second_buffer: [signature_bytes_max]u8 = undefined;
    const first = try deterministic.sign(content, &first_buffer);
    const second = try deterministic.sign(content, &second_buffer);
    // RFC 6979: same key, same content — the same signature, bit for bit.
    try std.testing.expectEqualSlices(u8, first, second);
    try deterministic.verify(content, first);

    // Negative space: a tampered signature and tampered content both fail.
    var tampered_buffer: [signature_bytes_max]u8 = undefined;
    @memcpy(tampered_buffer[0..first.len], first);
    tampered_buffer[first.len - 1] ^= 1;
    try std.testing.expectError(error.SignatureInvalid, deterministic.verify(content, tampered_buffer[0..first.len]));
    try std.testing.expectError(error.SignatureInvalid, deterministic.verify("TLS 1.3 test content, signed 0nce", first));

    // Hedged (default) nonces: two signatures over the same content differ.
    var hedged = try Signer.fromPem(key_pem, false);
    defer hedged.deinit();
    const third = try hedged.sign(content, &first_buffer);
    const fourth = try hedged.sign(content, &second_buffer);
    try std.testing.expect(!std.mem.eql(u8, third, fourth));
    try hedged.verify(content, third);
    try hedged.verify(content, fourth);
}

test "signer refuses what policy excludes" {
    // An Ed25519 key is a fine key for someone else's TLS library.
    const ed25519_pem =
        "-----BEGIN PRIVATE KEY-----\n" ++
        "MC4CAQAwBQYDK2VwBCIEIFf+dQTz6cUdWa5TXBWSGCNjZfbWEUxTAKF+bmKlbYzR\n" ++
        "-----END PRIVATE KEY-----\n";
    try std.testing.expectError(error.UnsupportedKey, Signer.fromPem(ed25519_pem, false));
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

// The drain needs a gate or it is one refactor from being deleted as
// dead code. `ERR_peek_error` answers 0 for an empty queue, so the
// property is directly observable: force a failure through each entry
// point that can fail without a live key, and the queue is empty after.
test "libcrypto's error queue is empty after a failure" {
    // Start from a known state: an earlier test in this process may have
    // left entries, and what is under test is what *these* calls leave.
    c.ERR_clear_error();
    try std.testing.expectEqual(@as(c_ulong, 0), c.ERR_peek_error());

    // A key that is not a key. `fromPem` fails inside PEM_read_bio_*,
    // which is one of libcrypto's chattier error paths.
    try std.testing.expectError(
        error.UnsupportedKey,
        Signer.fromPem("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n", false),
    );
    try std.testing.expectEqual(@as(c_ulong, 0), c.ERR_peek_error());

    // The all-zero peer point: EVP_PKEY_derive refuses it, which is the
    // §7.4.2 abort and also an error-queue entry.
    const private_key = [_]u8{0x11} ** 31 ++ [_]u8{0x42};
    const zero_point = [_]u8{0} ** 32;
    var shared: [32]u8 = undefined;
    try std.testing.expectError(
        error.IdentityElement,
        x25519Shared(&private_key, &zero_point, &shared),
    );
    try std.testing.expectEqual(@as(c_ulong, 0), c.ERR_peek_error());

    // A tag that does not authenticate — the one failure a peer can
    // cause at will, so the one whose residue would accumulate fastest.
    const key = [_]u8{0x33} ** 16;
    var aead = try AeadKey.init(.aes_128_gcm_sha256, &key);
    defer aead.deinit();
    const nonce = [_]u8{0x44} ** nonce_bytes;
    var sealed: [8]u8 = undefined;
    var tag: [tag_bytes]u8 = undefined;
    try aead.seal(&nonce, "aad", "12345678", &sealed, &tag);
    tag[0] ^= 1;
    var opened: [8]u8 = undefined;
    try std.testing.expectError(
        error.AuthenticationFailed,
        aead.open(&nonce, "aad", &sealed, &tag, &opened),
    );
    try std.testing.expectEqual(@as(c_ulong, 0), c.ERR_peek_error());
}
