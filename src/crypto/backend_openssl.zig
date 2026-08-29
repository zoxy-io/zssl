//! The libcrypto primitive backend: AEAD record protection and X25519.
//!
//! This file and `c.zig` are the codebase's entire C surface. The division
//! of trust is DESIGN.md §2: constant-time primitives come from the
//! most-watched assembly available; every protocol decision stays above
//! this boundary in Zig. Callers hand in already-framed slices with
//! asserted lengths.
//!
//! One exception, and it is deliberate: `verifyEcdsa` hands a peer's DER
//! ECDSA-Sig-Value to libcrypto's own ASN.1 decoder, and `ecFromPublic` a
//! peer's point to its own point decoder. Both are peer-chosen bytes, and
//! both are length-checked by the caller before they get here — see the
//! note on `ClientHandshake.verifyEcdsa` for why that trade was taken.
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
/// The key-exchange groups zssl offers, and the sizes each implies.
/// x25519 is the one every peer has; the two NIST curves are here
/// because half the TLS test corpora in existence assume secp256r1, and
/// because a terminating proxy meets clients that offer nothing else.
pub const Group = enum(u16) {
    secp256r1 = 0x0017,
    secp384r1 = 0x0018,
    x25519 = 0x001d,

    pub fn fromWire(wire: u16) ?Group {
        return std.enums.fromInt(Group, wire);
    }

    /// The scalar an embedder supplies. Each curve's own order size —
    /// never a hash of something shorter, because the entropy policy is
    /// the embedder's and silently stretching it would take that away.
    pub fn privateBytes(group: Group) u8 {
        return switch (group) {
            .x25519, .secp256r1 => 32,
            .secp384r1 => 48,
        };
    }

    /// What goes on the wire in a KeyShareEntry: a raw u-coordinate for
    /// x25519, an uncompressed SEC1 point for the NIST curves (§4.2.8.2).
    pub fn publicBytes(group: Group) u8 {
        return switch (group) {
            .x25519 => 32,
            .secp256r1 => 65,
            .secp384r1 => 97,
        };
    }

    /// The ECDH output §7.4.2 feeds the key schedule: the x-coordinate
    /// alone, at the curve's field size.
    pub fn sharedBytes(group: Group) u8 {
        return switch (group) {
            .x25519, .secp256r1 => 32,
            .secp384r1 => 48,
        };
    }

    fn curveNid(group: Group) c_int {
        return switch (group) {
            .secp256r1 => c.NID_X9_62_prime256v1,
            .secp384r1 => c.NID_secp384r1,
            .x25519 => unreachable, // Not an EC group in libcrypto's sense.
        };
    }

    fn curveName(group: Group) [:0]const u8 {
        return switch (group) {
            // libcrypto's own spelling: P-256 is "prime256v1" there.
            .secp256r1 => "prime256v1",
            .secp384r1 => "secp384r1",
            .x25519 => unreachable, // Not an EC group in libcrypto's sense.
        };
    }
};

pub const group_private_bytes_max: u8 = 48;
pub const group_public_bytes_max: u8 = 97;
pub const group_shared_bytes_max: u8 = 48;

/// The public half of `private_key` under `group`, written into `out`.
pub fn keySharePublic(group: Group, private_key: []const u8, out: []u8) Error![]u8 {
    assert(private_key.len == group.privateBytes());
    assert(out.len >= group.publicBytes());
    if (group == .x25519) {
        try x25519Public(private_key[0..x25519_key_bytes], out[0..x25519_key_bytes]);
        return out[0..x25519_key_bytes];
    }
    errdefer clearErrorQueue();
    return ecPublicFromScalar(group, private_key, out);
}

/// scalar × G, as an uncompressed SEC1 point.
///
/// Deliberately the low-level EC API rather than `EVP_PKEY_fromdata`:
/// importing a private key alone does *not* make the provider compute
/// the public half, so asking for `OSSL_PKEY_PARAM_PUB_KEY` afterwards
/// fails. The multiplication is the thing we actually want, and this is
/// the call that does it.
fn ecPublicFromScalar(group: Group, private_key: []const u8, out: []u8) Error![]u8 {
    const ec_group = c.EC_GROUP_new_by_curve_name(group.curveNid()) orelse
        return error.LibcryptoFailed;
    defer c.EC_GROUP_free(ec_group);
    const scalar = c.BN_bin2bn(private_key.ptr, @intCast(private_key.len), null) orelse
        return error.LibcryptoFailed;
    defer c.BN_clear_free(scalar);
    const point = c.EC_POINT_new(ec_group) orelse return error.LibcryptoFailed;
    defer c.EC_POINT_free(point);
    if (c.EC_POINT_mul(ec_group, point, scalar, null, null, null) != 1) {
        return error.LibcryptoFailed;
    }
    const written = c.EC_POINT_point2oct(
        ec_group,
        point,
        c.POINT_CONVERSION_UNCOMPRESSED,
        out.ptr,
        out.len,
        null,
    );
    if (written != group.publicBytes()) return error.LibcryptoFailed;
    return out[0..written];
}

/// One party's key-exchange keypair: the embedder's scalar, and the
/// public value it implies, computed once and kept.
///
/// The two halves are bundled because OpenSSL 3 offers no way to build a
/// private-key object *without* deriving its public one. For X25519,
/// `ossl_ecx_key_fromdata` calls `ossl_ecx_public_from_private` whenever
/// the public parameter is absent — which `EVP_PKEY_new_raw_private_key`
/// always leaves absent — and the EC path's `fromdata` rejects a keypair
/// selection that carries only the scalar. So an agreement handed only a
/// scalar pays for a fixed-base scalar multiplication and then throws the
/// answer away. That was ~18 µs of a ~43 µs X25519 agreement, and a
/// handshake did it twice: once on each peer, on top of the multiplication
/// each had already done to put a share on the wire (bench/README.md).
///
/// Bundled rather than passed as a second argument to `agree` so the two
/// halves cannot disagree: only `init` builds one, and it builds both. A
/// public value that did not match its scalar would derive a shared
/// secret the peer does not hold, and surface three flights later as a
/// bad record MAC — the same shape as the key-selection bug
/// `ClientHandshake` records in its own comment.
///
/// The scalar is copied in. The embedder's original outlives this
/// (`Config` owns it); `deinit` zeroes the copy.
pub const KeyShare = struct {
    group: Group,
    private: [group_private_bytes_max]u8,
    public: [group_public_bytes_max]u8,

    pub fn init(group: Group, private_key: []const u8) Error!KeyShare {
        assert(private_key.len == group.privateBytes());
        var share: KeyShare = undefined;
        share.group = group;
        @memset(&share.private, 0);
        @memcpy(share.private[0..private_key.len], private_key);
        errdefer std.crypto.secureZero(u8, &share.private);
        @memset(&share.public, 0);
        // The one multiplication. Everything else here exists so that it
        // happens exactly once.
        const public = try keySharePublic(group, private_key, &share.public);
        assert(public.len == group.publicBytes());
        assert(share.group == group);
        // A point that came back all zero is not a point, and every caller
        // is about to put this on the wire as its KeyShareEntry.
        assert(!std.mem.allEqual(u8, public, 0));
        return share;
    }

    pub fn deinit(self: *KeyShare) void {
        std.crypto.secureZero(u8, &self.private);
        self.* = undefined;
    }

    /// What goes in the KeyShareEntry.
    pub fn publicValue(self: *const KeyShare) []const u8 {
        return self.public[0..self.group.publicBytes()];
    }

    fn privateValue(self: *const KeyShare) []const u8 {
        return self.private[0..self.group.privateBytes()];
    }

    /// §7.4.2's shared secret: X25519's raw output, or the x-coordinate
    /// of the ECDH point. An all-zero result is `IdentityElement`, the
    /// abort §7.4.2 names, and libcrypto refuses a point off the curve
    /// for us.
    pub fn agree(self: *const KeyShare, peer_public: []const u8, out: []u8) Error![]u8 {
        assert(out.len >= self.group.sharedBytes());
        errdefer clearErrorQueue();
        // A peer value of the wrong length never reaches libcrypto: the
        // length is the peer's to choose and this is the boundary that
        // checks it (DESIGN.md §2).
        if (peer_public.len != self.group.publicBytes()) return error.IdentityElement;

        const pkey = if (self.group == .x25519)
            try x25519FromKeypair(
                self.private[0..x25519_key_bytes],
                self.public[0..x25519_key_bytes],
            )
        else blk: {
            if (peer_public[0] != 0x04) return error.IdentityElement; // §4.2.8.2: uncompressed only.
            break :blk try ecFromKeypair(self.group, self.privateValue(), self.publicValue());
        };
        defer c.EVP_PKEY_free(pkey);

        const peer = if (self.group == .x25519)
            c.EVP_PKEY_new_raw_public_key(
                c.EVP_PKEY_X25519,
                null,
                peer_public.ptr,
                x25519_key_bytes,
            ) orelse return error.LibcryptoFailed
        else
            try ecFromPublic(self.group, peer_public);
        defer c.EVP_PKEY_free(peer);

        const ctx = c.EVP_PKEY_CTX_new(pkey, null) orelse return error.LibcryptoFailed;
        defer c.EVP_PKEY_CTX_free(ctx);
        if (c.EVP_PKEY_derive_init(ctx) != 1) return error.LibcryptoFailed;
        if (c.EVP_PKEY_derive_set_peer(ctx, peer) != 1) return error.IdentityElement;
        var shared_len: usize = out.len;
        if (c.EVP_PKEY_derive(ctx, out.ptr, &shared_len) != 1) return error.IdentityElement;
        if (shared_len != self.group.sharedBytes()) return error.LibcryptoFailed;
        // libcrypto already rejects the low-order X25519 result; asserting
        // the negative space here keeps the §7.4.2 guarantee ours.
        if (std.mem.allEqual(u8, out[0..shared_len], 0)) return error.IdentityElement;
        return out[0..shared_len];
    }
};

/// One-shot agreement, for a caller that holds no `KeyShare`: build one,
/// use it, drop it.
///
/// This pays the fixed-base multiplication `KeyShare.init` does, which is
/// exactly what holding a share avoids — so the two handshakes hold one
/// and this is for test scaffolding, which agrees once and does not care.
pub fn keyShareShared(
    group: Group,
    private_key: []const u8,
    peer_public: []const u8,
    out: []u8,
) Error![]u8 {
    var share = try KeyShare.init(group, private_key);
    defer share.deinit();
    return share.agree(peer_public, out);
}

/// An X25519 `EVP_PKEY` carrying both halves, so that
/// `ossl_ecx_key_fromdata` takes the public one as given rather than
/// multiplying for it. `EVP_PKEY_new_raw_private_key` cannot express
/// this — it builds a params array with the private key alone.
fn x25519FromKeypair(
    private_key: *const [x25519_key_bytes]u8,
    public_key: *const [x25519_key_bytes]u8,
) Error!*c.EVP_PKEY {
    const builder = c.OSSL_PARAM_BLD_new() orelse return error.LibcryptoFailed;
    defer c.OSSL_PARAM_BLD_free(builder);
    if (c.OSSL_PARAM_BLD_push_octet_string(
        builder,
        c.OSSL_PKEY_PARAM_PRIV_KEY,
        private_key,
        x25519_key_bytes,
    ) != 1) return error.LibcryptoFailed;
    if (c.OSSL_PARAM_BLD_push_octet_string(
        builder,
        c.OSSL_PKEY_PARAM_PUB_KEY,
        public_key,
        x25519_key_bytes,
    ) != 1) return error.LibcryptoFailed;
    return pkeyFromBuilder("X25519", builder, c.EVP_PKEY_KEYPAIR);
}

/// Build an EC `EVP_PKEY` from a scalar and the point it implies. The
/// point is passed in rather than computed: `fromdata` does not derive
/// the public half from the private, and a keypair selection without it
/// is rejected, so somebody has to supply it — and `KeyShare` already
/// has.
fn ecFromKeypair(group: Group, private_key: []const u8, public_key: []const u8) Error!*c.EVP_PKEY {
    const bn = c.BN_bin2bn(private_key.ptr, @intCast(private_key.len), null) orelse
        return error.LibcryptoFailed;
    defer c.BN_clear_free(bn);
    const builder = c.OSSL_PARAM_BLD_new() orelse return error.LibcryptoFailed;
    defer c.OSSL_PARAM_BLD_free(builder);
    const name = group.curveName();
    if (c.OSSL_PARAM_BLD_push_utf8_string(
        builder,
        c.OSSL_PKEY_PARAM_GROUP_NAME,
        name.ptr,
        name.len,
    ) != 1) return error.LibcryptoFailed;
    if (c.OSSL_PARAM_BLD_push_BN(builder, c.OSSL_PKEY_PARAM_PRIV_KEY, bn) != 1)
        return error.LibcryptoFailed;
    if (c.OSSL_PARAM_BLD_push_octet_string(
        builder,
        c.OSSL_PKEY_PARAM_PUB_KEY,
        public_key.ptr,
        public_key.len,
    ) != 1) return error.LibcryptoFailed;
    return pkeyFromBuilder("EC", builder, c.EVP_PKEY_KEYPAIR);
}

/// The peer's point, as an uncompressed SEC1 octet string. libcrypto
/// rejects a point that is not on the curve at import, which is where
/// §4.2.8.2's validation actually happens.
fn ecFromPublic(group: Group, peer_public: []const u8) Error!*c.EVP_PKEY {
    const builder = c.OSSL_PARAM_BLD_new() orelse return error.LibcryptoFailed;
    defer c.OSSL_PARAM_BLD_free(builder);
    const name = group.curveName();
    if (c.OSSL_PARAM_BLD_push_utf8_string(
        builder,
        c.OSSL_PKEY_PARAM_GROUP_NAME,
        name.ptr,
        name.len,
    ) != 1) return error.LibcryptoFailed;
    if (c.OSSL_PARAM_BLD_push_octet_string(
        builder,
        c.OSSL_PKEY_PARAM_PUB_KEY,
        peer_public.ptr,
        peer_public.len,
    ) != 1) return error.LibcryptoFailed;
    return pkeyFromBuilder("EC", builder, c.EVP_PKEY_PUBLIC_KEY);
}

fn pkeyFromBuilder(
    algorithm: [:0]const u8,
    builder: *c.OSSL_PARAM_BLD,
    selection: c_int,
) Error!*c.EVP_PKEY {
    const params = c.OSSL_PARAM_BLD_to_param(builder) orelse return error.LibcryptoFailed;
    defer c.OSSL_PARAM_free(params);
    const ctx = c.EVP_PKEY_CTX_new_from_name(null, algorithm.ptr, null) orelse
        return error.LibcryptoFailed;
    defer c.EVP_PKEY_CTX_free(ctx);
    if (c.EVP_PKEY_fromdata_init(ctx) != 1) return error.LibcryptoFailed;
    var pkey: ?*c.EVP_PKEY = null;
    if (c.EVP_PKEY_fromdata(ctx, &pkey, selection, params) != 1) return error.IdentityElement;
    return pkey orelse error.LibcryptoFailed;
}

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
    /// §4.4.3 forbids rsa_pkcs1_* in CertificateVerify, so an RSA leaf
    /// signs PSS or not at all. All three digests, because the choice is
    /// the *peer's*: a client that offers only rsa_pss_rsae_sha384 is a
    /// client we can still answer, and refusing it would be a handshake
    /// failure over a digest we hold.
    rsa_pss_rsae_sha256 = 0x0804,
    rsa_pss_rsae_sha384 = 0x0805,
    rsa_pss_rsae_sha512 = 0x0806,

    fn digest(scheme: SignatureScheme) *const c.EVP_MD {
        return switch (scheme) {
            .ecdsa_secp256r1_sha256, .rsa_pss_rsae_sha256 => c.EVP_sha256(),
            .ecdsa_secp384r1_sha384, .rsa_pss_rsae_sha384 => c.EVP_sha384(),
            .rsa_pss_rsae_sha512 => c.EVP_sha512(),
        } orelse unreachable; // Statically-linked digests always exist.
    }

    fn isRsaPss(scheme: SignatureScheme) bool {
        return switch (scheme) {
            .rsa_pss_rsae_sha256, .rsa_pss_rsae_sha384, .rsa_pss_rsae_sha512 => true,
            .ecdsa_secp256r1_sha256, .ecdsa_secp384r1_sha384 => false,
        };
    }
};

/// The most schemes one key admits: an RSA modulus signs PSS under any of
/// three digests, an EC key under exactly the one its curve names.
pub const schemes_max: u8 = 3;

/// A DER ECDSA-Sig-Value is at most 72 bytes for P-256 and 104 for P-384;
/// an RSA-PSS signature is exactly the modulus, which `Signer.fromPem`
/// bounds at 4096 bits. The larger of the two is the buffer everything
/// downstream sizes against.
pub const signature_bytes_max: u16 = 512;

/// The RSA moduli we will sign with. The floor is what PSS-SHA256 with a
/// digest-length salt needs before it is worth anything and what the
/// public web has used for a decade; the ceiling is what
/// `signature_bytes_max` reserves, refused at load rather than discovered
/// mid-flight.
pub const rsa_bits_min: u32 = 2048;
pub const rsa_bits_max: u32 = 4096;

/// A signing key held as a libcrypto `EVP_PKEY` — ECDSA P-256/P-384, or
/// RSA under PSS. Lives from credential load to shutdown; each `sign`
/// call creates and frees one digest context through the hooked
/// allocator — handshake-time cost, never per-record.
/// §4.4.3's PSS parameters, spelled out rather than left to libcrypto's
/// default: an RSA `EVP_PKEY` signs PKCS#1 v1.5 unless told otherwise,
/// and v1.5 is the one padding TLS 1.3 forbids in CertificateVerify. The
/// salt is the digest's own length and MGF1 uses the same digest, which
/// is what §4.4.3 requires and what a peer will check.
fn configureRsaPss(scheme: SignatureScheme, pkey_ctx: ?*c.EVP_PKEY_CTX) SignError!void {
    if (!scheme.isRsaPss()) return;
    const ctx = pkey_ctx orelse return error.LibcryptoFailed;
    if (c.EVP_PKEY_CTX_set_rsa_padding(ctx, c.RSA_PKCS1_PSS_PADDING) <= 0) {
        return error.LibcryptoFailed;
    }
    if (c.EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, c.RSA_PSS_SALTLEN_DIGEST) <= 0) {
        return error.LibcryptoFailed;
    }
    if (c.EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, scheme.digest()) <= 0) {
        return error.LibcryptoFailed;
    }
}

pub const Signer = struct {
    pkey: *c.EVP_PKEY,
    /// Every scheme this key can sign under, in our preference order.
    /// The peer picks from it: §4.4.2 requires the CertificateVerify to
    /// name a scheme the client offered, and an RSA key admits three.
    schemes: [schemes_max]SignatureScheme,
    scheme_count: u8,
    /// Opt-in RFC 6979 nonces make the signature — and through DER
    /// integer trimming, the flight length — a pure function of key and
    /// transcript, which is what seeded-simulation replay needs. Off in
    /// production: hedged random nonces are the conservative default.
    deterministic_nonces: bool,

    /// Load a PEM private key and classify it. Everything outside the
    /// policy — a curve we do not sign on, an RSA modulus outside
    /// `rsa_bits_min`..`rsa_bits_max` — is refused here, at load, where
    /// the operator can read the error rather than meeting it mid-flight
    /// with a client already waiting on a flight.
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

        const bits = c.EVP_PKEY_get_bits(pkey);
        var schemes: [schemes_max]SignatureScheme = undefined;
        var count: u8 = 0;
        if (c.EVP_PKEY_is_a(pkey, "EC") == 1) {
            schemes[0] = switch (bits) {
                256 => .ecdsa_secp256r1_sha256,
                384 => .ecdsa_secp384r1_sha384,
                else => return error.UnsupportedKey,
            };
            count = 1;
        } else if (c.EVP_PKEY_is_a(pkey, "RSA") == 1) {
            if (bits < rsa_bits_min or bits > rsa_bits_max) return error.UnsupportedKey;
            // PSS draws a fresh salt per signature, so a signature over
            // the same transcript is never the same bytes twice. An
            // embedder that asked for replayable flights has to be told
            // it cannot have them with this key, not quietly given random
            // ones — the same loudness the ECDSA path gets from
            // `requireDeterministicNonce`.
            if (deterministic_nonces) return error.DeterministicNonceUnsupported;
            schemes[0] = .rsa_pss_rsae_sha256;
            schemes[1] = .rsa_pss_rsae_sha384;
            schemes[2] = .rsa_pss_rsae_sha512;
            count = 3;
        } else return error.UnsupportedKey;
        assert(count >= 1);
        assert(count <= schemes_max);
        return .{
            .pkey = pkey,
            .schemes = schemes,
            .scheme_count = count,
            .deterministic_nonces = deterministic_nonces,
        };
    }

    pub fn deinit(self: *Signer) void {
        assert(self.scheme_count >= 1);
        c.EVP_PKEY_free(self.pkey);
        self.* = undefined;
    }

    /// What this key can sign under, in our preference order — the list
    /// a server intersects with the client's signature_algorithms.
    pub fn supported(self: *const Signer) []const SignatureScheme {
        assert(self.scheme_count >= 1);
        assert(self.scheme_count <= schemes_max);
        return self.schemes[0..self.scheme_count];
    }

    /// Sign `content` (the full CertificateVerify content structure — the
    /// digest happens inside). Returns the DER signature written into `out`.
    pub fn sign(
        self: *const Signer,
        scheme: SignatureScheme,
        content: []const u8,
        out: []u8,
    ) SignError![]const u8 {
        errdefer clearErrorQueue();
        assert(content.len >= 1);
        assert(out.len >= signature_bytes_max);
        // The caller chose from `supported`; anything else would sign
        // under a digest this key does not admit.
        assert(std.mem.indexOfScalar(SignatureScheme, self.supported(), scheme) != null);
        const ctx = c.EVP_MD_CTX_new() orelse return error.LibcryptoFailed;
        defer c.EVP_MD_CTX_free(ctx);

        var pkey_ctx: ?*c.EVP_PKEY_CTX = null;
        if (c.EVP_DigestSignInit(ctx, &pkey_ctx, scheme.digest(), null, self.pkey) != 1)
            return error.LibcryptoFailed;
        try configureRsaPss(scheme, pkey_ctx);
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
    pub fn verify(
        self: *const Signer,
        scheme: SignatureScheme,
        content: []const u8,
        signature: []const u8,
    ) SignError!void {
        errdefer clearErrorQueue();
        assert(content.len >= 1);
        assert(signature.len >= 8);
        assert(std.mem.indexOfScalar(SignatureScheme, self.supported(), scheme) != null);
        const ctx = c.EVP_MD_CTX_new() orelse return error.LibcryptoFailed;
        defer c.EVP_MD_CTX_free(ctx);
        var pkey_ctx: ?*c.EVP_PKEY_CTX = null;
        if (c.EVP_DigestVerifyInit(ctx, &pkey_ctx, scheme.digest(), null, self.pkey) != 1)
            return error.LibcryptoFailed;
        try configureRsaPss(scheme, pkey_ctx);
        if (c.EVP_DigestVerifyUpdate(ctx, content.ptr, content.len) != 1) return error.LibcryptoFailed;
        if (c.EVP_DigestVerifyFinal(ctx, signature.ptr, signature.len) != 1)
            return error.SignatureInvalid;
    }
};

pub const VerifyError = Error || error{
    /// The octet string is not a public key on the scheme's curve —
    /// wrong length, not a point encoding, or not on the curve.
    /// libcrypto validates at import, and this is that refusal.
    BadPublicKey,
    /// The signature did not verify against the key.
    SignatureInvalid,
};

/// Verify a *peer's* ECDSA signature against a public key we were handed,
/// as a SEC1 octet string — the CertificateVerify path.
///
/// `Signer.verify` is the same operation from the other side of a keypair
/// we loaded ourselves, and is test-side tooling. This one is production:
/// the key, the signature and the content all came off the wire, and only
/// the content was assembled by us.
///
/// The two failures are kept apart because the caller owes the peer
/// different alerts for them. `BadPublicKey` is a leaf we cannot use;
/// `SignatureInvalid` is a signature that did not check out. libcrypto
/// re-encodes the DER ECDSA-Sig-Value and compares it against the input
/// before verifying, so a non-canonical encoding lands in the second —
/// the same strictness `std.crypto`'s `Signature.fromDer` applied, which
/// matters because BoGo asks for it.
pub fn verifyEcdsa(
    scheme: SignatureScheme,
    public_key_sec1: []const u8,
    content: []const u8,
    signature_der: []const u8,
) VerifyError!void {
    errdefer clearErrorQueue();
    assert(content.len >= 1);
    assert(signature_der.len >= 1);
    // The caller chose an ECDSA scheme; RSA-PSS has no curve to name.
    assert(!scheme.isRsaPss());
    const group: Group = switch (scheme) {
        .ecdsa_secp256r1_sha256 => .secp256r1,
        .ecdsa_secp384r1_sha384 => .secp384r1,
        else => unreachable, // The assert above admitted only these two.
    };

    // Point validation happens here, at import, exactly as it does for a
    // KeyShareEntry: a point off the curve never reaches the verifier.
    const pkey = ecFromPublic(group, public_key_sec1) catch |err| return switch (err) {
        error.IdentityElement => error.BadPublicKey,
        else => err,
    };
    defer c.EVP_PKEY_free(pkey);

    const ctx = c.EVP_MD_CTX_new() orelse return error.LibcryptoFailed;
    defer c.EVP_MD_CTX_free(ctx);
    if (c.EVP_DigestVerifyInit(ctx, null, scheme.digest(), null, pkey) != 1)
        return error.LibcryptoFailed;
    if (c.EVP_DigestVerifyUpdate(ctx, content.ptr, content.len) != 1)
        return error.LibcryptoFailed;
    if (c.EVP_DigestVerifyFinal(ctx, signature_der.ptr, signature_der.len) != 1)
        return error.SignatureInvalid;
}

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
    const p256 = SignatureScheme.ecdsa_secp256r1_sha256;
    try std.testing.expectEqualSlices(
        SignatureScheme,
        &.{p256},
        deterministic.supported(),
    );

    var first_buffer: [signature_bytes_max]u8 = undefined;
    var second_buffer: [signature_bytes_max]u8 = undefined;
    const first = try deterministic.sign(p256, content, &first_buffer);
    const second = try deterministic.sign(p256, content, &second_buffer);
    // RFC 6979: same key, same content — the same signature, bit for bit.
    try std.testing.expectEqualSlices(u8, first, second);
    try deterministic.verify(p256, content, first);

    // Negative space: a tampered signature and tampered content both fail.
    var tampered_buffer: [signature_bytes_max]u8 = undefined;
    @memcpy(tampered_buffer[0..first.len], first);
    tampered_buffer[first.len - 1] ^= 1;
    try std.testing.expectError(error.SignatureInvalid, deterministic.verify(p256, content, tampered_buffer[0..first.len]));
    try std.testing.expectError(error.SignatureInvalid, deterministic.verify(p256, "TLS 1.3 test content, signed 0nce", first));

    // Hedged (default) nonces: two signatures over the same content differ.
    var hedged = try Signer.fromPem(key_pem, false);
    defer hedged.deinit();
    const third = try hedged.sign(p256, content, &first_buffer);
    const fourth = try hedged.sign(p256, content, &second_buffer);
    try std.testing.expect(!std.mem.eql(u8, third, fourth));
    try hedged.verify(p256, content, third);
    try hedged.verify(p256, content, fourth);
}

test "an RSA key offers all three PSS digests and signs under each" {
    const key_pem = @embedFile("../testdata/rsa2048-key.pem");
    const content = "TLS 1.3 CertificateVerify content, PSS";

    var signer = try Signer.fromPem(key_pem, false);
    defer signer.deinit();
    // The digest is the peer's choice among these, never ours alone.
    try std.testing.expectEqualSlices(
        SignatureScheme,
        &.{ .rsa_pss_rsae_sha256, .rsa_pss_rsae_sha384, .rsa_pss_rsae_sha512 },
        signer.supported(),
    );

    var buffer: [signature_bytes_max]u8 = undefined;
    for (signer.supported()) |scheme| {
        const signature = try signer.sign(scheme, content, &buffer);
        // PSS emits exactly the modulus, and a v1.5 signature would too —
        // what separates them is that verification is configured for PSS
        // on both sides, so a v1.5 signature would not round-trip here.
        try std.testing.expectEqual(@as(usize, 256), signature.len);
        try signer.verify(scheme, content, signature);
    }

    // Negative space: a fresh salt per signature means PSS is never
    // reproducible, which is why deterministic nonces are refused at load.
    var first: [signature_bytes_max]u8 = undefined;
    var second: [signature_bytes_max]u8 = undefined;
    const a = try signer.sign(.rsa_pss_rsae_sha256, content, &first);
    const b = try signer.sign(.rsa_pss_rsae_sha256, content, &second);
    try std.testing.expect(!std.mem.eql(u8, a, b));
}

test "signer refuses what policy excludes" {
    // An Ed25519 key is a fine key for someone else's TLS library.
    const ed25519_pem =
        "-----BEGIN PRIVATE KEY-----\n" ++
        "MC4CAQAwBQYDK2VwBCIEIFf+dQTz6cUdWa5TXBWSGCNjZfbWEUxTAKF+bmKlbYzR\n" ++
        "-----END PRIVATE KEY-----\n";
    try std.testing.expectError(error.UnsupportedKey, Signer.fromPem(ed25519_pem, false));
}

test "P-256 and P-384 key exchange agree with std.crypto and with themselves" {
    const std_curves = .{
        .{ Group.secp256r1, std.crypto.ecc.P256 },
        .{ Group.secp384r1, std.crypto.ecc.P384 },
    };
    inline for (std_curves) |pair| {
        const group: Group = pair[0];
        const Curve = pair[1];
        const private_bytes = comptime group.privateBytes();

        // Two scalars an embedder might have handed us. Fixed, because
        // zssl draws no randomness and neither does its test suite.
        var alice: [group_private_bytes_max]u8 = undefined;
        var bob: [group_private_bytes_max]u8 = undefined;
        for (0..private_bytes) |i| {
            alice[i] = @intCast((i * 7 + 3) & 0x7f);
            bob[i] = @intCast((i * 11 + 5) & 0x7f);
        }

        var alice_public: [group_public_bytes_max]u8 = undefined;
        var bob_public: [group_public_bytes_max]u8 = undefined;
        const alice_share = try keySharePublic(group, alice[0..private_bytes], &alice_public);
        const bob_share = try keySharePublic(group, bob[0..private_bytes], &bob_public);
        try std.testing.expectEqual(@as(usize, group.publicBytes()), alice_share.len);
        try std.testing.expectEqual(@as(u8, 0x04), alice_share[0]); // §4.2.8.2: uncompressed.

        // Oracle one: `std.crypto`'s own scalar multiplication, which
        // shares no line of code with libcrypto's.
        const expected = try Curve.basePoint.mul(alice[0..private_bytes].*, .big);
        try std.testing.expectEqualSlices(u8, &expected.toUncompressedSec1(), alice_share);

        // Oracle two: both sides reach the same secret, which is the
        // property the key schedule actually rests on.
        var alice_shared: [group_shared_bytes_max]u8 = undefined;
        var bob_shared: [group_shared_bytes_max]u8 = undefined;
        const from_alice = try keyShareShared(group, alice[0..private_bytes], bob_share, &alice_shared);
        const from_bob = try keyShareShared(group, bob[0..private_bytes], alice_share, &bob_shared);
        try std.testing.expectEqualSlices(u8, from_alice, from_bob);
        try std.testing.expectEqual(@as(usize, group.sharedBytes()), from_alice.len);

        // And §7.4.2's own arithmetic, taken from std: the shared secret
        // is the x-coordinate of the product point, nothing more.
        const peer = try Curve.fromSec1(bob_share);
        const product = try peer.mul(alice[0..private_bytes].*, .big);
        try std.testing.expectEqualSlices(
            u8,
            &product.affineCoordinates().x.toBytes(.big),
            from_alice,
        );

        // Negative space: a point that is not on the curve, a compressed
        // point, and a truncated one are all refused at the boundary
        // rather than reaching the key schedule.
        var bogus: [group_public_bytes_max]u8 = undefined;
        @memcpy(bogus[0..alice_share.len], alice_share);
        bogus[alice_share.len - 1] ^= 0xff;
        try std.testing.expectError(error.IdentityElement, keyShareShared(
            group,
            bob[0..private_bytes],
            bogus[0..alice_share.len],
            &bob_shared,
        ));
        @memcpy(bogus[0..alice_share.len], alice_share);
        bogus[0] = 0x02; // compressed form, which §4.2.8.2 forbids
        try std.testing.expectError(error.IdentityElement, keyShareShared(
            group,
            bob[0..private_bytes],
            bogus[0..alice_share.len],
            &bob_shared,
        ));
        try std.testing.expectError(error.IdentityElement, keyShareShared(
            group,
            bob[0..private_bytes],
            alice_share[0 .. alice_share.len - 1],
            &bob_shared,
        ));
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

test "KeyShare bundles both halves and agrees exactly as the one-shot does" {
    const groups = [_]Group{ .x25519, .secp256r1, .secp384r1 };
    for (groups) |group| {
        const private_bytes = group.privateBytes();
        var alice: [group_private_bytes_max]u8 = undefined;
        var bob: [group_private_bytes_max]u8 = undefined;
        for (0..private_bytes) |i| {
            alice[i] = @intCast((i * 7 + 3) & 0x7f);
            bob[i] = @intCast((i * 11 + 5) & 0x7f);
        }

        var alice_share = try KeyShare.init(group, alice[0..private_bytes]);
        defer alice_share.deinit();
        var bob_share = try KeyShare.init(group, bob[0..private_bytes]);
        defer bob_share.deinit();

        // The bundled public half is the same value the standalone
        // multiplication produces — the bundle is an accounting change,
        // not an arithmetic one.
        var expected_public: [group_public_bytes_max]u8 = undefined;
        try std.testing.expectEqualSlices(
            u8,
            try keySharePublic(group, alice[0..private_bytes], &expected_public),
            alice_share.publicValue(),
        );

        // Both directions reach one secret, which is what the key
        // schedule rests on.
        var from_alice: [group_shared_bytes_max]u8 = undefined;
        var from_bob: [group_shared_bytes_max]u8 = undefined;
        const alice_secret = try alice_share.agree(bob_share.publicValue(), &from_alice);
        const bob_secret = try bob_share.agree(alice_share.publicValue(), &from_bob);
        try std.testing.expectEqualSlices(u8, alice_secret, bob_secret);

        // And the same secret the one-shot wrapper reaches, which is the
        // path that still re-derives the public half. Skipping that
        // multiplication must not change the answer.
        var one_shot: [group_shared_bytes_max]u8 = undefined;
        try std.testing.expectEqualSlices(u8, alice_secret, try keyShareShared(
            group,
            alice[0..private_bytes],
            bob_share.publicValue(),
            &one_shot,
        ));

        // Negative space: a peer value of the wrong length is refused at
        // the boundary, before libcrypto sees it.
        try std.testing.expectError(
            error.IdentityElement,
            alice_share.agree(bob_share.publicValue()[0 .. group.publicBytes() - 1], &from_alice),
        );
    }
    try std.testing.expectEqual(@as(c_ulong, 0), c.ERR_peek_error());
}

test "verifyEcdsa accepts a std.crypto signature and keeps its two refusals apart" {
    // The differential that matters: `std.crypto` signs, libcrypto
    // verifies, and the two share no line of code. This is the oracle
    // for moving `ClientHandshake.verifyEcdsa` across the boundary.
    const curves = .{
        .{ SignatureScheme.ecdsa_secp256r1_sha256, std.crypto.sign.ecdsa.EcdsaP256Sha256 },
        .{ SignatureScheme.ecdsa_secp384r1_sha384, std.crypto.sign.ecdsa.EcdsaP384Sha384 },
    };
    inline for (curves) |pair| {
        const scheme: SignatureScheme = pair[0];
        const Ecdsa = pair[1];

        const seed = [_]u8{0x5c} ** Ecdsa.KeyPair.seed_length;
        const keys = try Ecdsa.KeyPair.generateDeterministic(seed);
        const sec1 = keys.public_key.toUncompressedSec1();
        // A CertificateVerify content structure's shape and length; the
        // bytes themselves do not matter to a signature check.
        const content = [_]u8{0x20} ** 130;
        var der_storage: [Ecdsa.Signature.der_encoded_length_max]u8 = undefined;
        const der = (try keys.sign(&content, null)).toDer(&der_storage);

        try verifyEcdsa(scheme, &sec1, &content, der);

        // A signature over other content, and a mangled one. Both are
        // `SignatureInvalid` — libcrypto's ASN.1 decoder rejecting the
        // encoding and its verifier rejecting the maths are the same
        // answer to the peer, exactly as `std.crypto`'s were.
        const other = [_]u8{0x21} ** 130;
        try std.testing.expectError(
            error.SignatureInvalid,
            verifyEcdsa(scheme, &sec1, &other, der),
        );
        var mangled = der_storage;
        mangled[der.len - 1] ^= 0xff;
        try std.testing.expectError(
            error.SignatureInvalid,
            verifyEcdsa(scheme, &sec1, &content, mangled[0..der.len]),
        );
        // §4.4.3 framing is exact: a trailing byte is not a signature
        // that failed, and libcrypto's canonical re-encode catches it.
        var trailing: [Ecdsa.Signature.der_encoded_length_max + 1]u8 = undefined;
        @memcpy(trailing[0..der.len], der);
        trailing[der.len] = 0x00;
        try std.testing.expectError(
            error.SignatureInvalid,
            verifyEcdsa(scheme, &sec1, &content, trailing[0 .. der.len + 1]),
        );

        // A leaf we cannot use is a *different* answer from a signature
        // that failed: `ClientHandshake` maps this one to bad_certificate
        // and the three above to decrypt_error, and that split is the
        // whole reason `VerifyError` carries two names.
        var off_curve = sec1;
        off_curve[off_curve.len - 1] ^= 0xff;
        try std.testing.expectError(
            error.BadPublicKey,
            verifyEcdsa(scheme, &off_curve, &content, der),
        );
        try std.testing.expectError(
            error.BadPublicKey,
            verifyEcdsa(scheme, sec1[0 .. sec1.len - 1], &content, der),
        );
        // A point for the other curve, which is the shape a peer gets by
        // naming a scheme its leaf does not carry.
        const other_scheme: SignatureScheme = if (scheme == .ecdsa_secp256r1_sha256)
            .ecdsa_secp384r1_sha384
        else
            .ecdsa_secp256r1_sha256;
        try std.testing.expectError(
            error.BadPublicKey,
            verifyEcdsa(other_scheme, &sec1, &content, der),
        );
    }
    try std.testing.expectEqual(@as(c_ulong, 0), c.ERR_peek_error());
}
