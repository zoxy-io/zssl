//! RFC 9001: TLS 1.3 for QUIC.
//!
//! Two halves, and they land on opposite sides of the trust split
//! DESIGN.md §2 draws.
//!
//! **Packet protection** is computation: §5.3's AEAD and §5.4's header
//! protection, over keys the transport derived. It is libcrypto's for
//! the reason record protection is — constant-time AEAD and AES are the
//! primitives that split exists to hand to the most-watched assembly
//! available — and it is here because zssl is the one place in an
//! embedder's binary allowed to bind libcrypto. `PacketKey` and
//! `HeaderKey` are that surface; the QUIC key schedule above them (which
//! secret, which label, which packet number) is the transport's, and
//! HKDF stays the pure-Zig `hkdf` the TLS schedule already uses.
//!
//! Both are created once per key — the one libcrypto allocation, landing
//! in the embedder's fixed heap like every other context — and allocate
//! nothing per packet.

const std = @import("std");
const assert = std.debug.assert;

const backend = @import("crypto/backend_openssl.zig");
const cipher_suite = @import("cipher_suite.zig");
const CipherSuite = cipher_suite.CipherSuite;

/// §5.3: AEAD_AES_128_GCM, AEAD_AES_256_GCM and AEAD_CHACHA20_POLY1305
/// all carry a 16-octet tag and a 12-octet nonce.
pub const tag_bytes: u8 = cipher_suite.tag_bytes;
pub const nonce_bytes: u8 = cipher_suite.nonce_bytes;
/// §5.4.2: header protection samples 16 octets of ciphertext and yields a
/// 5-octet mask — one for the first byte, four for the packet number.
pub const sample_bytes: u8 = backend.HeaderProtection.sample_bytes;
pub const mask_bytes: u8 = backend.HeaderProtection.mask_bytes;
/// The largest payload one call protects. RFC 9000 §14 caps a UDP
/// payload, and so a packet, below 2^16 octets.
pub const payload_bytes_max: u32 = backend.PacketAead.payload_bytes_max;

pub const Error = backend.Error;

/// §8.2: the `quic_transport_parameters` extension. Its body is the
/// transport's encoding (RFC 9000 §18), opaque to TLS: zssl carries ours
/// out in a ClientHello or EncryptedExtensions and hands the peer's back.
pub const transport_parameters_extension: u16 = 0x39;

/// The longest body *we* send. RFC 9000 sets no ceiling, but ours goes
/// into fixed buffers — the ClientHello's and the server flight's — so
/// it needs one. Every parameter v1 defines, at its widest, with a
/// preferred address and three connection IDs, is under 200 octets;
/// the rest is room for GREASE (§18.1's reserved identifiers). The
/// peer's body has no such bound here: it is read where it lies.
pub const transport_parameters_bytes_max: u16 = 512;

comptime {
    assert(tag_bytes == 16);
    assert(nonce_bytes == 12);
    assert(sample_bytes == 16);
    assert(mask_bytes == 5);
}

/// §5.3's nonce: the IV with the full 62-bit packet number XORed into its
/// low octets, left-padded with zeroes. The *reconstructed* number, never
/// the truncation the header carried — the AEAD's whole security rests
/// on the nonce never repeating under one key.
///
/// The caller reconstructs it under RFC 9000 Appendix A.3, whose result
/// is below 2^62 by construction; a decoder that let a peer's truncated
/// number wander past that has a bug this assertion is there to catch.
pub fn nonce(iv: *const [nonce_bytes]u8, packet_number: u64) [nonce_bytes]u8 {
    // RFC 9000 §12.3: packet numbers are 0..2^62-1.
    assert(packet_number < (1 << 62));
    var result = iv.*;
    var number_octets: [8]u8 = undefined;
    std.mem.writeInt(u64, &number_octets, packet_number, .big);
    for (result[nonce_bytes - 8 ..], number_octets) |*target, octet| target.* ^= octet;
    assert(result.len == nonce_bytes);
    return result;
}

/// One §5.3 packet-protection key, used in one direction.
pub const PacketKey = struct {
    aead: backend.PacketAead,

    pub const Direction = backend.PacketAead.Direction;

    /// `key` is §5.1's "quic key" output: 16 octets for AES-128-GCM, 32
    /// for the other two.
    pub fn init(suite: CipherSuite, key: []const u8, direction: Direction) Error!PacketKey {
        assert(key.len == suite.keyBytes());
        const aead = try backend.PacketAead.init(suite, key, direction);
        assert(aead.direction == direction);
        return .{ .aead = aead };
    }

    pub fn deinit(self: *PacketKey) void {
        assert(self.aead.key_bytes == 16 or self.aead.key_bytes == 32);
        self.aead.deinit();
        self.* = undefined;
    }

    /// Encrypt `payload` in place; the tag goes to `tag`. `associated_data`
    /// is the packet's header up to and including the packet number, in
    /// the clear — §5.3, before §5.4 masks it.
    pub fn sealDetached(
        self: *PacketKey,
        packet_nonce: *const [nonce_bytes]u8,
        associated_data: []const u8,
        payload: []u8,
        tag: *[tag_bytes]u8,
    ) Error!void {
        assert(self.aead.direction == .seal);
        assert(payload.len <= payload_bytes_max);
        try self.aead.seal(packet_nonce, associated_data, payload, tag);
    }

    /// Encrypt `buffer[0..payload_bytes]` in place and append the tag
    /// behind it: the wire shape, where the tag follows the ciphertext.
    /// Answers the sealed bytes, `payload_bytes + tag_bytes` of them.
    pub fn seal(
        self: *PacketKey,
        packet_nonce: *const [nonce_bytes]u8,
        associated_data: []const u8,
        buffer: []u8,
        payload_bytes: usize,
    ) Error![]u8 {
        assert(payload_bytes <= payload_bytes_max);
        assert(buffer.len >= payload_bytes + tag_bytes);
        const tag = buffer[payload_bytes..][0..tag_bytes];
        try self.sealDetached(packet_nonce, associated_data, buffer[0..payload_bytes], tag);
        return buffer[0 .. payload_bytes + tag_bytes];
    }

    /// Decrypt `payload` in place against `tag`. On any error the payload
    /// is zeroed — what libcrypto wrote there was never authenticated.
    ///
    /// The lengths are a received packet's, so a payload or header past
    /// what one packet can hold is refused as a forgery rather than
    /// asserted on. No UDP datagram reaches it; a caller that is not
    /// reading datagrams might.
    pub fn openDetached(
        self: *PacketKey,
        packet_nonce: *const [nonce_bytes]u8,
        associated_data: []const u8,
        payload: []u8,
        tag: *const [tag_bytes]u8,
    ) Error!void {
        assert(self.aead.direction == .open);
        if (payload.len > payload_bytes_max) return error.AuthenticationFailed;
        if (associated_data.len > payload_bytes_max) return error.AuthenticationFailed;
        try self.aead.open(packet_nonce, associated_data, payload, tag);
        assert(payload.len <= payload_bytes_max);
    }

    /// Decrypt `sealed` — ciphertext with its tag behind it — in place,
    /// answering the plaintext prefix.
    ///
    /// A buffer shorter than a tag is a packet a peer truncated, so it
    /// is refused as a forgery rather than asserted on: the length is the
    /// one thing about it nobody has checked yet.
    pub fn open(
        self: *PacketKey,
        packet_nonce: *const [nonce_bytes]u8,
        associated_data: []const u8,
        sealed: []u8,
    ) Error![]u8 {
        assert(self.aead.direction == .open);
        if (sealed.len < tag_bytes) return error.AuthenticationFailed;
        const payload_bytes = sealed.len - tag_bytes;
        assert(payload_bytes + tag_bytes == sealed.len);
        const tag = sealed[payload_bytes..][0..tag_bytes];
        try self.openDetached(packet_nonce, associated_data, sealed[0..payload_bytes], tag);
        return sealed[0..payload_bytes];
    }
};

/// One §5.4 header-protection key.
pub const HeaderKey = struct {
    protection: backend.HeaderProtection,

    /// `key` is §5.1's "quic hp" output, the AEAD key's length.
    pub fn init(suite: CipherSuite, key: []const u8) Error!HeaderKey {
        assert(key.len == suite.keyBytes());
        const protection = try backend.HeaderProtection.init(suite, key);
        if (suite == .chacha20_poly1305_sha256) assert(protection.kind == .chacha20);
        if (suite != .chacha20_poly1305_sha256) assert(protection.kind == .aes);
        return .{ .protection = protection };
    }

    pub fn deinit(self: *HeaderKey) void {
        assert(self.protection.kind == .aes or self.protection.kind == .chacha20);
        self.protection.deinit();
        self.* = undefined;
    }

    /// §5.4.3 or §5.4.4, by the suite this key was made for: the mask
    /// whose first octet covers the header's low bits and whose other
    /// four cover the packet number.
    pub fn mask(self: *HeaderKey, sample: *const [sample_bytes]u8) Error![mask_bytes]u8 {
        assert(self.protection.kind == .aes or self.protection.kind == .chacha20);
        const result = try self.protection.mask(sample);
        assert(result.len == mask_bytes);
        return result;
    }
};
