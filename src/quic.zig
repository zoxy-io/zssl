//! RFC 9001: TLS 1.3 for QUIC.
//!
//! Two halves, and they land on opposite sides of the trust split
//! DESIGN.md §2 draws.
//!
//! **The handshake** is protocol: RFC 9001 §4 keeps TLS's messages and
//! its key schedule and throws away its record layer. Handshake bytes
//! cross as CRYPTO data at an encryption level, and what TLS hands back
//! is a traffic secret per level rather than a sealed record. Both
//! machines speak it when `Config.quic` is set — `handleCrypto` and
//! `drainCrypto` in place of `handleRecord` and `drain` — and this file
//! is the vocabulary they share with the transport: `Level`, `Secret`,
//! `Crypto`, and the §4.8 mapping from a refusal to a QUIC error code.
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

const alert = @import("alert.zig");
const backend = @import("crypto/backend_openssl.zig");
const cipher_suite = @import("cipher_suite.zig");
const ClientHandshake = @import("ClientHandshake.zig");
const ServerHandshake = @import("ServerHandshake.zig");
const CipherSuite = cipher_suite.CipherSuite;

/// §4.1.4's encryption levels, as far as TLS sees them: the three that
/// carry handshake bytes. 0-RTT is the fourth level and is absent on
/// purpose — §8.3 forbids CRYPTO frames in it, and zssl's QUIC mode never
/// accepts or offers early data, so nothing TLS does ever happens there.
/// `application` is 1-RTT, which h3 calls `one_rtt`.
pub const Level = enum(u2) {
    initial,
    handshake,
    application,
};

pub const Direction = enum { send, receive };

/// A traffic secret for the transport to install (§4.1.4, §5.1): the
/// level it protects, which way, and the suite whose hash and AEAD the
/// transport derives packet keys under.
///
/// `bytes` is borrowed from the machine that derived it — one hash
/// length, 32 or 48 octets — and valid until that machine's next call
/// or `deinit`. Copy it into the transport's own storage, as h3's
/// `installSecret` does, before calling in again.
pub const Secret = struct {
    level: Level,
    direction: Direction,
    suite: CipherSuite,
    bytes: []const u8,
};

/// Handshake bytes for the transport to send at `level`, borrowed until
/// the machine's next call.
pub const Crypto = struct {
    level: Level,
    bytes: []const u8,
};

/// The first whole handshake message at the front of `bytes` — a
/// transport's Initial CRYPTO stream, as h3's `cryptoOut` hands it over
/// — or null while it is still arriving.
///
/// For choosing a certificate before the handshake exists, the way a TCP
/// embedder reads a ClientHello's server_name off the first record: wait
/// for this to answer, `client_hello.parse` it, pick the `Credentials`
/// the name selects, and only then `init` the server and feed it the same
/// bytes. Nothing is consumed and nothing is judged here; the machine
/// will refuse whatever the parse let through on its own terms. A peer
/// can declare a length it never sends, so the wait is bounded by the
/// transport's CRYPTO buffer, not by this.
pub fn firstMessage(bytes: []const u8) ?[]const u8 {
    if (bytes.len < 4) return null;
    const declared = std.mem.readInt(u24, bytes[1..4], .big);
    const total = 4 + @as(usize, declared);
    if (bytes.len < total) return null;
    assert(total <= bytes.len);
    const message = bytes[0..total];
    assert(message.len >= 4);
    return message;
}

/// RFC 9000 §20.1's PROTOCOL_VIOLATION, which is what a handful of RFC
/// 9001's rules name instead of an alert — see `errorCode`.
pub const protocol_violation: u64 = 0x0a;

/// §4.8: "the AlertDescription value is added to 0x0100 to produce a QUIC
/// error code from the range reserved for CRYPTO_ERROR".
pub const crypto_error_base: u64 = 0x0100;

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

    /// Which of the two this key does: `.seal` on the sending side,
    /// `.open` on the receiving one.
    pub const Operation = backend.PacketAead.Direction;

    /// `key` is §5.1's "quic key" output: 16 octets for AES-128-GCM, 32
    /// for the other two.
    pub fn init(suite: CipherSuite, key: []const u8, operation: Operation) Error!PacketKey {
        assert(key.len == suite.keyBytes());
        const aead = try backend.PacketAead.init(suite, key, operation);
        assert(aead.direction == operation);
        return .{ .aead = aead };
    }

    pub fn deinit(self: *PacketKey) void {
        assert(self.aead.key_bytes == 16 or self.aead.key_bytes == 32);
        self.aead.deinit();
        self.* = undefined;
    }

    /// Key this context afresh for `key`, of the suite it was made for, in
    /// place and without allocating. A caller whose interface passes the
    /// raw key on every call — h3's packet-protection backend — keeps one
    /// key per suite and direction for the process and rekeys it per call,
    /// so it never reaches the libcrypto heap after startup. After an
    /// error the key is unspecified: nothing may be sealed or opened until
    /// a `rekey` succeeds.
    pub fn rekey(self: *PacketKey, key: []const u8) Error!void {
        assert(key.len == self.aead.key_bytes);
        try self.aead.rekey(key);
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

    /// `PacketKey.rekey`'s twin: a key of the length this key's cipher
    /// reads, and the same rule after an error.
    pub fn rekey(self: *HeaderKey, key: []const u8) Error!void {
        assert(key.len == self.protection.key_bytes);
        try self.protection.rekey(key);
    }

    /// The whole AES block the §5.4.3 mask is the first five octets of.
    pub fn encryptBlock(self: *HeaderKey, input: *const [sample_bytes]u8, output: *[sample_bytes]u8) Error!void {
        assert(self.protection.kind == .aes);
        try self.protection.encryptBlock(input, output);
    }

    /// ChaCha20 keystream from `counter_and_nonce`, the §5.4.4 sample:
    /// up to `keystream_bytes_max` octets, of which the mask is five.
    pub fn writeKeystream(self: *HeaderKey, counter_and_nonce: *const [sample_bytes]u8, output: []u8) Error!void {
        assert(self.protection.kind == .chacha20);
        try self.protection.writeKeystream(counter_and_nonce, output);
    }

    pub const keystream_bytes_max = backend.HeaderProtection.keystream_bytes_max;

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

/// Every refusal either machine can answer from a QUIC entry point.
///
/// The one place this file reaches above the vocabulary it defines: the
/// machines import `Level` and `Secret` from here, and this imports
/// their error sets back. Zig resolves the cycle lazily — neither error
/// set depends on anything declared here — and the price is worth the
/// exhaustive switch below, which a set of our own would not give.
pub const HandshakeError = ServerHandshake.Error || ClientHandshake.Error;

/// §4.8: the QUIC error code a failed handshake closes with — 0x0100 plus
/// the TLS alert `alertFor` names, or PROTOCOL_VIOLATION for the rules
/// RFC 9001 states as one (§8.4's session ID, §4.1.3's level change).
pub fn errorCode(err: HandshakeError) u64 {
    if (err == error.QuicProtocolViolation) return protocol_violation;
    const code = crypto_error_base + @backingInt(alertFor(err));
    assert(code >= crypto_error_base);
    assert(code <= crypto_error_base + 0xff);
    return code;
}

/// §4.8's alert for a refusal: what a TCP embedder would have sent as a
/// record, which over QUIC becomes `errorCode`'s CRYPTO_ERROR.
///
/// zssl leaves this choice with a TCP embedder — the shims carry their
/// own tables, on purpose — but a QUIC one has nowhere to send an alert
/// and every refusal must become a code, so the library answers. The
/// table is the shims' reading of RFC 8446 §6.2, and exhaustive on
/// purpose: a new error is a compile error here until someone decides
/// which alert it is.
pub fn alertFor(err: HandshakeError) alert.Description {
    return switch (err) {
        // A message, or a KeyUpdate (§6), arriving where the handshake
        // has no place for it.
        error.UnexpectedMessage => .unexpected_message,
        error.HandshakeFailure => .handshake_failure,
        error.MissingExtension => .missing_extension,
        error.UnsupportedExtension => .unsupported_extension,
        error.NoApplicationProtocol => .no_application_protocol,
        error.CertificateRequired => .certificate_required,
        error.BadCertificate => .bad_certificate,
        // §4.4.3 and §4.4.4 name decrypt_error for a CertificateVerify or
        // Finished that does not check out, and §4.2.11.2 computes a
        // binder "in the same way as the Finished message".
        error.DecryptError, error.BadSignature, error.BadBinder => .decrypt_error,
        // Legal grammar, illegal content.
        error.IllegalRetry,
        error.BadServerHello,
        error.IdentityElement,
        error.IllegalKeyUpdate,
        error.IllegalCompression,
        error.PskNotLast,
        error.BadKeyShare,
        error.NonMinimalEncoding,
        error.BinderCountMismatch,
        error.UnofferedSignatureScheme,
        error.BadAlpn,
        => .illegal_parameter,
        // Bytes that do not decode into a decision.
        error.MalformedMessage,
        error.MalformedCertificate,
        error.MalformedExtension,
        error.MalformedAlert,
        error.BadAlert,
        error.DuplicateExtension,
        error.SuiteOverflow,
        error.ExtensionOverflow,
        error.Truncated,
        error.TrailingBytes,
        => .decode_error,
        // §8.4 and §4.1.3 name PROTOCOL_VIOLATION, which `errorCode`
        // answers before asking here; unexpected_message is the nearest
        // alert for a caller that wants one anyway.
        error.QuicProtocolViolation => .unexpected_message,
        // Our side, not the peer's: a buffer the embedder sized smaller
        // than the message, libcrypto refusing, an embedder that skipped
        // a drain or asked before the handshake finished. §6.2 has no
        // alert for any of them.
        error.BufferOverflow,
        error.LibcryptoFailed,
        error.EventsPending,
        error.HandshakeNotComplete,
        error.TicketNotPermitted,
        error.UnsupportedKey,
        error.DeterministicNonceUnsupported,
        error.SignatureInvalid,
        => .internal_error,
        // The record layer's and its ceilings', and 0-RTT's. None is
        // reachable from a QUIC entry point — there are no records and no
        // early data — and they are named here only because the error sets
        // are shared with TCP, where each has its alert.
        error.AuthenticationFailed => .bad_record_mac,
        error.RecordOverflow => .record_overflow,
        error.NotATlsRecord => .protocol_version,
        error.BadInnerPlaintext,
        error.EmptyFragment,
        error.UnexpectedRecordType,
        error.UnknownContentType,
        error.TooManyEmptyRecords,
        error.TooManyKeyUpdates,
        error.TooManyWarningAlerts,
        error.TooMuchEarlyData,
        error.TooMuchSkippedEarlyData,
        => .unexpected_message,
        error.SequenceExhausted, error.RotationsExhausted => .internal_error,
        // A peer alert arrives over QUIC as a CONNECTION_CLOSE, never as
        // TLS bytes; answering one with another is internal_error if it
        // is anything.
        error.PeerAlert => .internal_error,
    };
}
