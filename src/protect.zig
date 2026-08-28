//! Record protection: sealing and opening protected TLS 1.3 records
//! (RFC 8446 §5.2-§5.4) over the AEAD backend.
//!
//! One `Protector` is one direction under one traffic key: it owns the
//! static IV, the record sequence number, and the AEAD contexts. Both
//! halves of a connection are two `Protector`s, which is also what makes
//! the RFC 8448 tests possible — each traced key becomes one instance.

const std = @import("std");
const assert = std.debug.assert;

const backend = @import("crypto/backend_openssl.zig");
const cipher_suite = @import("cipher_suite.zig");
const record = @import("record.zig");
const CipherSuite = cipher_suite.CipherSuite;

pub const Error = backend.Error || record.HeaderError || error{
    /// The decrypted inner plaintext exceeds §5.4's cap, or is all padding.
    BadInnerPlaintext,
    /// §5.5: the per-key sequence space is spent; rekey before this fires.
    SequenceExhausted,
    /// The outer record is not a protected application_data record.
    UnexpectedRecordType,
};

/// §5.5's conservative bound for AES-GCM is ~2^24.5 records per key; zssl
/// rounds down to a power of two and applies it to every suite, because a
/// limit only one suite enforces is a limit nobody remembers.
pub const records_per_key_max: u64 = 1 << 24;

pub const Opened = struct {
    content_type: record.ContentType,
    plaintext_bytes: u16,
};

pub const Protector = struct {
    aead: backend.AeadKey,
    static_iv: [cipher_suite.nonce_bytes]u8,
    sequence: u64,

    pub fn init(suite: CipherSuite, key: []const u8, static_iv: *const [cipher_suite.nonce_bytes]u8) Error!Protector {
        assert(key.len == suite.keyBytes());
        assert(!std.mem.allEqual(u8, static_iv, 0));
        return .{
            .aead = try backend.AeadKey.init(suite, key),
            .static_iv = static_iv.*,
            .sequence = 0,
        };
    }

    pub fn deinit(self: *Protector) void {
        assert(self.sequence <= records_per_key_max);
        self.aead.deinit();
        std.crypto.secureZero(u8, &self.static_iv);
        self.* = undefined;
    }

    /// §5.3: nonce = static_iv XOR left-padded sequence number.
    fn nonceFor(self: *const Protector, sequence: u64) [cipher_suite.nonce_bytes]u8 {
        assert(sequence <= records_per_key_max);
        var nonce = self.static_iv;
        var sequence_be: [8]u8 = undefined;
        std.mem.writeInt(u64, &sequence_be, sequence, .big);
        for (nonce[4..12], sequence_be) |*nonce_byte, sequence_byte| {
            nonce_byte.* ^= sequence_byte;
        }
        return nonce;
    }

    /// Seal one record: inner plaintext is `content || content_type` with
    /// no padding (zssl never pads; reading padded peers is `open`'s job).
    /// Returns the full wire record written into `out`.
    pub fn seal(
        self: *Protector,
        content_type: record.ContentType,
        content: []const u8,
        out: []u8,
    ) Error![]const u8 {
        assert(content.len <= record.plaintext_bytes_max);
        if (self.sequence >= records_per_key_max) return error.SequenceExhausted;
        const inner_bytes = content.len + 1;
        const ciphertext_bytes = inner_bytes + cipher_suite.tag_bytes;
        const wire_bytes = record.header_bytes + ciphertext_bytes;
        assert(out.len >= wire_bytes);
        assert(ciphertext_bytes <= record.ciphertext_bytes_max);

        record.writeHeader(
            .{ .content_type = .application_data, .length = @intCast(ciphertext_bytes) },
            out[0..record.header_bytes],
        );
        // The inner plaintext is assembled in place: content, then type.
        const body = out[record.header_bytes..wire_bytes];
        @memcpy(body[0..content.len], content);
        body[content.len] = @intFromEnum(content_type);

        const nonce = self.nonceFor(self.sequence);
        var tag: [cipher_suite.tag_bytes]u8 = undefined;
        // In-place encrypt: EVP permits identical in/out pointers for GCM.
        try self.aead.seal(&nonce, out[0..record.header_bytes], body[0..inner_bytes], body[0..inner_bytes], &tag);
        @memcpy(body[inner_bytes..][0..cipher_suite.tag_bytes], &tag);
        self.sequence += 1;
        return out[0..wire_bytes];
    }

    /// Open one full wire record (header included). The plaintext lands in
    /// `out`; the answer says what it was and how long. Padding is
    /// stripped per §5.4; a record of only padding is an error, as is an
    /// inner plaintext past the §5.4 cap — the check ztls left to callers.
    pub fn open(self: *Protector, wire: []const u8, out: []u8) Error!Opened {
        if (wire.len < record.header_bytes + cipher_suite.tag_bytes + 1) return error.BadInnerPlaintext;
        const header = try record.parseHeader(wire[0..record.header_bytes]);
        if (header.content_type != .application_data) return error.UnexpectedRecordType;
        if (self.sequence >= records_per_key_max) return error.SequenceExhausted;
        const ciphertext_with_tag = wire[record.header_bytes..];
        if (ciphertext_with_tag.len != header.length) return error.BadInnerPlaintext;
        if (ciphertext_with_tag.len < cipher_suite.tag_bytes + 1) return error.BadInnerPlaintext;

        const inner_bytes = ciphertext_with_tag.len - cipher_suite.tag_bytes;
        // §5.4: the inner plaintext — content, its type byte, and any
        // padding — is capped one past §5.1's limit. Checked here, on
        // the length the peer framed, rather than after unpadding: the
        // cap is on what was *sent*, and a peer can spend the whole
        // budget on padding. The post-strip content is bounded again
        // below, and that check alone is what §5.4 asks for only if you
        // read "inner plaintext" as "content", which it is not.
        if (inner_bytes > record.inner_plaintext_bytes_max) return error.RecordOverflow;
        assert(inner_bytes >= 1);
        assert(out.len >= inner_bytes);
        const nonce = self.nonceFor(self.sequence);
        try self.aead.open(
            &nonce,
            wire[0..record.header_bytes],
            ciphertext_with_tag[0..inner_bytes],
            ciphertext_with_tag[inner_bytes..][0..cipher_suite.tag_bytes],
            out[0..inner_bytes],
        );
        self.sequence += 1;

        // §5.4: scan padding backwards to the content-type byte. Bounded
        // structurally by inner_bytes ≤ 16385, and by construction the
        // loop ends at index 0 if every byte is zero.
        var index: usize = inner_bytes;
        while (index > 0) : (index -= 1) {
            if (out[index - 1] != 0) break;
        }
        if (index == 0) return error.BadInnerPlaintext;
        const content_bytes = index - 1;
        // A type we do not know is exactly that, and §5.4 answers it with
        // unexpected_message — distinct from `BadInnerPlaintext`, which
        // is a record whose structure never yielded a type byte at all.
        const content_type = record.ContentType.fromWire(out[content_bytes]) orelse
            return error.UnknownContentType;
        // §5.1's cap on what survives unpadding, and now a consequence
        // rather than a check: the guard above holds inner_bytes at
        // 2^14+1, the content-type byte costs one, so this can only be
        // 2^14 at most. It was a live `return error.RecordOverflow` until
        // that guard existed — the half of §5.4 that *was* enforced while
        // the docs credited the other half.
        assert(content_bytes <= record.plaintext_bytes_max);
        return .{ .content_type = content_type, .plaintext_bytes = @intCast(content_bytes) };
    }
};

test "sequence exhaustion is an error, not a wrap" {
    const suite: CipherSuite = .aes_128_gcm_sha256;
    const key = [_]u8{0x11} ** 16;
    const static_iv = [_]u8{0x22} ** 12;
    var protector = try Protector.init(suite, &key, &static_iv);
    defer protector.deinit();
    protector.sequence = records_per_key_max;
    var out: [64]u8 = undefined;
    try std.testing.expectError(error.SequenceExhausted, protector.seal(.handshake, "x", &out));
}

test "nonce XOR folds the sequence into the IV tail" {
    const suite: CipherSuite = .aes_128_gcm_sha256;
    const key = [_]u8{0x11} ** 16;
    const static_iv = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };
    var protector = try Protector.init(suite, &key, &static_iv);
    defer protector.deinit();
    const nonce_zero = protector.nonceFor(0);
    try std.testing.expectEqualSlices(u8, &static_iv, &nonce_zero);
    const nonce_one = protector.nonceFor(1);
    try std.testing.expectEqual(static_iv[11] ^ 1, nonce_one[11]);
    try std.testing.expectEqualSlices(u8, static_iv[0..11], nonce_one[0..11]);
}

test "§5.4: an inner plaintext past the cap is record_overflow, before any AEAD work" {
    // BoGo's `LargePlaintext-TLS13-Padded-16384-1` and `-8193-8192`: one
    // spends the overflow on content, the other on padding, and both
    // frame 16386 inner bytes where §5.4 allows 16385. The split does not
    // matter to this check and that is the point — the cap is on what the
    // peer sent, not on what survives unpadding, and reading it the other
    // way is what left this open with the wrong diagnosis attached.
    const suite: CipherSuite = .aes_128_gcm_sha256;
    const key = [_]u8{0x22} ** 16;
    const static_iv = [_]u8{0x33} ** 12;
    var protector = try Protector.init(suite, &key, &static_iv);
    defer protector.deinit();

    var wire: [record.wire_record_bytes_max]u8 = undefined;
    var out: [record.wire_record_bytes_max]u8 = undefined;

    // 16386 inner bytes plus the tag, which §5.2's cap still admits — so
    // the header parses and this check is what refuses it.
    const over = record.inner_plaintext_bytes_max + 1;
    const body_bytes = @as(usize, over) + cipher_suite.tag_bytes;
    record.writeHeader(
        .{ .content_type = .application_data, .length = @intCast(body_bytes) },
        wire[0..record.header_bytes],
    );
    @memset(wire[record.header_bytes..][0..body_bytes], 0x5a);
    try std.testing.expectError(
        error.RecordOverflow,
        protector.open(wire[0 .. record.header_bytes + body_bytes], &out),
    );

    // The boundary itself is admitted this far: exactly 16385 inner bytes
    // is legal framing, so it reaches the AEAD and dies there instead.
    // Garbage never authenticates, which is the answer that proves the
    // length check let it past rather than swallowing it.
    const at_cap = @as(usize, record.inner_plaintext_bytes_max) + cipher_suite.tag_bytes;
    record.writeHeader(
        .{ .content_type = .application_data, .length = @intCast(at_cap) },
        wire[0..record.header_bytes],
    );
    @memset(wire[record.header_bytes..][0..at_cap], 0x5a);
    try std.testing.expectError(
        error.AuthenticationFailed,
        protector.open(wire[0 .. record.header_bytes + at_cap], &out),
    );
}
