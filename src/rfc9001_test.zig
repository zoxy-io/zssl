//! RFC 9001 Appendix A, reproduced: the Initial keys, both protected
//! Initial packets, the Retry integrity tag, and the ChaCha20-Poly1305
//! short-header packet — every octet derived here and compared against
//! the RFC's own, which `scripts/extract_rfc9001.py` lifts from the text.
//!
//! The derivations go through `hkdf` (pure Zig over std.crypto) and the
//! protection through `quic.PacketKey` and `quic.HeaderKey` (libcrypto),
//! so a vector that agrees has crossed both sides of DESIGN.md §2's
//! trust split. AES-256-GCM has no worked packet in the appendix; it is
//! held to `std.crypto` instead, which shares no code with libcrypto.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

const hkdf = @import("hkdf.zig");
const quic = @import("quic.zig");
const vectors = @import("rfc9001_vectors.zig");
const CipherSuite = @import("cipher_suite.zig").CipherSuite;

/// A.1's Destination Connection ID, stated in the appendix's prose
/// ("an 8-byte client-chosen Destination Connection ID of
/// 0x8394c8f03e515708") and present in both A.2's header and A.4's.
const destination_connection_id = vectors.client_header[6..14];

/// §5.1's three derivations from one traffic secret, through the
/// library's HKDF. The context is always empty in QUIC.
fn KeyMaterial(comptime key_bytes: u8) type {
    return struct { key: [key_bytes]u8, iv: [quic.nonce_bytes]u8, hp: [key_bytes]u8 };
}

fn keyMaterial(comptime Hkdf: type, comptime key_bytes: u8, secret: *const [Hkdf.prk_bytes]u8) KeyMaterial(key_bytes) {
    var material: KeyMaterial(key_bytes) = undefined;
    Hkdf.expandLabel(secret, "quic key", "", &material.key);
    Hkdf.expandLabel(secret, "quic iv", "", &material.iv);
    Hkdf.expandLabel(secret, "quic hp", "", &material.hp);
    return material;
}

test "RFC 9001 A.1: the Initial secrets and their keys, IVs and header keys" {
    // A.1's connection ID really is the one A.2's header carries.
    try testing.expectEqualSlices(u8, &.{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 }, destination_connection_id);
    const initial_secret = hkdf.HkdfSha256.extract(&vectors.initial_salt, destination_connection_id);
    try testing.expectEqualSlices(u8, &vectors.initial_secret, &initial_secret);

    var client_secret: [32]u8 = undefined;
    hkdf.HkdfSha256.expandLabel(&initial_secret, "client in", "", &client_secret);
    try testing.expectEqualSlices(u8, &vectors.client_initial_secret, &client_secret);
    const client = keyMaterial(hkdf.HkdfSha256, 16, &client_secret);
    try testing.expectEqualSlices(u8, &vectors.client_key, &client.key);
    try testing.expectEqualSlices(u8, &vectors.client_iv, &client.iv);
    try testing.expectEqualSlices(u8, &vectors.client_hp, &client.hp);

    var server_secret: [32]u8 = undefined;
    hkdf.HkdfSha256.expandLabel(&initial_secret, "server in", "", &server_secret);
    try testing.expectEqualSlices(u8, &vectors.server_initial_secret, &server_secret);
    const server = keyMaterial(hkdf.HkdfSha256, 16, &server_secret);
    try testing.expectEqualSlices(u8, &vectors.server_key, &server.key);
    try testing.expectEqualSlices(u8, &vectors.server_iv, &server.iv);
    try testing.expectEqualSlices(u8, &vectors.server_hp, &server.hp);
}

/// A long or short header packet as the appendix builds it: the header
/// with its packet number in the clear, then the payload, sealed and
/// masked in place. `packet_number_bytes` is the header's own encoding
/// (its low two bits plus one), which fixes where §5.4.2 samples.
const Example = struct {
    suite: CipherSuite,
    key: []const u8,
    iv: *const [quic.nonce_bytes]u8,
    hp: []const u8,
    packet_number: u64,
    header: []const u8,
    payload: []const u8,
    sample: *const [quic.sample_bytes]u8,
    mask: *const [quic.mask_bytes]u8,
    protected_header: []const u8,
    packet: []const u8,
};

/// Protect `example` and compare every intermediate the appendix shows,
/// then reverse it: unmask, open, and land back on the plaintext — and
/// refuse the same packet with one ciphertext bit flipped.
fn checkExample(example: *const Example) !void {
    var buffer: [1200]u8 = undefined;
    assert(example.packet.len <= buffer.len);
    const header_bytes = example.header.len;
    const packet_number_bytes: usize = (example.header[0] & 0x03) + 1;
    const packet_number_offset = header_bytes - packet_number_bytes;
    @memcpy(buffer[0..header_bytes], example.header);
    @memcpy(buffer[header_bytes..][0..example.payload.len], example.payload);

    const packet_nonce = quic.nonce(example.iv, example.packet_number);
    var seal_key = try quic.PacketKey.init(example.suite, example.key, .seal);
    defer seal_key.deinit();
    const sealed = try seal_key.seal(&packet_nonce, example.header, buffer[header_bytes..], example.payload.len);
    try testing.expectEqual(example.packet.len - header_bytes, sealed.len);

    // §5.4.2: the sample starts four octets past the packet number's
    // first, whatever the encoding's length.
    const sample = buffer[packet_number_offset + 4 ..][0..quic.sample_bytes];
    try testing.expectEqualSlices(u8, example.sample, sample);
    var header_key = try quic.HeaderKey.init(example.suite, example.hp);
    defer header_key.deinit();
    const mask = try header_key.mask(sample);
    try testing.expectEqualSlices(u8, example.mask, &mask);
    applyMask(buffer[0..header_bytes], &mask, packet_number_bytes);
    try testing.expectEqualSlices(u8, example.protected_header, buffer[0..header_bytes]);
    try testing.expectEqualSlices(u8, example.packet, buffer[0..example.packet.len]);

    // The receiving side. Unmasking is the same XOR; the sample is the
    // same ciphertext, so the same mask comes back.
    applyMask(buffer[0..header_bytes], &mask, packet_number_bytes);
    try testing.expectEqualSlices(u8, example.header, buffer[0..header_bytes]);
    var open_key = try quic.PacketKey.init(example.suite, example.key, .open);
    defer open_key.deinit();
    var copy: [1200]u8 = undefined;
    @memcpy(copy[0..example.packet.len], buffer[0..example.packet.len]);
    const opened = try open_key.open(&packet_nonce, example.header, buffer[header_bytes..example.packet.len]);
    try testing.expectEqualSlices(u8, example.payload, opened);

    copy[header_bytes] ^= 0x01;
    try testing.expectError(
        error.AuthenticationFailed,
        open_key.open(&packet_nonce, example.header, copy[header_bytes..example.packet.len]),
    );
    // §5's refusal leaves nothing behind: what libcrypto decrypted before
    // the tag failed is not plaintext anyone may read.
    const payload_bytes = example.packet.len - header_bytes - quic.tag_bytes;
    try testing.expect(std.mem.allEqual(u8, copy[header_bytes..][0..payload_bytes], 0));
}

/// §5.4.1: the low four bits of a long header's first octet (five of a
/// short one's), and the packet number's octets.
fn applyMask(header: []u8, mask: *const [quic.mask_bytes]u8, packet_number_bytes: usize) void {
    assert(packet_number_bytes >= 1 and packet_number_bytes <= 4);
    assert(header.len >= 1 + packet_number_bytes);
    const long_header = header[0] & 0x80 != 0;
    header[0] ^= mask[0] & @as(u8, if (long_header) 0x0f else 0x1f);
    const packet_number = header[header.len - packet_number_bytes ..];
    for (packet_number, mask[1..][0..packet_number_bytes]) |*octet, masking| octet.* ^= masking;
}

test "RFC 9001 A.2: the client Initial, AES-128-GCM and AES-ECB header protection" {
    // §14.1's 1200-octet floor is met with PADDING frames, which are
    // zero octets; A.2 says the payload is 1162 of them in all.
    var payload: [1162]u8 = @splat(0);
    @memcpy(payload[0..vectors.client_crypto_frame.len], &vectors.client_crypto_frame);
    try checkExample(&.{
        .suite = .aes_128_gcm_sha256,
        .key = &vectors.client_key,
        .iv = &vectors.client_iv,
        .hp = &vectors.client_hp,
        .packet_number = vectors.client_packet_number,
        .header = &vectors.client_header,
        .payload = &payload,
        .sample = &vectors.client_sample,
        .mask = &vectors.client_mask,
        .protected_header = &vectors.client_protected_header,
        .packet = &vectors.client_packet,
    });
}

test "RFC 9001 A.3: the server Initial, sampled past a two-octet packet number" {
    try checkExample(&.{
        .suite = .aes_128_gcm_sha256,
        .key = &vectors.server_key,
        .iv = &vectors.server_iv,
        .hp = &vectors.server_hp,
        .packet_number = vectors.server_packet_number,
        .header = &vectors.server_header,
        .payload = &vectors.server_payload,
        .sample = &vectors.server_sample,
        .mask = &vectors.server_mask,
        .protected_header = &vectors.server_protected_header,
        .packet = &vectors.server_packet,
    });
}

test "RFC 9001 A.4: the Retry integrity tag is AES-128-GCM over the pseudo-packet" {
    // §5.8: an empty plaintext, and associated data that is the original
    // Destination Connection ID behind its length, then the Retry packet
    // without its tag. A detached seal of nothing answers the tag alone.
    const retry_without_tag = vectors.retry_packet[0 .. vectors.retry_packet.len - quic.tag_bytes];
    var pseudo_packet: [1 + 20 + vectors.retry_packet.len]u8 = undefined;
    pseudo_packet[0] = @intCast(destination_connection_id.len);
    @memcpy(pseudo_packet[1..][0..destination_connection_id.len], destination_connection_id);
    const pseudo_bytes = 1 + destination_connection_id.len + retry_without_tag.len;
    @memcpy(pseudo_packet[1 + destination_connection_id.len ..][0..retry_without_tag.len], retry_without_tag);

    var empty: [0]u8 = .{};
    var key = try quic.PacketKey.init(.aes_128_gcm_sha256, &vectors.retry_key, .seal);
    defer key.deinit();
    var tag: [quic.tag_bytes]u8 = undefined;
    try key.sealDetached(&vectors.retry_nonce, pseudo_packet[0..pseudo_bytes], &empty, &tag);
    try testing.expectEqualSlices(u8, vectors.retry_packet[retry_without_tag.len..], &tag);

    // And verifying it is an open of nothing against that tag.
    var verify = try quic.PacketKey.init(.aes_128_gcm_sha256, &vectors.retry_key, .open);
    defer verify.deinit();
    try verify.openDetached(&vectors.retry_nonce, pseudo_packet[0..pseudo_bytes], &empty, &tag);
    pseudo_packet[1] ^= 0x80; // A different original connection ID.
    try testing.expectError(
        error.AuthenticationFailed,
        verify.openDetached(&vectors.retry_nonce, pseudo_packet[0..pseudo_bytes], &empty, &tag),
    );
}

test "RFC 9001 A.5: the ChaCha20-Poly1305 short header packet" {
    const material = keyMaterial(hkdf.HkdfSha256, 32, &vectors.chacha_secret);
    try testing.expectEqualSlices(u8, &vectors.chacha_key, &material.key);
    try testing.expectEqualSlices(u8, &vectors.chacha_iv, &material.iv);
    try testing.expectEqualSlices(u8, &vectors.chacha_hp, &material.hp);
    // §6.1's next generation, from the same secret.
    var next: [32]u8 = undefined;
    hkdf.HkdfSha256.expandLabel(&vectors.chacha_secret, "quic ku", "", &next);
    try testing.expectEqualSlices(u8, &vectors.chacha_ku, &next);
    try testing.expectEqualSlices(
        u8,
        &vectors.chacha_nonce,
        &quic.nonce(&vectors.chacha_iv, vectors.chacha_packet_number),
    );
    try testing.expectEqualSlices(u8, &vectors.chacha_ciphertext, vectors.chacha_packet[vectors.chacha_header.len..]);

    try checkExample(&.{
        .suite = .chacha20_poly1305_sha256,
        .key = &vectors.chacha_key,
        .iv = &vectors.chacha_iv,
        .hp = &vectors.chacha_hp,
        .packet_number = vectors.chacha_packet_number,
        .header = &vectors.chacha_header,
        .payload = &vectors.chacha_plaintext,
        .sample = &vectors.chacha_sample,
        .mask = &vectors.chacha_mask,
        .protected_header = &vectors.chacha_protected_header,
        .packet = &vectors.chacha_packet,
    });
}

test "AES-256-GCM and AES-256-ECB, which the appendix never shows, agree with std.crypto" {
    // A.2's payload and header under a 32-octet key: the shape is real,
    // only the key is ours. Two implementations sharing no code agreeing
    // on every octet is the oracle the appendix does not supply here.
    const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;
    var key: [32]u8 = undefined;
    for (&key, 0..) |*octet, index| octet.* = @truncate(index *% 7 + 3);
    var hp: [32]u8 = undefined;
    for (&hp, 0..) |*octet, index| octet.* = @truncate(index *% 13 + 1);
    const packet_nonce = quic.nonce(&vectors.client_iv, 0x3fff_ffff_ffff_ffff);
    var ours: [vectors.client_crypto_frame.len + quic.tag_bytes]u8 = undefined;
    @memcpy(ours[0..vectors.client_crypto_frame.len], &vectors.client_crypto_frame);

    var seal_key = try quic.PacketKey.init(.aes_256_gcm_sha384, &key, .seal);
    defer seal_key.deinit();
    _ = try seal_key.seal(&packet_nonce, &vectors.client_header, &ours, vectors.client_crypto_frame.len);
    var theirs: [vectors.client_crypto_frame.len]u8 = undefined;
    var theirs_tag: [quic.tag_bytes]u8 = undefined;
    Aes256Gcm.encrypt(&theirs, &theirs_tag, &vectors.client_crypto_frame, &vectors.client_header, packet_nonce, key);
    try testing.expectEqualSlices(u8, &theirs, ours[0..theirs.len]);
    try testing.expectEqualSlices(u8, &theirs_tag, ours[theirs.len..]);

    var header_key = try quic.HeaderKey.init(.aes_256_gcm_sha384, &hp);
    defer header_key.deinit();
    const sample = ours[0..quic.sample_bytes];
    var block: [16]u8 = undefined;
    std.crypto.core.aes.Aes256.initEnc(hp).encrypt(&block, sample);
    try testing.expectEqualSlices(u8, block[0..quic.mask_bytes], &try header_key.mask(sample));

    var open_key = try quic.PacketKey.init(.aes_256_gcm_sha384, &key, .open);
    defer open_key.deinit();
    const opened = try open_key.open(&packet_nonce, &vectors.client_header, &ours);
    try testing.expectEqualSlices(u8, &vectors.client_crypto_frame, opened);
}

test "every suite: masks and sealed packets agree with std.crypto across lengths" {
    // The two vector suites again, plus the cases the appendix has no
    // reason to show: an empty payload, an empty associated data, a
    // payload straddling a block, a SHA-384 secret's keys.
    const lengths = [_]usize{ 0, 1, 15, 16, 17, 1000 };
    var plaintext: [1000]u8 = undefined;
    for (&plaintext, 0..) |*octet, index| octet.* = @truncate(index *% 29);
    inline for (.{
        .{ CipherSuite.aes_128_gcm_sha256, std.crypto.aead.aes_gcm.Aes128Gcm },
        .{ CipherSuite.aes_256_gcm_sha384, std.crypto.aead.aes_gcm.Aes256Gcm },
        .{ CipherSuite.chacha20_poly1305_sha256, std.crypto.aead.chacha_poly.ChaCha20Poly1305 },
    }) |pair| {
        const suite = pair[0];
        const Std = pair[1];
        var key: [suite.keyBytes()]u8 = undefined;
        for (&key, 0..) |*octet, index| octet.* = @truncate(index + 0x41);
        var seal_key = try quic.PacketKey.init(suite, &key, .seal);
        defer seal_key.deinit();
        var open_key = try quic.PacketKey.init(suite, &key, .open);
        defer open_key.deinit();
        for (lengths, 0..) |length, round| {
            const associated_data: []const u8 = if (round % 2 == 0) &.{} else "header";
            const packet_nonce = quic.nonce(&vectors.server_iv, round);
            var ours: [1000 + @as(usize, quic.tag_bytes)]u8 = undefined;
            @memcpy(ours[0..length], plaintext[0..length]);
            const sealed = try seal_key.seal(&packet_nonce, associated_data, &ours, length);
            var theirs: [1000]u8 = undefined;
            var theirs_tag: [quic.tag_bytes]u8 = undefined;
            Std.encrypt(theirs[0..length], &theirs_tag, plaintext[0..length], associated_data, packet_nonce, key);
            try testing.expectEqualSlices(u8, theirs[0..length], sealed[0..length]);
            try testing.expectEqualSlices(u8, &theirs_tag, sealed[length..]);
            const opened = try open_key.open(&packet_nonce, associated_data, ours[0 .. length + quic.tag_bytes]);
            try testing.expectEqualSlices(u8, plaintext[0..length], opened);
        }
    }
}

test "a sealed packet shorter than its tag is a forgery, not an assertion" {
    var key = try quic.PacketKey.init(.aes_128_gcm_sha256, &vectors.client_key, .open);
    defer key.deinit();
    const packet_nonce = quic.nonce(&vectors.client_iv, 0);
    var short: [quic.tag_bytes - 1]u8 = @splat(0xaa);
    for (0..short.len + 1) |length| {
        try testing.expectError(
            error.AuthenticationFailed,
            key.open(&packet_nonce, &vectors.client_header, short[0..length]),
        );
    }
}

test "§5.3: the nonce XORs the full packet number into the IV's low octets" {
    const iv: [quic.nonce_bytes]u8 = @splat(0xff);
    const zero = quic.nonce(&iv, 0);
    try testing.expectEqualSlices(u8, &iv, &zero);
    const largest = quic.nonce(&iv, (1 << 62) - 1);
    // The top two bits of a 62-bit number are clear, so the octet four
    // from the left keeps two of its bits and the four ahead of it all.
    try testing.expectEqualSlices(u8, &.{ 0xff, 0xff, 0xff, 0xff, 0xc0, 0, 0, 0, 0, 0, 0, 0 }, &largest);
}

test "HKDF-Extract admits the empty connection ID a Retry may leave" {
    // RFC 9000 §17.2.5 lets a server's chosen connection ID be empty, and
    // §5.2's Initial secrets then extract from nothing. HMAC over an
    // empty message is still HMAC: this must answer, and must agree with
    // std.crypto's own extract.
    const ours = hkdf.HkdfSha256.extract(&vectors.initial_salt, &.{});
    const theirs = std.crypto.kdf.hkdf.HkdfSha256.extract(&vectors.initial_salt, &.{});
    try testing.expectEqualSlices(u8, &theirs, &ours);
}

test "a rekeyed context seals, opens and protects headers as a fresh one does" {
    // One context per suite and direction, rekeyed per call, is how a
    // backend whose every call carries the raw key (h3's) stays off the
    // libcrypto heap after startup. So the context is used before each
    // rekey — the case with stale state to leave behind — and a failed
    // open precedes one, and every result is held to a fresh context's.
    inline for (.{ CipherSuite.aes_128_gcm_sha256, CipherSuite.aes_256_gcm_sha384, CipherSuite.chacha20_poly1305_sha256 }) |suite| {
        var keys: [3][suite.keyBytes()]u8 = undefined;
        for (&keys, 0..) |*key, round| {
            for (key, 0..) |*octet, index| octet.* = @truncate(index *% 5 + round * 0x31 + 0x11);
        }
        var sealer = try quic.PacketKey.init(suite, &keys[0], .seal);
        defer sealer.deinit();
        var opener = try quic.PacketKey.init(suite, &keys[0], .open);
        defer opener.deinit();
        var header = try quic.HeaderKey.init(suite, &keys[0]);
        defer header.deinit();
        const sample = vectors.client_crypto_frame[0..quic.sample_bytes];
        for (keys, 0..) |key, round| {
            if (round > 0) {
                try sealer.rekey(&key);
                try opener.rekey(&key);
                try header.rekey(&key);
            }
            var fresh = try quic.PacketKey.init(suite, &key, .seal);
            defer fresh.deinit();
            const packet_nonce = quic.nonce(&vectors.server_iv, round);
            var ours: [32 + @as(usize, quic.tag_bytes)]u8 = @splat(0x5a);
            var theirs: [32 + @as(usize, quic.tag_bytes)]u8 = @splat(0x5a);
            _ = try sealer.seal(&packet_nonce, "header", &ours, 32);
            _ = try fresh.seal(&packet_nonce, "header", &theirs, 32);
            try testing.expectEqualSlices(u8, &theirs, &ours);
            // A forgery first, then the real packet: a refused open must
            // leave nothing behind for the next one to trip over.
            var forged = ours;
            forged[0] ^= 1;
            try testing.expectError(error.AuthenticationFailed, opener.open(&packet_nonce, "header", &forged));
            const opened = try opener.open(&packet_nonce, "header", &ours);
            try testing.expect(std.mem.allEqual(u8, opened, 0x5a));
            var header_fresh = try quic.HeaderKey.init(suite, &key);
            defer header_fresh.deinit();
            try testing.expectEqualSlices(u8, &try header_fresh.mask(sample), &try header.mask(sample));
        }
    }
}

test "the header key's whole AES block and ChaCha20 keystream agree with std.crypto" {
    // h3's backend takes the block and the keystream rather than the
    // mask; the mask is their first five octets.
    const sample = vectors.client_crypto_frame[0..quic.sample_bytes];
    var key128: [16]u8 = undefined;
    for (&key128, 0..) |*octet, index| octet.* = @truncate(index *% 3 + 9);
    var aes = try quic.HeaderKey.init(.aes_128_gcm_sha256, &key128);
    defer aes.deinit();
    var ours: [16]u8 = undefined;
    try aes.encryptBlock(sample, &ours);
    var theirs: [16]u8 = undefined;
    std.crypto.core.aes.Aes128.initEnc(key128).encrypt(&theirs, sample);
    try testing.expectEqualSlices(u8, &theirs, &ours);
    try testing.expectEqualSlices(u8, theirs[0..quic.mask_bytes], &try aes.mask(sample));

    var key256: [32]u8 = undefined;
    for (&key256, 0..) |*octet, index| octet.* = @truncate(index *% 11 + 2);
    var chacha = try quic.HeaderKey.init(.chacha20_poly1305_sha256, &key256);
    defer chacha.deinit();
    const counter = std.mem.readInt(u32, sample[0..4], .little);
    for ([_]usize{ 1, 5, 16, 64 }) |length| {
        var stream: [quic.HeaderKey.keystream_bytes_max]u8 = undefined;
        try chacha.writeKeystream(sample, stream[0..length]);
        var expected: [quic.HeaderKey.keystream_bytes_max]u8 = @splat(0);
        std.crypto.stream.chacha.ChaCha20IETF.xor(expected[0..length], expected[0..length], counter, key256, sample[4..16].*);
        try testing.expectEqualSlices(u8, expected[0..length], stream[0..length]);
    }
    var stream: [quic.mask_bytes]u8 = undefined;
    try chacha.writeKeystream(sample, &stream);
    try testing.expectEqualSlices(u8, &stream, &try chacha.mask(sample));
}
