//! Server-side handshake message encoders (RFC 8446 §4). Pure functions
//! into caller-owned buffers; the state machine decides when, these decide
//! only the bytes.

const std = @import("std");
const assert = std.debug.assert;

const cipher_suite = @import("cipher_suite.zig");
const client_hello = @import("client_hello.zig");
const handshake = @import("handshake.zig");
const wire = @import("wire.zig");
const CipherSuite = cipher_suite.CipherSuite;

const extension_key_share: u16 = 51;
const extension_supported_versions: u16 = 43;
const extension_alpn: u16 = 16;
const tls13_wire_version: u16 = 0x0304;

/// §4.1.3: the fixed random value that marks a ServerHello as a
/// HelloRetryRequest — SHA-256 of "HelloRetryRequest".
pub const hello_retry_magic = [32]u8{
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
};

/// §5: the compatibility ChangeCipherSpec record, sent once after the
/// ServerHello and otherwise meaningless.
pub const change_cipher_spec_record = [6]u8{ 0x14, 0x03, 0x03, 0x00, 0x01, 0x01 };

/// A ServerHello needs ~90 bytes plus the session echo; the flight
/// encoders below all assert against their real need, this is for sizing
/// callers' buffers.
pub const server_hello_bytes_max: u16 = 128;

pub fn serverHello(
    out: []u8,
    random: *const [32]u8,
    session_echo: []const u8,
    suite: CipherSuite,
    x25519_public: *const [32]u8,
) []const u8 {
    assert(out.len >= server_hello_bytes_max);
    assert(session_echo.len <= 32);
    var builder = wire.Builder.init(out);
    const message = handshake.beginMessage(&builder, .server_hello);
    builder.putU16(0x0303);
    builder.putSlice(random);
    builder.putByte(@intCast(session_echo.len));
    builder.putSlice(session_echo);
    builder.putU16(@intFromEnum(suite));
    builder.putByte(0); // legacy_compression_method
    const extensions = builder.markU16();
    // key_share first, then supported_versions — the order RFC 8448's
    // trace uses, which the byte-exact test below leans on.
    builder.putU16(extension_key_share);
    const key_share = builder.markU16();
    builder.putU16(client_hello.group_x25519);
    builder.putU16(32);
    builder.putSlice(x25519_public);
    builder.patchU16(key_share);
    builder.putU16(extension_supported_versions);
    const versions = builder.markU16();
    builder.putU16(tls13_wire_version);
    builder.patchU16(versions);
    builder.patchU16(extensions);
    handshake.endMessage(&builder, message);
    assert(builder.written().len >= 48);
    assert(builder.written().len <= server_hello_bytes_max);
    return builder.written();
}

/// §4.1.4: a HelloRetryRequest is a ServerHello with the magic random and
/// a key_share carrying only the group the server insists on.
pub fn helloRetryRequest(out: []u8, session_echo: []const u8, suite: CipherSuite) []const u8 {
    assert(out.len >= server_hello_bytes_max);
    assert(session_echo.len <= 32);
    var builder = wire.Builder.init(out);
    const message = handshake.beginMessage(&builder, .server_hello);
    builder.putU16(0x0303);
    builder.putSlice(&hello_retry_magic);
    builder.putByte(@intCast(session_echo.len));
    builder.putSlice(session_echo);
    builder.putU16(@intFromEnum(suite));
    builder.putByte(0);
    const extensions = builder.markU16();
    builder.putU16(extension_key_share);
    const key_share = builder.markU16();
    builder.putU16(client_hello.group_x25519);
    builder.patchU16(key_share);
    builder.putU16(extension_supported_versions);
    const versions = builder.markU16();
    builder.putU16(tls13_wire_version);
    builder.patchU16(versions);
    builder.patchU16(extensions);
    handshake.endMessage(&builder, message);
    assert(builder.written().len >= 44);
    assert(builder.written().len <= server_hello_bytes_max);
    return builder.written();
}

/// §4.3.1. Empty unless ALPN was negotiated; zssl advertises nothing else
/// in EncryptedExtensions today.
pub fn encryptedExtensions(out: []u8, alpn_selected: ?[]const u8) []const u8 {
    assert(out.len >= 64);
    if (alpn_selected) |protocol| assert(protocol.len >= 1);
    var builder = wire.Builder.init(out);
    const message = handshake.beginMessage(&builder, .encrypted_extensions);
    const extensions = builder.markU16();
    if (alpn_selected) |protocol| {
        assert(protocol.len <= 32);
        builder.putU16(extension_alpn);
        const body = builder.markU16();
        const list = builder.markU16();
        builder.putByte(@intCast(protocol.len));
        builder.putSlice(protocol);
        builder.patchU16(list);
        builder.patchU16(body);
    }
    builder.patchU16(extensions);
    handshake.endMessage(&builder, message);
    return builder.written();
}

/// §4.4.2, server shape: empty certificate_request_context, then the
/// chain, leaf first, each entry with empty extensions.
pub fn certificateChain(out: []u8, certificates: []const []const u8) []const u8 {
    assert(certificates.len >= 1);
    assert(certificates.len <= 8);
    var total: usize = 0;
    for (certificates) |der| total += der.len;
    assert(out.len >= total + 64);
    var builder = wire.Builder.init(out);
    const message = handshake.beginMessage(&builder, .certificate);
    builder.putByte(0); // certificate_request_context length
    const list = builder.markU24();
    for (certificates) |der| {
        assert(der.len >= 1);
        builder.putU24(@intCast(der.len));
        builder.putSlice(der);
        builder.putU16(0); // per-entry extensions
    }
    builder.patchU24(list);
    handshake.endMessage(&builder, message);
    return builder.written();
}

/// §4.4.3.
pub fn certificateVerify(out: []u8, scheme: u16, signature: []const u8) []const u8 {
    assert(signature.len >= 8);
    assert(signature.len <= 512);
    assert(out.len >= signature.len + 16);
    var builder = wire.Builder.init(out);
    const message = handshake.beginMessage(&builder, .certificate_verify);
    builder.putU16(scheme);
    const body = builder.markU16();
    builder.putSlice(signature);
    builder.patchU16(body);
    handshake.endMessage(&builder, message);
    return builder.written();
}

/// §4.4.4.
pub fn finished(out: []u8, verify_data: []const u8) []const u8 {
    assert(verify_data.len == 32 or verify_data.len == 48);
    assert(out.len >= verify_data.len + handshake.header_bytes);
    var builder = wire.Builder.init(out);
    const message = handshake.beginMessage(&builder, .finished);
    builder.putSlice(verify_data);
    handshake.endMessage(&builder, message);
    return builder.written();
}

pub const Side = enum { server, client };

pub const certificate_verify_content_bytes_max: u16 = 64 + 34 + 1 + 48;

/// §4.4.3: the signed content — 64 spaces, the context string, a zero,
/// the transcript hash.
pub fn certificateVerifyContent(side: Side, transcript_hash: []const u8, out: []u8) []const u8 {
    assert(transcript_hash.len == 32 or transcript_hash.len == 48);
    assert(out.len >= certificate_verify_content_bytes_max);
    const label = switch (side) {
        .server => "TLS 1.3, server CertificateVerify",
        .client => "TLS 1.3, client CertificateVerify",
    };
    var builder = wire.Builder.init(out);
    builder.putSlice(&(.{0x20} ** 64));
    builder.putSlice(label);
    builder.putByte(0);
    builder.putSlice(transcript_hash);
    assert(builder.written().len == 64 + label.len + 1 + transcript_hash.len);
    return builder.written();
}

test "serverHello reproduces RFC 8448's traced bytes exactly" {
    const vectors = @import("rfc8448_vectors.zig");
    // The trace's ServerHello fields: its random, an empty session echo,
    // suite 0x1301, and the server's x25519 share.
    const traced_random = vectors.server_hello[6..38];
    var out: [server_hello_bytes_max]u8 = undefined;
    const encoded = serverHello(
        &out,
        traced_random,
        &.{},
        .aes_128_gcm_sha256,
        &vectors.server_x25519_public,
    );
    try std.testing.expectEqualSlices(u8, &vectors.server_hello, encoded);
}

test "helloRetryRequest carries the §4.1.3 magic and the demanded group" {
    var out: [server_hello_bytes_max]u8 = undefined;
    const encoded = helloRetryRequest(&out, &.{ 0xab, 0xcd }, .chacha20_poly1305_sha256);
    try std.testing.expectEqualSlices(u8, &hello_retry_magic, encoded[6..38]);
    // Session echo survives, and the message parses as server_hello.
    try std.testing.expectEqual(@as(u8, 2), encoded[38]);
    try std.testing.expectEqual(@as(u8, @intFromEnum(handshake.MessageType.server_hello)), encoded[0]);
    // Negative space: an HRR names a group but ships no key bytes.
    try std.testing.expect(encoded.len < 64);
}
