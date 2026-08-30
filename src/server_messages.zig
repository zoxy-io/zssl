//! Server-side handshake message encoders (RFC 8446 §4). Pure functions
//! into caller-owned buffers; the state machine decides when, these decide
//! only the bytes.

const std = @import("std");
const assert = std.debug.assert;

const cipher_suite = @import("cipher_suite.zig");
const client_hello = @import("client_hello.zig");
const backend = @import("crypto/backend_openssl.zig");
const handshake = @import("handshake.zig");
const wire = @import("wire.zig");
const CipherSuite = cipher_suite.CipherSuite;

const extension_key_share: u16 = 51;
const extension_supported_versions: u16 = 43;
const extension_alpn: u16 = 16;
const extension_early_data: u16 = 42;
const extension_signature_algorithms: u16 = 13;
const extension_pre_shared_key: u16 = 41;
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

/// A ServerHello needs ~90 bytes plus the session echo and the key
/// share, and the share is the part that moves: 32 bytes for x25519, 97
/// for secp384r1's uncompressed point. Sized for the largest group so
/// the buffer does not depend on what the client offered; the flight
/// encoders below all assert against their real need.
pub const server_hello_bytes_max: u16 = 224;

pub fn serverHello(
    out: []u8,
    random: *const [32]u8,
    session_echo: []const u8,
    suite: CipherSuite,
    key_share_group: u16,
    key_share_public: []const u8,
    selected_psk: ?u16,
) []const u8 {
    assert(out.len >= server_hello_bytes_max);
    assert(session_echo.len <= 32);
    // The share's length is the group's, not the caller's to choose.
    assert(key_share_public.len == client_hello.groupShareBytes(key_share_group).?);
    if (selected_psk) |index| assert(index < client_hello.psk_identities_max);
    var builder = wire.Builder.init(out);
    const message = handshake.beginMessage(&builder, .server_hello);
    builder.putU16(0x0303);
    builder.putSlice(random);
    builder.putByte(@intCast(session_echo.len));
    builder.putSlice(session_echo);
    builder.putU16(@intFromEnum(suite));
    builder.putByte(0); // legacy_compression_method
    const extensions = builder.markU16();
    // pre_shared_key, key_share, supported_versions — the order both of
    // RFC 8448's traces use, which the byte-exact tests lean on.
    if (selected_psk) |index| {
        builder.putU16(extension_pre_shared_key);
        const psk = builder.markU16();
        builder.putU16(index);
        builder.patchU16(psk);
    }
    builder.putU16(extension_key_share);
    const key_share = builder.markU16();
    builder.putU16(key_share_group);
    builder.putU16(@intCast(key_share_public.len));
    builder.putSlice(key_share_public);
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
pub fn helloRetryRequest(
    out: []u8,
    session_echo: []const u8,
    suite: CipherSuite,
    key_share_group: u16,
) []const u8 {
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
    builder.putU16(key_share_group);
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
/// §4.2.10: `early_data` here, and empty, is the whole of how a server
/// says it accepted 0-RTT. There is no other signal and no room for one
/// — the client has already sent the data.
pub fn encryptedExtensions(out: []u8, alpn_selected: ?[]const u8, early_data: bool) []const u8 {
    assert(out.len >= 64);
    if (alpn_selected) |protocol| assert(protocol.len >= 1);
    var builder = wire.Builder.init(out);
    const message = handshake.beginMessage(&builder, .encrypted_extensions);
    const extensions = builder.markU16();
    if (early_data) {
        builder.putU16(extension_early_data);
        builder.patchU16(builder.markU16());
    }
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

/// §4.3.2's CertificateRequest — the message that makes a handshake
/// mutual.
///
/// `certificate_request_context` is always empty here, and that is the
/// RFC's rule rather than a simplification: the field "SHALL be zero
/// length unless used for the post-handshake authentication exchanges",
/// which DESIGN.md §1 puts permanently out of scope. Nothing has to
/// track an echo, and a client sending a non-empty one is answering a
/// request we did not make.
///
/// One extension, and §4.3.2 makes it mandatory: `signature_algorithms`
/// is what the client's CertificateVerify must choose from.
/// `certificate_authorities` and `oid_filters` are omitted — a server
/// that names no CAs is asking for any certificate, and the embedder's
/// `chain_verifier` is where that judgement belongs.
pub fn certificateRequest(out: []u8, schemes: []const backend.SignatureScheme) []const u8 {
    assert(schemes.len >= 1);
    assert(out.len >= certificate_request_bytes_max);
    var builder = wire.Builder.init(out);
    const message = handshake.beginMessage(&builder, .certificate_request);
    builder.putByte(0); // certificate_request_context: empty, per §4.3.2.
    const extensions = builder.markU16();
    builder.putU16(extension_signature_algorithms);
    const body = builder.markU16();
    const list = builder.markU16();
    for (schemes) |scheme| builder.putU16(@intFromEnum(scheme));
    builder.patchU16(list);
    builder.patchU16(body);
    builder.patchU16(extensions);
    handshake.endMessage(&builder, message);
    return builder.written();
}

/// §4.4.2: empty certificate_request_context, then the chain, leaf
/// first, each entry with empty extensions.
///
/// Both sides send this message and the shape is identical. An *empty*
/// list is legal from a client and only from a client — §4.4.2's way of
/// saying it holds no certificate the request fits — so the count floors
/// at zero here rather than one, and whether an empty one is acceptable
/// is `ServerHandshake`'s `require` to decide. A server sending one
/// would be a server with no certificate, which `Credentials.load`
/// already refuses.
pub fn certificateChain(out: []u8, certificates: []const []const u8) []const u8 {
    assert(certificates.len <= 8);
    var total: usize = 0;
    for (certificates) |der| total += der.len;
    // Per entry: 3 length bytes and 2 of empty extensions. Plus the
    // header, the context byte and the list's own u24 — which is what an
    // *empty* list costs, and the reason a client declining needs no
    // chain-sized buffer at all.
    assert(out.len >= handshake.header_bytes + 1 + 3 + total + certificates.len * 5);
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

/// The sealed-ticket size budget shared by every encoder and buffer that
/// touches one. zoxy's tickets are ≤ 256 bytes; 512 leaves headroom.
pub const ticket_bytes_max: u16 = 512;

/// §4.6.1 caps `ticket_lifetime` at seven days: "Servers MUST NOT use
/// any value greater than 604800 seconds (7 days)."
pub const ticket_lifetime_s_max: u32 = 604800;

/// A NewSessionTicket message never exceeds this (§4.6.1's fields at
/// their caps), which is what sizes the sealing buffers above.
///
/// The trailing 8 is the `early_data` extension: four bytes of type and
/// length, four of `max_early_data_size`. It is counted whether or not a
/// given ticket carries one, because this is the *worst* case and
/// `wire.Builder` bounds-checks nothing — every `put` is an assertion,
/// so this constant is the entire safety net between a legal
/// maximum-size ticket and an out-of-bounds write.
pub const new_session_ticket_bytes_max: u16 =
    @as(u16, handshake.header_bytes) + 4 + 4 + 1 + 255 + 2 + ticket_bytes_max + 2 + 8;

/// §4.3.2 with one extension: 4 header + 1 context + 2 extensions
/// length + 2 type + 2 body + 2 list + two bytes per scheme. Five
/// schemes is every code point `SignatureScheme` has, so 32 is generous
/// and fixed — `wire.Builder` bounds nothing, and this is the number
/// that keeps it from having to.
pub const certificate_request_bytes_max: usize = 32;

/// §4.6.1, and the other half of accepting 0-RTT: a client offers early
/// data only against a ticket that told it how much it may send, so a
/// server that accepts and never advertises is one no client ever takes
/// up on it. Null keeps the extension block empty, which is what every
/// ticket looked like before the accept path existed.
pub fn newSessionTicket(
    out: []u8,
    lifetime_s: u32,
    age_add: u32,
    ticket_nonce: []const u8,
    ticket: []const u8,
    early_data_bytes_max: ?u32,
) []const u8 {
    assert(lifetime_s >= 1);
    assert(lifetime_s <= ticket_lifetime_s_max);
    assert(ticket_nonce.len >= 1);
    assert(ticket_nonce.len <= 255);
    assert(ticket.len >= 1);
    assert(ticket.len <= ticket_bytes_max);
    assert(out.len >= handshake.header_bytes + 4 + 4 + 1 + ticket_nonce.len + 2 + ticket.len + 2 + 8);
    var builder = wire.Builder.init(out);
    const message = handshake.beginMessage(&builder, .new_session_ticket);
    builder.putU32(lifetime_s);
    builder.putU32(age_add);
    builder.putByte(@intCast(ticket_nonce.len));
    builder.putSlice(ticket_nonce);
    const body = builder.markU16();
    builder.putSlice(ticket);
    builder.patchU16(body);
    const extensions = builder.markU16();
    if (early_data_bytes_max) |bytes_max| {
        // §4.2.10's `early_data` again, and it carries a body here where
        // in a ClientHello it carries none — the one extension in this
        // library whose shape depends on the message holding it.
        builder.putU16(extension_early_data);
        const body_mark = builder.markU16();
        builder.putU32(bytes_max);
        builder.patchU16(body_mark);
    }
    builder.patchU16(extensions);
    handshake.endMessage(&builder, message);
    return builder.written();
}

/// §4.6.3. One byte of body: whether the peer is asked to rotate too.
pub fn keyUpdate(out: []u8, request_update: bool) []const u8 {
    assert(out.len >= handshake.header_bytes + 1);
    var builder = wire.Builder.init(out);
    const message = handshake.beginMessage(&builder, .key_update);
    builder.putByte(if (request_update) 1 else 0);
    handshake.endMessage(&builder, message);
    assert(builder.written().len == handshake.header_bytes + 1);
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
        client_hello.group_x25519,
        &vectors.server_x25519_public,
        null,
    );
    try std.testing.expectEqualSlices(u8, &vectors.server_hello, encoded);
}

test "serverHello with a selected PSK reproduces the §4 traced bytes" {
    const vectors = @import("rfc8448_vectors.zig");
    const traced_random = vectors.resumed_server_hello[6..38];
    var out: [server_hello_bytes_max]u8 = undefined;
    const encoded = serverHello(
        &out,
        traced_random,
        &.{},
        .aes_128_gcm_sha256,
        client_hello.group_x25519,
        &vectors.resumed_server_x25519_public,
        0,
    );
    try std.testing.expectEqualSlices(u8, &vectors.resumed_server_hello, encoded);
}

test "helloRetryRequest carries the §4.1.3 magic and the demanded group" {
    var out: [server_hello_bytes_max]u8 = undefined;
    const encoded = helloRetryRequest(&out, &.{ 0xab, 0xcd }, .chacha20_poly1305_sha256, client_hello.group_x25519);
    try std.testing.expectEqualSlices(u8, &hello_retry_magic, encoded[6..38]);
    // Session echo survives, and the message parses as server_hello.
    try std.testing.expectEqual(@as(u8, 2), encoded[38]);
    try std.testing.expectEqual(@as(u8, @intFromEnum(handshake.MessageType.server_hello)), encoded[0]);
    // Negative space: an HRR names a group but ships no key bytes.
    try std.testing.expect(encoded.len < 64);
}
