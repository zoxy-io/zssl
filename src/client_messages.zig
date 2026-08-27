//! Client-side handshake message encoding (RFC 8446 §4.1.2): the
//! production ClientHello. Pure functions into caller-owned buffers, like
//! `server_messages.zig`; the machine decides when, these decide bytes.
//!
//! One deliberate absence: no knobs for malformed output. The adversarial
//! encoder lives in `test_client.zig`; this one only knows how to be
//! correct.

const std = @import("std");
const assert = std.debug.assert;

const cipher_suite = @import("cipher_suite.zig");
const client_hello = @import("client_hello.zig");
const handshake = @import("handshake.zig");
const key_schedule = @import("key_schedule.zig");
const server_messages = @import("server_messages.zig");
const wire = @import("wire.zig");
const CipherSuite = cipher_suite.CipherSuite;

/// Base fields plus every extension at its cap (a 255-byte server name,
/// a 512-byte ticket identity, a 48-byte binder, a full ALPN list).
pub const hello_bytes_max: u16 = 1280;

/// ALPN offer caps. Four is what a client that speaks HTTP needs — `h2`
/// and `http/1.1` with room to spare — and each name is bounded so the
/// hello's own bound stays a constant rather than a function of config.
pub const alpn_protocols_max: u8 = 4;
pub const alpn_protocol_bytes_max: u8 = 32;

pub const PskParams = struct {
    identity: []const u8,
    obfuscated_age: u32,
    /// One hash length — decides the binder placeholder's size.
    binder_bytes: u8,
};

pub const HelloParams = struct {
    random: *const [32]u8,
    session_id: []const u8,
    x25519_public: *const [32]u8,
    server_name: ?[]const u8 = null,
    /// Offered in preference order (RFC 7301 §3.1); empty omits the
    /// extension entirely.
    alpn_protocols: []const []const u8 = &.{},
    psk: ?PskParams = null,
};

/// Build the ClientHello. When a PSK is offered the binder bytes are a
/// zero placeholder — the caller computes and patches them over the
/// finished message (§4.2.11.2's truncated-transcript dance).
pub fn clientHello(out: []u8, params: *const HelloParams) []const u8 {
    assert(out.len >= hello_bytes_max);
    assert(params.session_id.len <= 32);
    if (params.server_name) |name| assert(name.len >= 1);
    if (params.server_name) |name| assert(name.len <= 255);
    assert(params.alpn_protocols.len <= alpn_protocols_max);
    var builder = wire.Builder.init(out);
    const message = handshake.beginMessage(&builder, .client_hello);
    builder.putU16(0x0303);
    builder.putSlice(params.random);
    builder.putByte(@intCast(params.session_id.len));
    builder.putSlice(params.session_id);
    // All three §B.4 suites, AES-128-GCM first — the order the server's
    // own preference list starts with.
    builder.putU16(6);
    builder.putU16(@intFromEnum(CipherSuite.aes_128_gcm_sha256));
    builder.putU16(@intFromEnum(CipherSuite.chacha20_poly1305_sha256));
    builder.putU16(@intFromEnum(CipherSuite.aes_256_gcm_sha384));
    builder.putByte(1);
    builder.putByte(0);
    const extensions = builder.markU16();
    helloExtensions(&builder, params);
    builder.patchU16(extensions);
    handshake.endMessage(&builder, message);
    assert(builder.written().len >= 64);
    assert(builder.written().len <= hello_bytes_max);
    return builder.written();
}

fn helloExtensions(builder: *wire.Builder, params: *const HelloParams) void {
    assert(builder.index >= 40);
    if (params.server_name) |name| {
        builder.putU16(0); // server_name (RFC 6066 §3)
        const body = builder.markU16();
        const list = builder.markU16();
        builder.putByte(0);
        const name_mark = builder.markU16();
        builder.putSlice(name);
        builder.patchU16(name_mark);
        builder.patchU16(list);
        builder.patchU16(body);
    }
    builder.putU16(10); // supported_groups: x25519 is the one we hold keys for.
    const groups = builder.markU16();
    const group_list = builder.markU16();
    builder.putU16(client_hello.group_x25519);
    builder.patchU16(group_list);
    builder.patchU16(groups);
    // signature_algorithms (§4.2.3): what we will accept in the server's
    // CertificateVerify. ECDSA first — it is what zssl's own server signs
    // with, and the cheaper verify — then RSA-PSS, because a client that
    // originates to arbitrary upstreams meets RSA leaves constantly and a
    // list without them is a handshake failure against most of the public
    // web. rsa_pkcs1_* is absent on purpose: §4.4.3 forbids it in
    // CertificateVerify, and listing it would invite a signature we then
    // refuse.
    builder.putU16(13);
    const schemes = builder.markU16();
    const scheme_list = builder.markU16();
    builder.putU16(0x0403); // ecdsa_secp256r1_sha256
    builder.putU16(0x0503); // ecdsa_secp384r1_sha384
    builder.putU16(0x0804); // rsa_pss_rsae_sha256
    builder.putU16(0x0805); // rsa_pss_rsae_sha384
    builder.putU16(0x0806); // rsa_pss_rsae_sha512
    builder.patchU16(scheme_list);
    builder.patchU16(schemes);
    if (params.alpn_protocols.len >= 1) {
        builder.putU16(16); // application_layer_protocol_negotiation
        const body = builder.markU16();
        const list = builder.markU16();
        for (params.alpn_protocols) |protocol| {
            assert(protocol.len >= 1);
            assert(protocol.len <= alpn_protocol_bytes_max);
            builder.putByte(@intCast(protocol.len));
            builder.putSlice(protocol);
        }
        builder.patchU16(list);
        builder.patchU16(body);
    }
    builder.putU16(43); // supported_versions: 1.3 and nothing else.
    const versions = builder.markU16();
    builder.putByte(2);
    builder.putU16(0x0304);
    builder.patchU16(versions);
    builder.putU16(51); // key_share
    const shares = builder.markU16();
    const share_list = builder.markU16();
    builder.putU16(client_hello.group_x25519);
    builder.putU16(32);
    builder.putSlice(params.x25519_public);
    builder.patchU16(share_list);
    builder.patchU16(shares);
    if (params.psk) |psk| helloPskExtensions(builder, &psk);
}

fn helloPskExtensions(builder: *wire.Builder, psk: *const PskParams) void {
    assert(psk.identity.len >= 1);
    assert(psk.identity.len <= server_messages.ticket_bytes_max);
    assert(psk.binder_bytes == 32 or psk.binder_bytes == 48);
    builder.putU16(45); // psk_key_exchange_modes: psk_dhe_ke only.
    const modes = builder.markU16();
    builder.putByte(1);
    builder.putByte(0x01);
    builder.patchU16(modes);
    builder.putU16(41); // pre_shared_key — last, per §4.2.
    const extension = builder.markU16();
    const identities = builder.markU16();
    builder.putU16(@intCast(psk.identity.len));
    builder.putSlice(psk.identity);
    builder.putU32(psk.obfuscated_age);
    builder.patchU16(identities);
    const binders = builder.markU16();
    builder.putByte(psk.binder_bytes);
    const placeholder = [_]u8{0} ** 48;
    builder.putSlice(placeholder[0..psk.binder_bytes]);
    builder.patchU16(binders);
    builder.patchU16(extension);
}

/// Compute and patch the binder over the finished message, with the hash
/// the PSK itself is bound to — decided by its length, not by whatever
/// suite the server will pick (§4.2.11.2).
pub fn patchBinder(message: []u8, psk: []const u8) void {
    assert(psk.len == 32 or psk.len == 48);
    const binders_section_bytes = 2 + 1 + psk.len;
    assert(message.len > binders_section_bytes + handshake.header_bytes);
    const truncated = message[0 .. message.len - binders_section_bytes];
    switch (psk.len) {
        inline 32, 48 => |comptime_bytes| {
            const suite: CipherSuite = if (comptime_bytes == 32) .aes_128_gcm_sha256 else .aes_256_gcm_sha384;
            const Hash = CipherSuite.HashType(suite);
            const Schedule = key_schedule.KeySchedule(suite);
            var truncated_hash: [Hash.digest_length]u8 = undefined;
            Hash.hash(truncated, &truncated_hash, .{});
            var schedule = Schedule.initEarly(psk);
            const binder = schedule.resumptionBinder(&truncated_hash);
            schedule.wipe();
            @memcpy(message[message.len - psk.len ..], &binder);
        },
        else => unreachable,
    }
}

test "the production hello parses under our own strict parser" {
    var out: [hello_bytes_max]u8 = undefined;
    const random = [_]u8{0x07} ** 32;
    const public = [_]u8{0x0b} ** 32;
    const encoded = clientHello(&out, &.{
        .random = &random,
        .session_id = &(.{0xee} ** 32),
        .x25519_public = &public,
        .server_name = "origin.internal",
        .alpn_protocols = &.{ "h2", "http/1.1" },
    });
    const hello = try client_hello.parse(encoded);
    try std.testing.expectEqualSlices(u8, "origin.internal", hello.server_name.?);
    try std.testing.expect(hello.supports_tls13);
    try std.testing.expect(hello.supportsGroup(client_hello.group_x25519));
    try std.testing.expect(hello.offersScheme(0x0403));
    // RSA-PSS travels beside ECDSA: an upstream with an RSA leaf must not
    // see a list that forces it to fail the handshake.
    try std.testing.expect(hello.offersScheme(0x0804));
    try std.testing.expectEqualSlices(u8, &public, hello.key_share_x25519.?);
    try std.testing.expect(hello.offersSuite(.aes_128_gcm_sha256));
    try std.testing.expect(hello.offersSuite(.aes_256_gcm_sha384));
    try std.testing.expect(hello.offersSuite(.chacha20_poly1305_sha256));
    // Negative space: no PSK material appears when none was configured.
    try std.testing.expectEqual(@as(?[]const u8, null), hello.pre_shared_key_wire);
    try std.testing.expect(!hello.offersPskDheKe());
}

test "a PSK hello carries a well-formed offer and a patchable binder" {
    var out: [hello_bytes_max]u8 = undefined;
    const random = [_]u8{0x07} ** 32;
    const public = [_]u8{0x0b} ** 32;
    const psk = [_]u8{0x33} ** 32;
    const encoded = clientHello(&out, &.{
        .random = &random,
        .session_id = &.{},
        .x25519_public = &public,
        .psk = .{ .identity = "sealed-ticket", .obfuscated_age = 7, .binder_bytes = 32 },
    });
    // The mutable view for patching is the same bytes.
    patchBinder(out[0..encoded.len], &psk);
    const hello = try client_hello.parse(out[0..encoded.len]);
    try std.testing.expect(hello.offersPskDheKe());
    const offer = (try client_hello.parsePskOffer(&hello)).?;
    try std.testing.expectEqual(@as(u8, 1), offer.count);
    try std.testing.expectEqualSlices(u8, "sealed-ticket", offer.identities[0]);
    try std.testing.expectEqual(@as(u16, 35), offer.binders_section_bytes);
    // The patched binder is not the placeholder.
    try std.testing.expect(!std.mem.allEqual(u8, offer.binders[0], 0));
}
