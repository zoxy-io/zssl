//! Client-side handshake message encoding (RFC 8446 §4.1.2): the
//! production ClientHello. Pure functions into caller-owned buffers, like
//! `server_messages.zig`; the machine decides when, these decide bytes.
//!
//! One deliberate absence: no knobs for malformed output. The adversarial
//! encoder lives in `test_client.zig`; this one only knows how to be
//! correct.

const std = @import("std");
const assert = std.debug.assert;

/// §4.2.10, empty here and a `uint32` in a NewSessionTicket — one code
/// point, two shapes, decided by the message carrying it.
const extension_early_data: u16 = 42;

const backend = @import("crypto/backend_openssl.zig");
const cipher_suite = @import("cipher_suite.zig");
const client_hello = @import("client_hello.zig");
const handshake = @import("handshake.zig");
const key_schedule = @import("key_schedule.zig");
const server_messages = @import("server_messages.zig");
const wire = @import("wire.zig");
const CipherSuite = cipher_suite.CipherSuite;

/// §4.2.3's default offer: ECDSA first — it is what zssl's own server
/// signs with, and the cheaper verify — then RSA-PSS, because a client
/// that originates to arbitrary upstreams meets RSA leaves constantly
/// and a list without them is a handshake failure against most of the
/// public web.
///
/// One list, because §4.4.3 makes the hello's offer and the verifier's
/// accept-set the same promise: `ClientHandshake.Config.verify_schemes`
/// defaults to this and is what both read.
pub const signature_schemes_default = [_]backend.SignatureScheme{
    .ecdsa_secp256r1_sha256,
    .ecdsa_secp384r1_sha384,
    .rsa_pss_rsae_sha256,
    .rsa_pss_rsae_sha384,
    .rsa_pss_rsae_sha512,
};

/// Base fields plus every extension at its cap (a 255-byte server name,
/// a 512-byte ticket identity, a 48-byte binder, a full ALPN list).
/// 4096, not 1280. A resumption hello carries the ticket the *server*
/// chose the size of, and §4.2.11 writes `opaque identity<1..2^16-1>`.
/// 1280 was sized against the tickets zssl issues (512) rather than the
/// ones it might be handed: BoGo's runner mints 829 bytes once a client
/// certificate is in the session, and offering one panicked
/// `helloPreSharedKey` on an assertion — a crash any conforming server
/// could trigger by issuing a large ticket.
pub const hello_bytes_max: u16 = 5120;

/// §4.2.2's cookie, echoed verbatim into the second ClientHello. Its
/// size is the *server's* choice for a buffer that is ours, so it needs
/// a bound of ours.
pub const cookie_bytes_max: u16 = 512;

/// Everything a maximal hello carries except the PSK identity and the
/// cookie: the two variable fields whose size a peer picks. 768 is
/// conservative against the ~700 the encoder actually writes, and
/// `"a maximal ClientHello fits its own buffer"` below is the check
/// rather than this comment.
const fixed_bytes_max: u16 = 768;

/// The largest PSK identity a hello can carry, which is what bounds a
/// ticket an embedder may offer back. Derived from what is left of the
/// buffer once the fixed part and a maximal cookie are spoken for —
/// a *retried resumption* carries both at once, which is the case that
/// makes this a subtraction rather than two independent bounds.
pub const psk_identity_bytes_max: u16 = hello_bytes_max - fixed_bytes_max - cookie_bytes_max;

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
    /// §4.2.10: offer 0-RTT against this identity. Empty on the wire —
    /// the offer *is* the extension's presence — and legal only beside a
    /// `pre_shared_key`, which is why it lives here rather than beside
    /// `alpn_protocols`.
    early_data: bool = false,
};

pub const HelloParams = struct {
    random: *const [32]u8,
    session_id: []const u8,
    /// The one group we send a share for, and that share. A second hello
    /// after a HelloRetryRequest carries a different pair — §4.1.4 makes
    /// the retry's whole purpose "send a share for the group I name", so
    /// this cannot be fixed at x25519 the way it once was.
    share_group: u16,
    share_public: []const u8,
    /// What `supported_groups` advertises, in preference order. Wider
    /// than `share_group` on purpose: a client that advertises only what
    /// it has already shared can never be sent a legal
    /// HelloRetryRequest, which is a way of being untestable as much as
    /// it is a way of being narrow (DESIGN.md §1).
    groups: []const u16,
    /// §4.2.3's `signature_algorithms`, in preference order — what we
    /// will accept in the server's CertificateVerify. §4.4.3 makes this
    /// a promise rather than a hint: a signature under a scheme absent
    /// from here is an abort, so the list the hello carries and the list
    /// the verifier enforces have to be the same one.
    signature_schemes: []const backend.SignatureScheme,
    /// §4.2.2: echoed verbatim from a HelloRetryRequest that sent one.
    /// The server may keep its whole retry state in here, so dropping it
    /// is not a simplification — it is a handshake that cannot complete.
    cookie: ?[]const u8 = null,
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
    assert(params.groups.len >= 1);
    assert(params.signature_schemes.len >= 1);
    assert(params.share_public.len >= 1);
    if (params.cookie) |cookie| assert(cookie.len >= 1);
    if (params.cookie) |cookie| assert(cookie.len <= cookie_bytes_max);
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
    builder.putU16(10); // supported_groups
    const groups = builder.markU16();
    const group_list = builder.markU16();
    for (params.groups) |group| builder.putU16(group);
    builder.patchU16(group_list);
    builder.patchU16(groups);
    // signature_algorithms (§4.2.3): what we will accept in the server's
    // CertificateVerify. The default is ECDSA first — it is what zssl's
    // own server signs with, and the cheaper verify — then RSA-PSS,
    // because a client that originates to arbitrary upstreams meets RSA
    // leaves constantly and a list without them is a handshake failure
    // against most of the public web. rsa_pkcs1_* cannot appear at all:
    // §4.4.3 forbids it in CertificateVerify, and `SignatureScheme` has
    // no code point for it, so the type is what keeps it out.
    builder.putU16(13);
    const schemes = builder.markU16();
    const scheme_list = builder.markU16();
    for (params.signature_schemes) |scheme| builder.putU16(@intFromEnum(scheme));
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
    if (params.cookie) |cookie| {
        builder.putU16(44); // cookie (§4.2.2)
        const body = builder.markU16();
        const value = builder.markU16();
        builder.putSlice(cookie);
        builder.patchU16(value);
        builder.patchU16(body);
    }
    builder.putU16(51); // key_share
    const shares = builder.markU16();
    const share_list = builder.markU16();
    builder.putU16(params.share_group);
    builder.putU16(@intCast(params.share_public.len));
    builder.putSlice(params.share_public);
    builder.patchU16(share_list);
    builder.patchU16(shares);
    // psk_key_exchange_modes (§4.2.9), sent on *every* hello and not only
    // on the resuming one: §4.6.1 lets a server issue a NewSessionTicket
    // only to a client that has advertised a mode it can resume under, so
    // a hello without this can never be given a ticket to come back with.
    // psk_dhe_ke alone — zssl never accepts psk_ke (slice 3).
    builder.putU16(45);
    const modes = builder.markU16();
    builder.putByte(1);
    builder.putByte(0x01);
    builder.patchU16(modes);
    if (params.psk) |psk| {
        // §4.2.10's extension goes ahead of `pre_shared_key`, because
        // §4.2 makes that one last and everything else is "before".
        if (psk.early_data) {
            builder.putU16(extension_early_data);
            builder.patchU16(builder.markU16());
        }
        helloPreSharedKey(builder, &psk);
    }
}

/// §4.2's one ordering rule: pre_shared_key is the last extension in the
/// ClientHello, because the binder is computed over everything before it.
fn helloPreSharedKey(builder: *wire.Builder, psk: *const PskParams) void {
    assert(psk.identity.len >= 1);
    assert(psk.identity.len <= psk_identity_bytes_max);
    assert(psk.binder_bytes == 32 or psk.binder_bytes == 48);
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

/// The bytes §4.2.11.2's binder covers: the hello up to but not
/// including the binders section `helloPreSharedKey` left as a
/// placeholder. Public because a caller computing the binder's
/// transcript itself — see `patchBinder`'s `transcript_hash` — needs to
/// know where the truncation falls before it can hash it.
pub fn binderTruncation(message: []const u8, psk_bytes: u8) []const u8 {
    assert(psk_bytes == 32 or psk_bytes == 48);
    const binders_section_bytes = 2 + 1 + @as(usize, psk_bytes);
    assert(message.len > binders_section_bytes + handshake.header_bytes);
    return message[0 .. message.len - binders_section_bytes];
}

/// Compute and patch the binder over the finished message, with the hash
/// the PSK itself is bound to — decided by its length, not by whatever
/// suite the server will pick (§4.2.11.2).
///
/// `transcript_hash` is §4.2.11.2's `Transcript-Hash(Truncate(...))`,
/// and null asks for the plain reading of it: the truncated hello
/// hashed alone, which is right for a first ClientHello and wrong for
/// every second one. After a HelloRetryRequest §4.4.1 replaces CH1 with
/// a `message_hash` message and puts the retry behind it, so the binder
/// covers three things and only the caller holds the first two —
/// `ClientHandshake.handleHelloRetryRequest` passes them in as a hash
/// taken off the ladder's transcript. Getting this wrong is not a
/// handshake that fails here; it is one that fails at the server's
/// binder check and blames the key.
pub fn patchBinder(message: []u8, psk: []const u8, transcript_hash: ?[]const u8) void {
    assert(psk.len == 32 or psk.len == 48);
    const truncated = binderTruncation(message, @intCast(psk.len));
    if (transcript_hash) |given| assert(given.len == psk.len);
    switch (psk.len) {
        inline 32, 48 => |comptime_bytes| {
            const suite: CipherSuite = if (comptime_bytes == 32) .aes_128_gcm_sha256 else .aes_256_gcm_sha384;
            const Hash = CipherSuite.HashType(suite);
            const Schedule = key_schedule.KeySchedule(suite);
            var truncated_hash: [Hash.digest_length]u8 = undefined;
            if (transcript_hash) |given| {
                @memcpy(&truncated_hash, given);
            } else {
                Hash.hash(truncated, &truncated_hash, .{});
            }
            var schedule = Schedule.initEarly(psk);
            // Resumption by construction: this offer's PSK came from a
            // ticket this client was issued. Offering an *external* PSK
            // would need the suite from somewhere other than the PSK's
            // length, which the switch above infers it from — see
            // `ServerHandshake.Psk`, where the accepting half does
            // carry the distinction.
            const binder = schedule.pskBinder(.resumption, &truncated_hash);
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
        .share_group = client_hello.group_x25519,
        .share_public = &public,
        .signature_schemes = &signature_schemes_default,
        .groups = &.{client_hello.group_x25519},
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
    try std.testing.expectEqualSlices(u8, &public, hello.keyShareFor(client_hello.group_x25519).?);
    try std.testing.expect(hello.offersSuite(.aes_128_gcm_sha256));
    try std.testing.expect(hello.offersSuite(.aes_256_gcm_sha384));
    try std.testing.expect(hello.offersSuite(.chacha20_poly1305_sha256));
    // Negative space: no PSK *offer* appears when none was configured —
    // but the mode does, because §4.6.1 lets a server issue a ticket only
    // to a client that has said which mode it would resume under. A hello
    // without this can never be given a ticket to come back with.
    try std.testing.expectEqual(@as(?[]const u8, null), hello.pre_shared_key_wire);
    try std.testing.expect(hello.offersPskDheKe());
}

test "a PSK hello carries a well-formed offer and a patchable binder" {
    var out: [hello_bytes_max]u8 = undefined;
    const random = [_]u8{0x07} ** 32;
    const public = [_]u8{0x0b} ** 32;
    const psk = [_]u8{0x33} ** 32;
    const encoded = clientHello(&out, &.{
        .random = &random,
        .session_id = &.{},
        .share_group = client_hello.group_x25519,
        .share_public = &public,
        .signature_schemes = &signature_schemes_default,
        .groups = &.{client_hello.group_x25519},
        .psk = .{ .identity = "sealed-ticket", .obfuscated_age = 7, .binder_bytes = 32 },
    });
    // The mutable view for patching is the same bytes.
    patchBinder(out[0..encoded.len], &psk, null);
    const hello = try client_hello.parse(out[0..encoded.len]);
    try std.testing.expect(hello.offersPskDheKe());
    const offer = (try client_hello.parsePskOffer(&hello)).?;
    try std.testing.expectEqual(@as(u8, 1), offer.count);
    try std.testing.expectEqualSlices(u8, "sealed-ticket", offer.identities[0]);
    try std.testing.expectEqual(@as(u16, 35), offer.binders_section_bytes);
    // The patched binder is not the placeholder.
    try std.testing.expect(!std.mem.allEqual(u8, offer.binders[0], 0));
}

test "a maximal ClientHello fits its own buffer" {
    // `hello_bytes_max` is the only thing between a peer-chosen length
    // and an out-of-bounds write: `wire.Builder` bounds-checks nothing,
    // so every `put` past the end is an assertion at best. The number
    // was derived by hand twice and was wrong the second time — it
    // omitted §4.2.2's cookie, which a server sizes and we must echo —
    // so it is derived by *construction* here instead.
    //
    // Every field at its documented maximum, and both peer-chosen ones
    // at once: a retried resumption is the flight that carries a cookie
    // and a PSK identity in the same hello.
    var out: [hello_bytes_max]u8 = undefined;
    const identity = [_]u8{0xa5} ** psk_identity_bytes_max;
    const cookie = [_]u8{0xc0} ** cookie_bytes_max;
    const name = [_]u8{'n'} ** 255;
    const public = [_]u8{0x0b} ** 97; // Uncompressed P-384, the widest share.
    const encoded = clientHello(&out, &.{
        .random = &(.{0x07} ** 32),
        .session_id = &(.{0xee} ** 32),
        .share_group = client_hello.group_secp384r1,
        .share_public = &public,
        .signature_schemes = &signature_schemes_default,
        .groups = &client_hello.groups_supported,
        .cookie = &cookie,
        .server_name = &name,
        .alpn_protocols = &.{
            &(.{'a'} ** alpn_protocol_bytes_max),
            &(.{'b'} ** alpn_protocol_bytes_max),
            &(.{'c'} ** alpn_protocol_bytes_max),
            &(.{'d'} ** alpn_protocol_bytes_max),
        },
        .psk = .{ .identity = &identity, .obfuscated_age = 7, .binder_bytes = 48 },
    });
    // The assertion inside `clientHello` would already have fired; this
    // says by how much, so a future field has a number to spend rather
    // than a cliff to discover.
    try std.testing.expect(encoded.len <= hello_bytes_max);
    const headroom = hello_bytes_max - encoded.len;
    try std.testing.expect(headroom < 1024); // Not wildly oversized either.
}
