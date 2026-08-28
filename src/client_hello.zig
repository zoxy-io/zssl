//! ClientHello parsing (RFC 8446 §4.1.2).
//!
//! A view parser: the result borrows the input buffer and allocates
//! nothing. Every list on the wire is walked under a counted bound, every
//! length is checked before the slice, and the extensions this library
//! acts on are validated here — unknown extensions (GREASE included) are
//! skipped by structure, which is what keeps a 1.3-only server honest
//! about ignoring what it does not understand.

const std = @import("std");
const assert = std.debug.assert;

const cipher_suite = @import("cipher_suite.zig");
const wire = @import("wire.zig");
const CipherSuite = cipher_suite.CipherSuite;
const Cursor = wire.Cursor;

pub const Error = error{
    Truncated,
    TrailingBytes,
    MalformedMessage,
    MalformedExtension,
    /// A KeyShareEntry whose share length is not the one its group fixes
    /// (§4.2.8.2) — a compressed point where an uncompressed one belongs,
    /// most often. The value is illegal rather than undecodable, which is
    /// the difference between illegal_parameter and decode_error.
    BadKeyShare,
    IllegalCompression,
    SuiteOverflow,
    ExtensionOverflow,
    DuplicateExtension,
    PskNotLast,
};

/// Real clients offer a couple dozen suites (1.2 compatibility included)
/// and around twenty extensions with GREASE. The caps are generous by
/// several fold; past them is not a client, it is a probe.
pub const suites_count_max: u16 = 128;
pub const extensions_count_max: u16 = 64;
pub const key_share_entries_max: u16 = 16;

/// Names in one ALPN offer. Browsers send two or three; past this is a
/// probe, not a client.
pub const alpn_entries_max: u16 = 32;
pub const groups_count_max: u16 = 64;
pub const schemes_count_max: u16 = 64;
pub const psk_identities_max: u8 = 4;

pub const handshake_header_bytes: u8 = 4;
const client_hello_message_type: u8 = 0x01;

const extension_server_name: u16 = 0;
const extension_supported_groups: u16 = 10;
const extension_signature_algorithms: u16 = 13;
const extension_alpn: u16 = 16;
const extension_pre_shared_key: u16 = 41;
const extension_supported_versions: u16 = 43;
const extension_psk_key_exchange_modes: u16 = 45;
const extension_key_share: u16 = 51;
const tls13_wire_version: u16 = 0x0304;

pub const group_secp256r1: u16 = 0x0017;
pub const group_secp384r1: u16 = 0x0018;
pub const group_x25519: u16 = 0x001d;

/// The groups zssl can complete, in the order it prefers them. x25519
/// first because it is the fastest and the one every modern peer offers;
/// the NIST curves behind it because a terminating proxy meets clients
/// that offer nothing else.
pub const groups_supported = [_]u16{ group_x25519, group_secp256r1, group_secp384r1 };

/// A KeyShareEntry's share length is fixed by its group (§4.2.8.2): a
/// raw u-coordinate for x25519, an uncompressed SEC1 point otherwise.
pub fn groupShareBytes(group: u16) ?u16 {
    return switch (group) {
        group_x25519 => 32,
        group_secp256r1 => 65,
        group_secp384r1 => 97,
        else => null,
    };
}

pub const KeyShareEntry = struct {
    group: u16,
    share: []const u8,
};

pub const ClientHello = struct {
    random: *const [32]u8,
    legacy_session_id: []const u8,
    /// The raw u16 suite list, even-length, bounded at parse.
    cipher_suites_wire: []const u8,
    server_name: ?[]const u8 = null,
    /// The offered shares for groups we can complete, in the order the
    /// client sent them. Groups we do not hold are skipped rather than
    /// refused — §4.2.8 lets a client offer whatever it likes.
    key_shares: [groups_supported.len]KeyShareEntry = undefined,
    key_share_count: u8 = 0,
    /// Whether the extension was present at all, which `key_share_count`
    /// cannot say: a client that offers only groups we skip leaves the
    /// count at zero, and so does a client that sends the empty
    /// `client_shares` §4.2.8 defines for requesting our choice. Both of
    /// those earn a HelloRetryRequest. An omitted extension is a §9.2
    /// protocol error instead, so the two have to be distinguishable.
    has_key_share: bool = false,
    supports_tls13: bool = false,
    /// The inner u16 group list, prefix stripped and validated even.
    supported_groups_wire: ?[]const u8 = null,
    signature_algorithms_wire: ?[]const u8 = null,
    alpn_wire: ?[]const u8 = null,
    psk_modes_wire: ?[]const u8 = null,
    pre_shared_key_wire: ?[]const u8 = null,

    /// Walk the offered suites for one of ours.
    pub fn offersSuite(self: *const ClientHello, suite: CipherSuite) bool {
        assert(self.cipher_suites_wire.len % 2 == 0);
        assert(self.cipher_suites_wire.len <= 2 * @as(usize, suites_count_max));
        var index: usize = 0;
        while (index < self.cipher_suites_wire.len) : (index += 2) {
            const code = std.mem.readInt(u16, self.cipher_suites_wire[index..][0..2], .big);
            if (CipherSuite.fromWire(code) == suite) return true;
        }
        return false;
    }

    /// Whether the client's supported_groups names `group` — the fact a
    /// HelloRetryRequest decision rests on (§4.2.7).
    /// The share this client offered for `group`, if any.
    pub fn keyShareFor(self: *const ClientHello, group: u16) ?[]const u8 {
        assert(self.key_share_count <= groups_supported.len);
        for (self.key_shares[0..self.key_share_count]) |entry| {
            if (entry.group == group) return entry.share;
        }
        return null;
    }

    /// The first offered share we can complete, in *our* preference
    /// order rather than the client's — §4.2.8 leaves the choice to the
    /// server, and a client's ordering is a hint.
    pub fn preferredKeyShare(self: *const ClientHello) ?KeyShareEntry {
        assert(self.key_share_count <= groups_supported.len);
        for (groups_supported) |group| {
            if (self.keyShareFor(group)) |share| return .{ .group = group, .share = share };
        }
        return null;
    }

    /// The group we would ask for in a HelloRetryRequest: the first we
    /// hold that the client says it supports, share or no share.
    pub fn preferredSupportedGroup(self: *const ClientHello) ?u16 {
        for (groups_supported) |group| {
            if (self.supportsGroup(group)) return group;
        }
        return null;
    }

    pub fn supportsGroup(self: *const ClientHello, group: u16) bool {
        const list = self.supported_groups_wire orelse return false;
        assert(list.len % 2 == 0);
        assert(list.len >= 2);
        var index: usize = 0;
        while (index < list.len) : (index += 2) {
            if (std.mem.readInt(u16, list[index..][0..2], .big) == group) return true;
        }
        return false;
    }

    /// §4.2.9: whether the client accepts PSK-with-(EC)DHE — the only
    /// mode zssl speaks (pure psk_ke would skip the forward secrecy the
    /// design insists on).
    pub fn offersPskDheKe(self: *const ClientHello) bool {
        const data = self.psk_modes_wire orelse return false;
        var cursor = Cursor.init(data);
        const list_bytes = cursor.takeByte() catch return false;
        // Guaranteed by the framing check at parse: `psk_modes_wire` is
        // only set for a body whose length byte accounts for exactly the
        // bytes after it. Silently answering "no mode offered" for a
        // mismatch is the bug that check exists to fix, so this states
        // the invariant instead of re-tolerating it.
        assert(list_bytes == cursor.remaining());
        var index: u16 = 0;
        while (cursor.remaining() > 0) : (index += 1) {
            assert(index < 256); // A u8 list length bounds this structurally.
            const mode = cursor.takeByte() catch return false;
            if (mode == 0x01) return true;
        }
        return false;
    }

    /// Whether signature_algorithms names `scheme` (§4.2.3). The list was
    /// validated and prefix-stripped at parse, so this walk is over an
    /// even list already bounded by `schemes_count_max`.
    pub fn offersScheme(self: *const ClientHello, scheme: u16) bool {
        const list = self.signature_algorithms_wire orelse return false;
        assert(list.len % 2 == 0);
        assert(list.len <= 2 * @as(usize, schemes_count_max));
        var index: usize = 0;
        while (index < list.len) : (index += 2) {
            if (std.mem.readInt(u16, list[index..][0..2], .big) == scheme) return true;
        }
        return false;
    }
};

/// Parse one complete ClientHello handshake message, 4-byte handshake
/// header included. The input must be exactly one message: reassembly
/// across records is the layer above, and trailing bytes are its bug to
/// hear about, not this parser's to forgive.
pub fn parse(message: []const u8) Error!ClientHello {
    if (message.len < handshake_header_bytes) return error.Truncated;
    if (message[0] != client_hello_message_type) return error.MalformedMessage;
    const declared = std.mem.readInt(u24, message[1..4], .big);
    if (message.len < @as(usize, declared) + handshake_header_bytes) return error.Truncated;
    if (message.len > @as(usize, declared) + handshake_header_bytes) return error.TrailingBytes;
    assert(declared <= (1 << 24) - 1);
    return parseBody(message[handshake_header_bytes..]);
}

fn parseBody(body: []const u8) Error!ClientHello {
    var cursor = Cursor.init(body);
    // legacy_version is read and dropped. §4.1.2 freezes it at 0x0303,
    // but §4.2.1 is the rule that binds a *reader*: "servers MUST ignore
    // the ClientHello.legacy_version value and MUST use only the
    // 'supported_versions' extension to determine client preferences".
    // zssl used to refuse anything else, which turned a field the spec
    // says to ignore into a handshake failure.
    _ = try cursor.takeU16();

    const random = (try cursor.takeSlice(32))[0..32];
    const session_id_bytes = try cursor.takeByte();
    if (session_id_bytes > 32) return error.MalformedMessage;
    const legacy_session_id = try cursor.takeSlice(session_id_bytes);

    const suites_bytes = try cursor.takeU16();
    if (suites_bytes < 2) return error.MalformedMessage;
    if (suites_bytes % 2 != 0) return error.MalformedMessage;
    if (suites_bytes > 2 * suites_count_max) return error.SuiteOverflow;
    const cipher_suites_wire = try cursor.takeSlice(suites_bytes);

    // §4.1.2: legacy_compression_methods MUST be exactly [0].
    const compression_bytes = try cursor.takeByte();
    if (compression_bytes != 1) return error.IllegalCompression;
    if (try cursor.takeByte() != 0) return error.IllegalCompression;

    const extensions_bytes = try cursor.takeU16();
    if (extensions_bytes != cursor.remaining()) return error.TrailingBytes;
    const extensions_wire = try cursor.takeSlice(extensions_bytes);
    assert(cursor.remaining() == 0);

    var hello: ClientHello = .{
        .random = random,
        .legacy_session_id = legacy_session_id,
        .cipher_suites_wire = cipher_suites_wire,
    };
    try parseExtensions(extensions_wire, &hello);
    return hello;
}

fn parseExtensions(extensions_bytes: []const u8, hello: *ClientHello) Error!void {
    // §4.2 over the whole block first: a duplicate is a fault in the
    // block, and deciding it inside the loop below would let whichever
    // extension came first answer for it instead.
    try wire.refuseDuplicateExtensions(extensions_count_max, extensions_bytes);
    var cursor = Cursor.init(extensions_bytes);
    var count: u16 = 0;
    while (cursor.remaining() > 0) : (count += 1) {
        if (count >= extensions_count_max) return error.ExtensionOverflow;
        assert(count < extensions_count_max);
        // §4.2: pre_shared_key, when offered, is the last extension.
        if (hello.pre_shared_key_wire != null) return error.PskNotLast;
        const extension_type = try cursor.takeU16();
        const data_bytes = try cursor.takeU16();
        const data = try cursor.takeSlice(data_bytes);
        try applyExtension(extension_type, data, hello);
    }
    assert(cursor.remaining() == 0);
}

/// RFC 7301 §3.1: a list of length-prefixed names, each at least one
/// byte. An empty name is the one shape the grammar forbids outright.
fn validateAlpnList(data: []const u8) Error!void {
    var cursor = wire.Cursor.init(data);
    const list_bytes = try cursor.takeU16();
    if (list_bytes != cursor.remaining()) return error.MalformedExtension;
    var entries: u16 = 0;
    while (cursor.remaining() > 0) : (entries += 1) {
        if (entries == alpn_entries_max) return error.ExtensionOverflow;
        assert(entries < alpn_entries_max);
        const name_bytes = try cursor.takeByte();
        if (name_bytes == 0) return error.MalformedExtension;
        _ = try cursor.takeSlice(name_bytes);
    }
    if (entries == 0) return error.MalformedExtension;
}

fn applyExtension(extension_type: u16, data: []const u8, hello: *ClientHello) Error!void {
    switch (extension_type) {
        extension_server_name => hello.server_name = try parseServerName(data),
        extension_key_share => {
            hello.has_key_share = true;
            try parseKeyShare(data, hello);
        },
        extension_supported_versions => hello.supports_tls13 = try parseSupportedVersions(data),
        extension_supported_groups => {
            hello.supported_groups_wire = try parseU16List(data, groups_count_max);
        },
        extension_signature_algorithms => {
            hello.signature_algorithms_wire = try parseU16List(data, schemes_count_max);
        },
        extension_alpn => {
            // No length floor here: `validateAlpnList` needs two bytes of
            // list length, one of name length and one of name to
            // succeed, so it enforces the same four and does not need
            // help arriving at them.
            // Validated in full here rather than where a protocol gets
            // selected: selection stops at the first name it likes, so a
            // list whose *later* entries are malformed would be accepted
            // whenever an earlier one matched — BoGo offers
            // ["foo", "", "baz"] and asks for "foo". Framing is not a
            // question the server's configuration gets to answer.
            try validateAlpnList(data);
            hello.alpn_wire = data;
        },
        extension_psk_key_exchange_modes => {
            if (data.len < 2) return error.MalformedExtension;
            // §4.2.9's grammar is `psk_key_exchange_modes<1..255>`: one
            // length byte, accounting for exactly the bytes after it.
            // Checked here rather than left to `offersPskDheKe`, which
            // read a disagreeing length as "no mode offered" and let a
            // malformed hello through as an ordinary handshake. TLS-Anvil
            // sends the length one short of its contents.
            if (data[0] != data.len - 1) return error.MalformedExtension;
            hello.psk_modes_wire = data;
        },
        extension_pre_shared_key => {
            if (data.len < 12) return error.MalformedExtension;
            hello.pre_shared_key_wire = data;
        },
        else => {}, // Unknown: skipped whole, contents never inspected.
    }
}

/// §4.2.11: the offered PSKs, parsed on demand by the server once it has
/// decided it can use them. Views into the message, no copies.
pub const PskOffer = struct {
    identities: [psk_identities_max][]const u8,
    obfuscated_ages: [psk_identities_max]u32,
    binders: [psk_identities_max][]const u8,
    count: u8,
    /// Bytes the binders section occupies at the message's tail — what
    /// §4.2.11.2's truncated-transcript arithmetic removes.
    binders_section_bytes: u16,
};

/// Parse the pre_shared_key extension captured at `parse` time. Answers
/// null when the client offered none; malformed offers are errors, not
/// ignored — a client that speaks the extension badly is not a client to
/// guess about.
pub fn parsePskOffer(hello: *const ClientHello) Error!?PskOffer {
    const data = hello.pre_shared_key_wire orelse return null;
    var cursor = Cursor.init(data);
    var offer: PskOffer = .{
        .identities = undefined,
        .obfuscated_ages = undefined,
        .binders = undefined,
        .count = 0,
        .binders_section_bytes = 0,
    };
    const identities_bytes = try cursor.takeU16();
    // §4.2.11's floor: one entry is at least a 2-byte identity length,
    // one identity byte, and the 4-byte obfuscated age.
    if (identities_bytes < 7) return error.MalformedExtension;
    if (identities_bytes > cursor.remaining()) return error.Truncated;
    const identities_end = cursor.index + identities_bytes;
    while (cursor.index < identities_end) {
        if (offer.count == psk_identities_max) return error.ExtensionOverflow;
        assert(offer.count < psk_identities_max);
        const identity_bytes = try cursor.takeU16();
        if (identity_bytes == 0) return error.MalformedExtension;
        offer.identities[offer.count] = try cursor.takeSlice(identity_bytes);
        offer.obfuscated_ages[offer.count] = try cursor.takeU32();
        offer.count += 1;
    }
    if (cursor.index != identities_end) return error.MalformedExtension;

    const binders_bytes = try cursor.takeU16();
    if (binders_bytes != cursor.remaining()) return error.MalformedExtension;
    offer.binders_section_bytes = binders_bytes + 2;
    var binders_seen: u8 = 0;
    while (cursor.remaining() > 0) : (binders_seen += 1) {
        if (binders_seen == offer.count) return error.MalformedExtension;
        assert(binders_seen < offer.count);
        const binder_bytes = try cursor.takeByte();
        // §4.2.11.2: a binder is an HMAC output — 32 or 48 here.
        if (binder_bytes != 32 and binder_bytes != 48) return error.MalformedExtension;
        offer.binders[binders_seen] = try cursor.takeSlice(binder_bytes);
    }
    // §4.2.11: one binder per identity, exactly.
    if (binders_seen != offer.count) return error.MalformedExtension;
    assert(offer.count >= 1);
    return offer;
}

/// A `<u16 length, u16 items>` list body, validated and prefix-stripped —
/// the shape supported_groups and signature_algorithms share (§4.2.7,
/// §4.2.3). The count cap is what makes every later walk's bound a true
/// invariant instead of an assertion an attacker can reach.
fn parseU16List(data: []const u8, count_max: u16) Error![]const u8 {
    var cursor = Cursor.init(data);
    const list_bytes = try cursor.takeU16();
    if (list_bytes != cursor.remaining()) return error.MalformedExtension;
    if (list_bytes < 2) return error.MalformedExtension;
    if (list_bytes % 2 != 0) return error.MalformedExtension;
    if (list_bytes > 2 * count_max) return error.ExtensionOverflow;
    const list = try cursor.takeSlice(list_bytes);
    assert(cursor.remaining() == 0);
    assert(list.len >= 2);
    return list;
}

/// §3 of RFC 6066: a ServerNameList; only host_name (0) entries exist.
fn parseServerName(data: []const u8) Error![]const u8 {
    var cursor = Cursor.init(data);
    const list_bytes = try cursor.takeU16();
    if (list_bytes != cursor.remaining()) return error.MalformedExtension;
    if (list_bytes < 3) return error.MalformedExtension;
    const name_type = try cursor.takeByte();
    if (name_type != 0) return error.MalformedExtension;
    const name_bytes = try cursor.takeU16();
    if (name_bytes == 0) return error.MalformedExtension;
    if (name_bytes != cursor.remaining()) return error.MalformedExtension;
    const name = try cursor.takeSlice(name_bytes);
    assert(name.len >= 1);
    assert(cursor.remaining() == 0);
    return name;
}

/// §4.2.8: walk the KeyShareClientHello, keeping the entries for groups
/// we can complete. A duplicate group is a MUST NOT the client broke;
/// unknown groups pass by, because offering them is legal.
fn parseKeyShare(data: []const u8, hello: *ClientHello) Error!void {
    var cursor = Cursor.init(data);
    const list_bytes = try cursor.takeU16();
    if (list_bytes != cursor.remaining()) return error.MalformedExtension;
    var entries: u16 = 0;
    while (cursor.remaining() > 0) : (entries += 1) {
        if (entries >= key_share_entries_max) return error.ExtensionOverflow;
        assert(entries < key_share_entries_max);
        const group = try cursor.takeU16();
        const share_bytes = try cursor.takeU16();
        const share = try cursor.takeSlice(share_bytes);
        const expected = groupShareBytes(group) orelse continue;
        if (hello.keyShareFor(group) != null) return error.MalformedExtension;
        // A share whose length does not match its group never reaches
        // the crypto boundary; §4.2.8.2 fixes the length per group.
        if (share.len != expected) return error.BadKeyShare;
        assert(hello.key_share_count < groups_supported.len);
        hello.key_shares[hello.key_share_count] = .{ .group = group, .share = share };
        hello.key_share_count += 1;
    }
    assert(cursor.remaining() == 0);
}

/// §4.2.1: the client's version list; 0x0304 anywhere in it is the offer.
fn parseSupportedVersions(data: []const u8) Error!bool {
    var cursor = Cursor.init(data);
    const list_bytes = try cursor.takeByte();
    if (list_bytes != cursor.remaining()) return error.MalformedExtension;
    if (list_bytes < 2) return error.MalformedExtension;
    if (list_bytes % 2 != 0) return error.MalformedExtension;
    var supports_tls13 = false;
    var index: u16 = 0;
    while (cursor.remaining() > 0) : (index += 1) {
        assert(index < 128); // list_bytes ≤ 255 bounds this structurally.
        const version = try cursor.takeU16();
        if (version == tls13_wire_version) supports_tls13 = true;
    }
    assert(cursor.remaining() == 0);
    return supports_tls13;
}

test "parses RFC 8448's ClientHello field for field" {
    const vectors = @import("rfc8448_vectors.zig");
    const hello = try parse(&vectors.client_hello);

    try std.testing.expectEqualSlices(u8, "server", hello.server_name.?);
    try std.testing.expectEqual(@as(usize, 0), hello.legacy_session_id.len);
    try std.testing.expect(hello.supports_tls13);
    try std.testing.expectEqualSlices(
        u8,
        &vectors.client_x25519_public,
        hello.keyShareFor(group_x25519).?,
    );
    try std.testing.expectEqual(group_x25519, hello.preferredKeyShare().?.group);
    // The trace offers 0x1301, 0x1303, 0x1302 in that order.
    try std.testing.expect(hello.offersSuite(.aes_128_gcm_sha256));
    try std.testing.expect(hello.offersSuite(.aes_256_gcm_sha384));
    try std.testing.expect(hello.offersSuite(.chacha20_poly1305_sha256));
    try std.testing.expectEqual(@as(usize, 6), hello.cipher_suites_wire.len);
    try std.testing.expect(hello.supportsGroup(group_x25519));
    try std.testing.expect(!hello.supportsGroup(0x9999));
    try std.testing.expect(hello.offersScheme(0x0403));
    try std.testing.expect(hello.offersScheme(0x0503));
    try std.testing.expect(!hello.offersScheme(0x0807)); // ed25519 is not in the trace's list.
    try std.testing.expect(hello.psk_modes_wire != null);
    // Negative space: nothing this trace does not offer appears offered.
    try std.testing.expectEqual(@as(?[]const u8, null), hello.alpn_wire);
    try std.testing.expectEqual(@as(?[]const u8, null), hello.pre_shared_key_wire);
}

test "rejects what the grammar forbids" {
    const vectors = @import("rfc8448_vectors.zig");

    // Truncation at every prefix must answer Truncated — never a crash,
    // never a false parse. Bounded by the message length itself.
    var length: usize = 0;
    while (length < vectors.client_hello.len) : (length += 1) {
        try std.testing.expectError(error.Truncated, parse(vectors.client_hello[0..length]));
    }

    // A trailing byte after the extensions block.
    var padded: [vectors.client_hello.len + 1]u8 = undefined;
    @memcpy(padded[0..vectors.client_hello.len], &vectors.client_hello);
    padded[vectors.client_hello.len] = 0x00;
    try std.testing.expectError(error.TrailingBytes, parse(&padded));

    // Compression [1, 1] instead of [0]: a 1.2-era client.
    var bad_compression = vectors.client_hello;
    // Offset of the compression block in this trace: 4 (header) + 2 + 32 +
    // 1 (empty session id) + 2 + 6 (suites) = 47; byte 47 is the count.
    try std.testing.expectEqual(@as(u8, 1), bad_compression[47]);
    bad_compression[48] = 0x01;
    try std.testing.expectError(error.IllegalCompression, parse(&bad_compression));
}
