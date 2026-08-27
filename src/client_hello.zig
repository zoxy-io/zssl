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
const CipherSuite = cipher_suite.CipherSuite;

pub const Error = error{
    Truncated,
    TrailingBytes,
    MalformedMessage,
    MalformedExtension,
    UnsupportedLegacyVersion,
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

pub const handshake_header_bytes: u8 = 4;
const client_hello_message_type: u8 = 0x01;

const extension_server_name: u16 = 0;
const extension_signature_algorithms: u16 = 13;
const extension_alpn: u16 = 16;
const extension_pre_shared_key: u16 = 41;
const extension_supported_versions: u16 = 43;
const extension_psk_key_exchange_modes: u16 = 45;
const extension_key_share: u16 = 51;
const group_x25519: u16 = 0x001d;
const tls13_wire_version: u16 = 0x0304;

pub const ClientHello = struct {
    random: *const [32]u8,
    legacy_session_id: []const u8,
    /// The raw u16 suite list, even-length, bounded at parse.
    cipher_suites_wire: []const u8,
    server_name: ?[]const u8 = null,
    key_share_x25519: ?*const [32]u8 = null,
    supports_tls13: bool = false,
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
            const wire = std.mem.readInt(u16, self.cipher_suites_wire[index..][0..2], .big);
            if (CipherSuite.fromWire(wire) == suite) return true;
        }
        return false;
    }
};

const Cursor = struct {
    bytes: []const u8,
    index: usize,

    fn init(bytes: []const u8) Cursor {
        return .{ .bytes = bytes, .index = 0 };
    }

    fn remaining(self: *const Cursor) usize {
        assert(self.index <= self.bytes.len);
        return self.bytes.len - self.index;
    }

    fn takeByte(self: *Cursor) Error!u8 {
        if (self.remaining() < 1) return error.Truncated;
        const byte = self.bytes[self.index];
        self.index += 1;
        return byte;
    }

    fn takeU16(self: *Cursor) Error!u16 {
        if (self.remaining() < 2) return error.Truncated;
        const value = std.mem.readInt(u16, self.bytes[self.index..][0..2], .big);
        self.index += 2;
        return value;
    }

    fn takeU24(self: *Cursor) Error!u24 {
        if (self.remaining() < 3) return error.Truncated;
        const value = std.mem.readInt(u24, self.bytes[self.index..][0..3], .big);
        self.index += 3;
        return value;
    }

    fn takeSlice(self: *Cursor, count: usize) Error![]const u8 {
        if (self.remaining() < count) return error.Truncated;
        const slice = self.bytes[self.index..][0..count];
        self.index += count;
        return slice;
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
    // legacy_version is frozen at 0x0303 in TLS 1.3 (§4.1.2); the real
    // version negotiation happens in supported_versions.
    const legacy_version = try cursor.takeU16();
    if (legacy_version != 0x0303) return error.UnsupportedLegacyVersion;

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

fn parseExtensions(wire: []const u8, hello: *ClientHello) Error!void {
    var cursor = Cursor.init(wire);
    var seen_types = std.StaticBitSet(64).initEmpty();
    var count: u16 = 0;
    while (cursor.remaining() > 0) : (count += 1) {
        if (count >= extensions_count_max) return error.ExtensionOverflow;
        assert(count < extensions_count_max);
        // §4.2: pre_shared_key, when offered, is the last extension.
        if (hello.pre_shared_key_wire != null) return error.PskNotLast;
        const extension_type = try cursor.takeU16();
        const data_bytes = try cursor.takeU16();
        const data = try cursor.takeSlice(data_bytes);
        if (trackedBit(extension_type)) |bit| {
            if (seen_types.isSet(bit)) return error.DuplicateExtension;
            seen_types.set(bit);
        }
        try applyExtension(extension_type, data, hello);
    }
    assert(cursor.remaining() == 0);
}

/// The extensions whose duplication we police, mapped to bitset slots.
/// Unknown types (GREASE among them) answer null and may repeat — a
/// duplicate we would ignore anyway is not this parser's fight.
fn trackedBit(extension_type: u16) ?u6 {
    return switch (extension_type) {
        extension_server_name => 0,
        extension_signature_algorithms => 1,
        extension_alpn => 2,
        extension_pre_shared_key => 3,
        extension_supported_versions => 4,
        extension_psk_key_exchange_modes => 5,
        extension_key_share => 6,
        else => null,
    };
}

fn applyExtension(extension_type: u16, data: []const u8, hello: *ClientHello) Error!void {
    switch (extension_type) {
        extension_server_name => hello.server_name = try parseServerName(data),
        extension_key_share => hello.key_share_x25519 = try parseKeyShare(data),
        extension_supported_versions => hello.supports_tls13 = try parseSupportedVersions(data),
        extension_signature_algorithms => {
            if (data.len < 4) return error.MalformedExtension;
            hello.signature_algorithms_wire = data;
        },
        extension_alpn => {
            if (data.len < 4) return error.MalformedExtension;
            hello.alpn_wire = data;
        },
        extension_psk_key_exchange_modes => {
            if (data.len < 2) return error.MalformedExtension;
            hello.psk_modes_wire = data;
        },
        extension_pre_shared_key => {
            if (data.len < 12) return error.MalformedExtension;
            hello.pre_shared_key_wire = data;
        },
        else => {}, // Unknown: skipped whole, contents never inspected.
    }
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

/// §4.2.8: walk the KeyShareClientHello for an x25519 entry. A duplicate
/// group is a MUST NOT the client broke; unknown groups pass by.
fn parseKeyShare(data: []const u8) Error!?*const [32]u8 {
    var cursor = Cursor.init(data);
    const list_bytes = try cursor.takeU16();
    if (list_bytes != cursor.remaining()) return error.MalformedExtension;
    var x25519_share: ?*const [32]u8 = null;
    var entries: u16 = 0;
    while (cursor.remaining() > 0) : (entries += 1) {
        if (entries >= key_share_entries_max) return error.ExtensionOverflow;
        assert(entries < key_share_entries_max);
        const group = try cursor.takeU16();
        const share_bytes = try cursor.takeU16();
        const share = try cursor.takeSlice(share_bytes);
        if (group == group_x25519) {
            if (x25519_share != null) return error.MalformedExtension;
            if (share.len != 32) return error.MalformedExtension;
            x25519_share = share[0..32];
        }
    }
    assert(cursor.remaining() == 0);
    return x25519_share;
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
    try std.testing.expectEqualSlices(u8, &vectors.client_x25519_public, hello.key_share_x25519.?);
    // The trace offers 0x1301, 0x1303, 0x1302 in that order.
    try std.testing.expect(hello.offersSuite(.aes_128_gcm_sha256));
    try std.testing.expect(hello.offersSuite(.aes_256_gcm_sha384));
    try std.testing.expect(hello.offersSuite(.chacha20_poly1305_sha256));
    try std.testing.expectEqual(@as(usize, 6), hello.cipher_suites_wire.len);
    try std.testing.expect(hello.signature_algorithms_wire != null);
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
