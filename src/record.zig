//! TLS record framing (RFC 8446 §5.1-§5.2).
//!
//! Framing only — protection lives in `protect.zig`. The length caps are
//! enforced *here*, at header parse, because admitting an overlong record
//! and compensating later is exactly the gap the ztls audit queue records
//! (its record layer admits up to 2^14+256 of plaintext where §5.2 caps
//! honest ciphertext expansion; the caller had to compensate). In zssl a
//! record the spec forbids never gets past the header.

const std = @import("std");
const assert = std.debug.assert;

pub const header_bytes: u16 = 5;

/// §5.1: a plaintext record fragment carries at most 2^14 bytes.
pub const plaintext_bytes_max: u16 = 1 << 14;

/// §5.2: AEAD expansion is capped at 255 bytes past the plaintext limit,
/// tag included. Anything longer draws record_overflow, not a buffer.
pub const ciphertext_bytes_max: u16 = plaintext_bytes_max + 256;

/// §5.4: the padded inner plaintext — content plus the content-type byte —
/// of a protected record is capped one past the plaintext limit.
pub const inner_plaintext_bytes_max: u16 = plaintext_bytes_max + 1;

pub const wire_record_bytes_max: u32 = @as(u32, header_bytes) + ciphertext_bytes_max;

comptime {
    assert(plaintext_bytes_max == 16384);
    assert(ciphertext_bytes_max == 16640);
    assert(wire_record_bytes_max == 16645);
}

pub const ContentType = enum(u8) {
    change_cipher_spec = 20,
    alert = 21,
    handshake = 22,
    application_data = 23,

    pub fn fromWire(wire: u8) ?ContentType {
        return switch (wire) {
            20 => .change_cipher_spec,
            21 => .alert,
            22 => .handshake,
            23 => .application_data,
            else => null,
        };
    }
};

pub const Header = struct {
    content_type: ContentType,
    /// Payload bytes following the 5-byte header.
    length: u16,
};

pub const HeaderError = error{
    UnknownContentType,
    /// The legacy version's major byte is not 0x03, so this is not a TLS
    /// record at all — a framing check, not a version negotiation.
    NotATlsRecord,
    RecordOverflow,
    EmptyFragment,
};

/// Parse and police one record header. The caps are per content type: a
/// protected record (outer type application_data) may run to the §5.2
/// ciphertext bound; every plaintext type stops at §5.1's. Zero-length
/// handshake and alert fragments are forbidden by §5.1.
pub fn parseHeader(bytes: *const [header_bytes]u8) HeaderError!Header {
    const content_type = ContentType.fromWire(bytes[0]) orelse
        return error.UnknownContentType;
    // legacy_record_version, bytes[1..3]. §5.1 says it "MUST be ignored
    // for all purposes", and zssl used to admit only 0x0303 and 0x0301 —
    // stricter than the spec, about a field carrying no information, and
    // enough to refuse real clients whose initial ClientHello says
    // 0x0300 or 0x0302. The minor byte is now ignored outright.
    //
    // The major byte still has to be 0x03, which is not a version check
    // but a framing one: 0xffff is not a TLS record, and a peer that
    // sends one has not started a handshake we can continue. We still
    // only ever *write* 0x0303.
    if (bytes[1] != 0x03) return error.NotATlsRecord;
    const length = std.mem.readInt(u16, bytes[3..5], .big);
    const cap: u16 = switch (content_type) {
        .application_data => ciphertext_bytes_max,
        .change_cipher_spec, .alert, .handshake => plaintext_bytes_max,
    };
    assert(cap == plaintext_bytes_max or cap == ciphertext_bytes_max);
    if (length > cap) return error.RecordOverflow;
    if (length == 0) {
        // §5.1: only application_data may be empty on the wire.
        if (content_type != .application_data) return error.EmptyFragment;
    }
    return .{ .content_type = content_type, .length = length };
}

/// Write one record header. Always 0x0303: zssl never emits the 0x0301
/// compatibility version — that is a client first-flight concession, and
/// reading it is enough.
pub fn writeHeader(header: Header, out: *[header_bytes]u8) void {
    assert(header.length >= 1 or header.content_type == .application_data);
    const cap: u16 = if (header.content_type == .application_data)
        ciphertext_bytes_max
    else
        plaintext_bytes_max;
    assert(header.length <= cap);
    out[0] = @intFromEnum(header.content_type);
    std.mem.writeInt(u16, out[1..3], 0x0303, .big);
    std.mem.writeInt(u16, out[3..5], header.length, .big);
}

test "parseHeader reads RFC 8448's ClientHello record" {
    const vectors = @import("rfc8448_vectors.zig");
    // The trace's first record: type handshake, legacy version 0x0301,
    // length 0xc4 — the 196-byte ClientHello.
    const header_wire: [header_bytes]u8 = .{ 0x16, 0x03, 0x01, 0x00, 0xc4 };
    const header = try parseHeader(&header_wire);
    try std.testing.expectEqual(ContentType.handshake, header.content_type);
    try std.testing.expectEqual(@as(u16, vectors.client_hello.len), header.length);
}

test "parseHeader rejects what the spec forbids" {
    // Overlong protected record: one past the §5.2 cap.
    try std.testing.expectError(error.RecordOverflow, parseHeader(&.{ 0x17, 0x03, 0x03, 0x41, 0x01 }));
    // A handshake record may not use the ciphertext allowance: §5.1 caps it.
    try std.testing.expectError(error.RecordOverflow, parseHeader(&.{ 0x16, 0x03, 0x03, 0x41, 0x00 }));
    // At the cap is legal for a protected record.
    _ = try parseHeader(&.{ 0x17, 0x03, 0x03, 0x41, 0x00 });
    // Unknown content type, SSLv2-era version byte, empty alert.
    try std.testing.expectError(error.UnknownContentType, parseHeader(&.{ 0x18, 0x03, 0x03, 0x00, 0x10 }));
    // §5.1's ignored field stays ignored across the 0x03xx range: a
    // client whose initial ClientHello says 0x0301 or 0x03ff has told us
    // nothing, and refusing it would break a handshake the spec expects
    // to succeed.
    for ([_]u8{ 0x00, 0x01, 0x03, 0x04, 0xff }) |minor| {
        try std.testing.expectEqual(
            @as(u16, 0x10),
            (try parseHeader(&.{ 0x16, 0x03, minor, 0x00, 0x10 })).length,
        );
    }
    // A major byte that is not 0x03 is not a TLS record; that is framing,
    // not version negotiation, and it is the one part still enforced.
    try std.testing.expectError(error.NotATlsRecord, parseHeader(&.{ 0x16, 0x02, 0x00, 0x00, 0x10 }));
    try std.testing.expectError(error.NotATlsRecord, parseHeader(&.{ 0x16, 0xff, 0xff, 0x00, 0x10 }));
    try std.testing.expectError(error.EmptyFragment, parseHeader(&.{ 0x15, 0x03, 0x03, 0x00, 0x00 }));
}

test "writeHeader round-trips through parseHeader" {
    var wire: [header_bytes]u8 = undefined;
    writeHeader(.{ .content_type = .application_data, .length = 1234 }, &wire);
    const parsed = try parseHeader(&wire);
    try std.testing.expectEqual(ContentType.application_data, parsed.content_type);
    try std.testing.expectEqual(@as(u16, 1234), parsed.length);
}
