//! A bounds-only pre-pass over a peer's certificate DER.
//!
//! `std.crypto.Certificate.parse` computes where one element starts from
//! where the last one ended and reads there without checking the index is
//! inside the buffer. A certificate whose length fields point past the
//! end therefore *panics* rather than returning an error — seven bytes is
//! enough — and zssl hands that function bytes a peer chose. In
//! ReleaseSafe, which is what release builds ship, that is a remote
//! abort. BoGo's `GarbageCertificate-Client-TLS13` is the case.
//!
//! `catch` cannot help: the failure is a safety panic, not an error. So
//! the encoding is walked here first, and anything whose framing does not
//! nest exactly is refused before std sees it.
//!
//! What this checks is framing and nothing else: every tag-length-value
//! lies inside its parent, the outermost covers the buffer exactly, and
//! the certificate carries the elements std will walk before it reaches
//! anything it validates itself. It is not a DER validator and does not
//! know what a certificate means — `std.crypto.Certificate` still decides
//! that, and it is still allowed to reject what this admits.

const std = @import("std");
const assert = std.debug.assert;

pub const Error = error{MalformedDer};

/// Nesting depth. A certificate's deepest legitimate structure is the
/// extension list, around eight levels; sixteen is slack without being
/// an invitation.
const depth_max: u8 = 16;

/// Elements in one certificate. Real ones carry a few hundred; past this
/// is not a certificate but a shape built to make a walker work.
const elements_max: u32 = 4096;

/// §4.4.2 hands us `cert_data` and nothing more, so every bound here is
/// the buffer's own.
///
/// Returns `error.MalformedDer` for anything std could walk off the end
/// of. A `void` return means the framing nests; it does not mean the
/// bytes are a certificate.
pub fn validate(bytes: []const u8) Error!void {
    if (bytes.len < 2) return error.MalformedDer;

    // Container ends, innermost last. The outermost bound is the buffer,
    // which makes the loop below uniform: everything is inside something.
    var ends: [depth_max]usize = undefined;
    var depth: u8 = 1;
    ends[0] = bytes.len;

    var position: usize = 0;
    var elements: u32 = 0;
    var top_level_seen = false;

    while (depth >= 1) {
        assert(depth <= depth_max);
        const container_end = ends[depth - 1];
        assert(container_end <= bytes.len);
        if (position == container_end) {
            depth -= 1;
            continue;
        }
        // A container that ends before its contents do was mis-sized by
        // the peer, and the check below would otherwise read past it.
        if (position > container_end) return error.MalformedDer;

        elements += 1;
        if (elements == elements_max) return error.MalformedDer;
        assert(elements < elements_max);

        const header = try parseHeader(bytes, position, container_end);
        if (depth == 1) {
            // Exactly one element at the top, covering everything: a
            // certificate is a single SEQUENCE, and trailing bytes after
            // it are what `Certificate.parse` would read as a second one.
            if (top_level_seen) return error.MalformedDer;
            if (header.content_end != bytes.len) return error.MalformedDer;
            if (!header.constructed) return error.MalformedDer;
            top_level_seen = true;
        }
        // Content must *begin* inside the buffer, not merely end inside
        // it. `Certificate.parseBitString` reads `buffer[slice.start]` —
        // the unused-bits byte — with no length check of its own, so a
        // zero-length BIT STRING sitting at the very end of the buffer
        // has `slice.start == buffer.len` and reads one past it. DER
        // permits that encoding, which is why refusing it belongs here
        // rather than being assumed away: the last element of a
        // certificate is its signatureValue, and an empty one is not
        // something a real certificate carries.
        //
        // Applied to every element rather than to BIT STRINGs alone. A
        // zero-length element anywhere but the tail keeps
        // `content_start < bytes.len`, so this only ever refuses the
        // shape that reads off the end, and it does not depend on
        // knowing which tags std dereferences without checking.
        if (header.content_start == bytes.len) return error.MalformedDer;
        assert(header.content_start < bytes.len);
        position = header.content_start;
        if (!header.constructed) {
            position = header.content_end;
            continue;
        }
        if (depth == depth_max) return error.MalformedDer;
        assert(depth < depth_max);
        ends[depth] = header.content_end;
        depth += 1;
    }
    if (!top_level_seen) return error.MalformedDer;

    // std walks tbsCertificate's first elements by end-of-previous
    // without bounds-checking, so the shape has to be deep enough that
    // those walks land on elements rather than past the last one. A
    // certificate has three top-level children and at least six inside
    // its tbsCertificate; anything shorter is refused here rather than
    // stepped off the end of there.
    try requireChildren(bytes, 3, 6);
}

const Header = struct {
    content_start: usize,
    content_end: usize,
    constructed: bool,
};

/// One tag-length-value header, bounded by its container.
fn parseHeader(bytes: []const u8, at: usize, container_end: usize) Error!Header {
    assert(at < container_end);
    assert(container_end <= bytes.len);
    // Identifier, then at least one length byte.
    if (container_end - at < 2) return error.MalformedDer;
    const identifier = bytes[at];
    // High-tag-number form: the tag continues while the high bit is set.
    // Refused rather than walked — nothing in a certificate uses it, and
    // admitting it would mean another unbounded scan.
    if (identifier & 0x1f == 0x1f) return error.MalformedDer;
    const constructed = identifier & 0x20 != 0;

    var cursor = at + 1;
    const first = bytes[cursor];
    cursor += 1;
    var length: usize = first & 0x7f;
    if (first & 0x80 != 0) {
        // Indefinite length is BER, not DER, and its terminator is
        // exactly the kind of unbounded scan this pass exists to refuse.
        if (length == 0) return error.MalformedDer;
        // std refuses more than four length bytes (`len_size > @sizeOf(u32)`)
        // before reading any of them. Matching that exactly keeps this
        // pass a model of the parser it guards rather than a looser
        // relative of it.
        if (length > @sizeOf(u32)) return error.MalformedDer;
        const length_bytes = length;
        if (container_end - cursor < length_bytes) return error.MalformedDer;
        length = 0;
        var index: usize = 0;
        while (index < length_bytes) : (index += 1) {
            length = (length << 8) | bytes[cursor + index];
        }
        cursor += length_bytes;
    }
    // The content must fit its container, which transitively means it
    // fits the buffer: the outermost container is the buffer itself.
    if (container_end - cursor < length) return error.MalformedDer;
    const content_end = cursor + length;
    assert(content_end <= container_end);
    assert(content_end <= bytes.len);
    return .{ .content_start = cursor, .content_end = content_end, .constructed = constructed };
}

/// Count the top-level element's children, and the first child's, without
/// descending further. Called only after `validate`'s walk has proved
/// every header in the buffer is in bounds, so the arithmetic here cannot
/// leave it.
fn requireChildren(bytes: []const u8, outer_min: u8, inner_min: u8) Error!void {
    assert(bytes.len >= 2);
    assert(outer_min >= 1);
    assert(inner_min >= 1);
    const outer = try parseHeader(bytes, 0, bytes.len);
    assert(outer.content_end <= bytes.len);
    var children: u8 = 0;
    var position = outer.content_start;
    var first_child: ?Header = null;
    while (position < outer.content_end) {
        const child = try parseHeader(bytes, position, outer.content_end);
        if (first_child == null) first_child = child;
        position = child.content_end;
        children +|= 1;
    }
    if (children < outer_min) return error.MalformedDer;

    const tbs = first_child orelse return error.MalformedDer;
    if (!tbs.constructed) return error.MalformedDer;
    var inner: u8 = 0;
    position = tbs.content_start;
    while (position < tbs.content_end) {
        const child = try parseHeader(bytes, position, tbs.content_end);
        position = child.content_end;
        inner +|= 1;
    }
    if (inner < inner_min) return error.MalformedDer;
}

test "a zero-length BIT STRING at the tail is refused" {
    // Found by review, and by a proof of concept rather than by reading:
    // this buffer passed an earlier version of `validate` and then
    // panicked std at `parseBitString`, which reads the unused-bits byte
    // of `signatureValue` without checking the slice is non-empty. 78
    // bytes, well-formed everywhere except that its last element is an
    // empty BIT STRING ending exactly at the buffer's end.
    const poc = [_]u8{
        0x30, 0x4c, 0x30, 0x3b, 0x02, 0x01, 0x01, 0x30, 0x00, 0x30, 0x00, 0x30,
        0x1e, 0x17, 0x0d, 0x37, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30,
        0x30, 0x30, 0x30, 0x5a, 0x17, 0x0d, 0x37, 0x30, 0x30, 0x31, 0x30, 0x31,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x30, 0x00, 0x30, 0x10, 0x30,
        0x0b, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
        0x03, 0x01, 0x00, 0x30, 0x0b, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
        0x0d, 0x01, 0x01, 0x0b, 0x03, 0x00,
    };
    try std.testing.expectError(error.MalformedDer, validate(&poc));
}

test "the seven bytes that panic std are refused" {
    // BoGo's `GarbageCertificate-Client-TLS13`, reduced: a SEQUENCE whose
    // length lies, so `Certificate.parse` walks to index 71 of a 7-byte
    // buffer. Reproduced standalone before this file existed.
    const garbage = [_]u8{ 0x30, 0x05, 0x02, 0x03, 0x41, 0x41, 0x41 };
    try std.testing.expectError(error.MalformedDer, validate(&garbage));
}

test "framing that does not nest is refused, in each way it can fail" {
    const cases = [_][]const u8{
        &.{}, // nothing
        &.{0x30}, // an identifier with no length
        &.{ 0x30, 0x7f }, // a length past the end
        &.{ 0x30, 0x02, 0x02, 0x7f }, // an inner length past its parent
        &.{ 0x30, 0x00, 0x30, 0x00 }, // two top-level elements
        &.{ 0x30, 0x01, 0x00, 0x00 }, // trailing byte after the top level
        &.{ 0x30, 0x80, 0x00, 0x00 }, // indefinite length: BER, not DER
        &.{ 0x3f, 0x02, 0x00, 0x00 }, // high-tag-number form
        &.{ 0x02, 0x02, 0x00, 0x00 }, // top level not constructed
    };
    for (cases, 0..) |bytes, index| {
        validate(bytes) catch continue;
        std.debug.print("case {d} was admitted and should not be\n", .{index});
        return error.TestUnexpectedResult;
    }
}

test "a real certificate passes, and std agrees it is one" {
    // The fixture the rest of the suite uses. This pass must not become
    // strict enough to refuse a certificate that works.
    const pem = @embedFile("testdata/cert.pem");
    const begin = "-----BEGIN CERTIFICATE-----";
    const end = "-----END CERTIFICATE-----";
    const body_start = std.mem.indexOf(u8, pem, begin).? + begin.len;
    const body_end = std.mem.indexOf(u8, pem, end).?;
    var base64: [8192]u8 = undefined;
    var used: usize = 0;
    for (pem[body_start..body_end]) |byte| {
        if (byte == '\n' or byte == '\r') continue;
        base64[used] = byte;
        used += 1;
    }
    var der: [8192]u8 = undefined;
    const decoder = std.base64.standard.Decoder;
    const der_bytes = try decoder.calcSizeForSlice(base64[0..used]);
    try decoder.decode(der[0..der_bytes], base64[0..used]);

    try validate(der[0..der_bytes]);
    const certificate: std.crypto.Certificate = .{ .buffer = der[0..der_bytes], .index = 0 };
    _ = try certificate.parse();
}
