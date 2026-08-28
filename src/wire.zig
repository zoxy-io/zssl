//! Bounded readers and writers for TLS wire structures.
//!
//! `Cursor` reads attacker bytes: every take is length-checked and answers
//! `error.Truncated`, never an assertion — asserting on untrusted input is
//! the wrong tool. `Builder` writes our own bytes: every put *is* asserted,
//! because running out of room in a buffer we sized is our bug, not the
//! peer's.

const std = @import("std");
const assert = std.debug.assert;

pub const Error = error{Truncated};

pub const DuplicateError = error{DuplicateExtension};

/// §4.2: "There MUST NOT be more than one extension of the same type in
/// a given extension block." Applied to the whole block before any of it
/// is acted on.
///
/// A pre-pass rather than a check folded into the caller's loop, and the
/// difference is observable rather than stylistic. A loop that refuses
/// the first extension it does not recognise never reaches the second
/// copy, so a peer sending one bogus type twice draws
/// unsupported_extension where §4.2 wants decode_error — which is
/// exactly what BoGo's `DuplicateExtensionClient-TLS-TLS13` measured
/// here. BoringSSL reaches the same conclusion with its own pre-pass,
/// `checkDuplicateExtensions`.
///
/// The rule has no carve-out for types the reader does not recognise,
/// and reading one in was the other half of the same finding: a
/// duplicate we would have ignored anyway is still a duplicate, because
/// §4.2 is about the block being well formed rather than about what its
/// contents mean.
///
/// `capacity` bounds the scan. A block with more entries than that is
/// left alone here and refused by the caller's own loop, which every
/// caller bounds with an overflow error of its own — so an over-long
/// block is still refused, just not by this function.
pub fn refuseDuplicateExtensions(comptime capacity: u16, block: []const u8) (Error || DuplicateError)!void {
    var cursor = Cursor.init(block);
    var seen: [capacity]u16 = undefined;
    var count: u16 = 0;
    while (cursor.remaining() > 0) {
        if (count == capacity) return;
        assert(count < capacity);
        const extension_type = try cursor.takeU16();
        _ = try cursor.takeSlice(try cursor.takeU16());
        for (seen[0..count]) |earlier| {
            if (earlier == extension_type) return error.DuplicateExtension;
        }
        seen[count] = extension_type;
        count += 1;
    }
    assert(cursor.remaining() == 0);
}

test "a repeated extension type is refused, whether or not it is known" {
    // key_share, then supported_versions: an ordinary pair.
    try refuseDuplicateExtensions(8, &.{ 0, 51, 0, 0, 0, 43, 0, 0 });
    // The same known type twice.
    try std.testing.expectError(
        error.DuplicateExtension,
        refuseDuplicateExtensions(8, &.{ 0, 51, 0, 0, 0, 51, 0, 0 }),
    );
    // A type no parser here knows, twice — 0xffff is what BoGo sends,
    // and the whole point is that not recognising it changes nothing.
    try std.testing.expectError(
        error.DuplicateExtension,
        refuseDuplicateExtensions(8, &.{ 0xff, 0xff, 0, 0, 0xff, 0xff, 0, 0 }),
    );
    // Separated by an unrelated extension, which is how BoGo places the
    // pair: first and last rather than adjacent.
    try std.testing.expectError(
        error.DuplicateExtension,
        refuseDuplicateExtensions(8, &.{ 0xff, 0xff, 0, 0, 0, 43, 0, 0, 0xff, 0xff, 0, 0 }),
    );
    // Truncated framing is the cursor's answer, not a duplicate verdict.
    try std.testing.expectError(error.Truncated, refuseDuplicateExtensions(8, &.{ 0, 51, 0 }));
}

pub const Cursor = struct {
    bytes: []const u8,
    index: usize,

    pub fn init(bytes: []const u8) Cursor {
        return .{ .bytes = bytes, .index = 0 };
    }

    pub fn remaining(self: *const Cursor) usize {
        assert(self.index <= self.bytes.len);
        return self.bytes.len - self.index;
    }

    /// Everything not yet taken, without taking it. For a caller that
    /// must look over a whole block before acting on any of it.
    pub fn rest(self: *const Cursor) []const u8 {
        assert(self.index <= self.bytes.len);
        return self.bytes[self.index..];
    }

    pub fn takeByte(self: *Cursor) Error!u8 {
        if (self.remaining() < 1) return error.Truncated;
        const byte = self.bytes[self.index];
        self.index += 1;
        return byte;
    }

    pub fn takeU16(self: *Cursor) Error!u16 {
        if (self.remaining() < 2) return error.Truncated;
        const value = std.mem.readInt(u16, self.bytes[self.index..][0..2], .big);
        self.index += 2;
        return value;
    }

    pub fn takeU32(self: *Cursor) Error!u32 {
        if (self.remaining() < 4) return error.Truncated;
        const value = std.mem.readInt(u32, self.bytes[self.index..][0..4], .big);
        self.index += 4;
        return value;
    }

    pub fn takeU24(self: *Cursor) Error!u24 {
        if (self.remaining() < 3) return error.Truncated;
        const value = std.mem.readInt(u24, self.bytes[self.index..][0..3], .big);
        self.index += 3;
        return value;
    }

    pub fn takeSlice(self: *Cursor, count: usize) Error![]const u8 {
        if (self.remaining() < count) return error.Truncated;
        const slice = self.bytes[self.index..][0..count];
        self.index += count;
        return slice;
    }
};

pub const Builder = struct {
    bytes: []u8,
    index: usize,

    pub fn init(bytes: []u8) Builder {
        assert(bytes.len >= 1);
        return .{ .bytes = bytes, .index = 0 };
    }

    pub fn written(self: *const Builder) []const u8 {
        assert(self.index <= self.bytes.len);
        return self.bytes[0..self.index];
    }

    pub fn putByte(self: *Builder, value: u8) void {
        assert(self.index + 1 <= self.bytes.len);
        self.bytes[self.index] = value;
        self.index += 1;
    }

    pub fn putU16(self: *Builder, value: u16) void {
        assert(self.index + 2 <= self.bytes.len);
        std.mem.writeInt(u16, self.bytes[self.index..][0..2], value, .big);
        self.index += 2;
    }

    pub fn putU32(self: *Builder, value: u32) void {
        assert(self.index + 4 <= self.bytes.len);
        std.mem.writeInt(u32, self.bytes[self.index..][0..4], value, .big);
        self.index += 4;
    }

    pub fn putU24(self: *Builder, value: u24) void {
        assert(self.index + 3 <= self.bytes.len);
        std.mem.writeInt(u24, self.bytes[self.index..][0..3], value, .big);
        self.index += 3;
    }

    pub fn putSlice(self: *Builder, bytes: []const u8) void {
        assert(self.index + bytes.len <= self.bytes.len);
        @memcpy(self.bytes[self.index..][0..bytes.len], bytes);
        self.index += bytes.len;
    }

    /// Reserve a length field to be filled once its contents are written.
    /// The mark pattern keeps every TLS `<length, body>` structure honest
    /// without a second pass: mark, write the body, patch.
    pub fn markU16(self: *Builder) usize {
        const mark = self.index;
        self.putU16(0);
        return mark;
    }

    pub fn patchU16(self: *Builder, mark: usize) void {
        assert(mark + 2 <= self.index);
        const length = self.index - mark - 2;
        assert(length <= std.math.maxInt(u16));
        std.mem.writeInt(u16, self.bytes[mark..][0..2], @intCast(length), .big);
    }

    pub fn markU24(self: *Builder) usize {
        const mark = self.index;
        self.putU24(0);
        return mark;
    }

    pub fn patchU24(self: *Builder, mark: usize) void {
        assert(mark + 3 <= self.index);
        const length = self.index - mark - 3;
        assert(length <= std.math.maxInt(u24));
        std.mem.writeInt(u24, self.bytes[mark..][0..3], @intCast(length), .big);
    }
};

test "builder mark/patch writes the length of what followed" {
    var storage: [16]u8 = undefined;
    var builder = Builder.init(&storage);
    const mark = builder.markU16();
    builder.putSlice("abc");
    builder.patchU16(mark);
    try std.testing.expectEqualSlices(u8, &.{ 0, 3, 'a', 'b', 'c' }, builder.written());
}

test "cursor truncation is an error, not a read" {
    var cursor = Cursor.init(&.{ 1, 2 });
    try std.testing.expectEqual(@as(u8, 1), try cursor.takeByte());
    try std.testing.expectError(error.Truncated, cursor.takeU16());
    try std.testing.expectEqual(@as(usize, 1), cursor.remaining());
}
