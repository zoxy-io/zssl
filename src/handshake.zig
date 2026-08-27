//! Handshake message framing (RFC 8446 §4): the 4-byte header, and the
//! `Assembler` that turns record plaintext — where messages coalesce and
//! fragment freely (§5.1) — back into whole messages. The buffer is
//! caller-owned and its size is the caller's policy: a ClientHello budget
//! for a server, a certificate-chain budget for a client.

const std = @import("std");
const assert = std.debug.assert;

const wire = @import("wire.zig");

pub const header_bytes: u8 = 4;

pub const MessageType = enum(u8) {
    client_hello = 1,
    server_hello = 2,
    new_session_ticket = 4,
    end_of_early_data = 5,
    encrypted_extensions = 8,
    certificate = 11,
    certificate_verify = 15,
    finished = 20,
    key_update = 24,
    message_hash = 254,

    pub fn fromWire(byte: u8) ?MessageType {
        return std.enums.fromInt(MessageType, byte);
    }
};

/// Begin a handshake message: type byte plus a u24 length to patch.
pub fn beginMessage(builder: *wire.Builder, message_type: MessageType) usize {
    builder.putByte(@intFromEnum(message_type));
    return builder.markU24();
}

pub fn endMessage(builder: *wire.Builder, mark: usize) void {
    builder.patchU24(mark);
}

pub const Message = struct {
    type_wire: u8,
    /// The complete message, header included — what the transcript eats.
    bytes: []const u8,

    pub fn messageType(self: *const Message) ?MessageType {
        assert(self.bytes.len >= header_bytes);
        return MessageType.fromWire(self.type_wire);
    }

    pub fn body(self: *const Message) []const u8 {
        assert(self.bytes.len >= header_bytes);
        return self.bytes[header_bytes..];
    }
};

pub const Assembler = struct {
    buffer: []u8,
    /// Consumed prefix; compacted away on the next push that needs room.
    start: usize,
    used: usize,

    pub const Error = error{ BufferOverflow, MalformedMessage };

    pub fn init(buffer: []u8) Assembler {
        assert(buffer.len >= header_bytes);
        return .{ .buffer = buffer, .start = 0, .used = 0 };
    }

    pub fn empty(self: *const Assembler) bool {
        assert(self.start <= self.used);
        return self.start == self.used;
    }

    /// Append one record's worth of handshake plaintext. Slices returned
    /// by `next` before this call are invalidated by the compaction here.
    pub fn push(self: *Assembler, plaintext: []const u8) Error!void {
        assert(plaintext.len >= 1);
        if (self.buffer.len - self.used < plaintext.len) {
            std.mem.copyForwards(u8, self.buffer[0 .. self.used - self.start], self.buffer[self.start..self.used]);
            self.used -= self.start;
            self.start = 0;
        }
        if (self.buffer.len - self.used < plaintext.len) return error.BufferOverflow;
        @memcpy(self.buffer[self.used..][0..plaintext.len], plaintext);
        self.used += plaintext.len;
        assert(self.used <= self.buffer.len);
    }

    /// The next complete message, or null while one is still arriving.
    /// The slice lives until the next `push`.
    pub fn next(self: *Assembler) Error!?Message {
        assert(self.start <= self.used);
        const available = self.used - self.start;
        if (available < header_bytes) return null;
        const head = self.buffer[self.start..self.used];
        const declared = std.mem.readInt(u24, head[1..4], .big);
        const total = @as(usize, declared) + header_bytes;
        // A message its own buffer can never hold will never complete;
        // report it now rather than stalling forever at "still arriving".
        if (total > self.buffer.len) return error.BufferOverflow;
        if (available < total) return null;
        self.start += total;
        assert(self.start <= self.used);
        return .{ .type_wire = head[0], .bytes = head[0..total] };
    }
};

test "assembler reunites a message split across pushes and splits a coalesced pair" {
    var storage: [64]u8 = undefined;
    var assembler = Assembler.init(&storage);

    // One message in three fragments: header split mid-length.
    try assembler.push(&.{ 20, 0 });
    try std.testing.expectEqual(@as(?Message, null), try assembler.next());
    try assembler.push(&.{ 0, 3, 0xaa });
    try std.testing.expectEqual(@as(?Message, null), try assembler.next());
    try assembler.push(&.{ 0xbb, 0xcc });
    const first = (try assembler.next()).?;
    try std.testing.expectEqual(MessageType.finished, first.messageType().?);
    try std.testing.expectEqualSlices(u8, &.{ 0xaa, 0xbb, 0xcc }, first.body());
    try std.testing.expect(assembler.empty());

    // Two messages in one push come out as two.
    try assembler.push(&.{ 8, 0, 0, 1, 0x11, 20, 0, 0, 1, 0x22 });
    const second = (try assembler.next()).?;
    try std.testing.expectEqual(MessageType.encrypted_extensions, second.messageType().?);
    const third = (try assembler.next()).?;
    try std.testing.expectEqual(MessageType.finished, third.messageType().?);
    try std.testing.expectEqual(@as(?Message, null), try assembler.next());
}

test "a message larger than the buffer is an error, not a stall" {
    var storage: [16]u8 = undefined;
    var assembler = Assembler.init(&storage);
    // Declared length 64 in a 16-byte buffer: can never complete.
    try assembler.push(&.{ 11, 0, 0, 64 });
    try std.testing.expectError(error.BufferOverflow, assembler.next());
}
