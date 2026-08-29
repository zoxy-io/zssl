//! Handshake message framing (RFC 8446 §4): the 4-byte header, and the
//! `Assembler` that turns record plaintext — where messages coalesce and
//! fragment freely (§5.1) — back into whole messages. The buffer is
//! caller-owned and its size is the caller's policy: a ClientHello budget
//! for a server, a certificate-chain budget for a client.

const std = @import("std");
const assert = std.debug.assert;

const cipher_suite = @import("cipher_suite.zig");
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

/// Can a message of this type declare this length at all? §4 fixes the
/// answer for two of them, and both are decidable from the four header
/// bytes — before a peer can make anyone hold the body it promised.
///
/// Only those two. Every other message is variable-length by grammar,
/// and its own parser is what bounds it; guessing a ceiling for a
/// ClientHello here would be a second policy competing with
/// `client_hello.zig`'s. An unknown type byte passes too — it is
/// refused as `unexpected_message` a layer up, and answering
/// decode_error for it here would be the wrong alert for the right
/// input.
fn declaredLengthPossible(type_wire: u8, declared: u24) bool {
    const message_type = MessageType.fromWire(type_wire) orelse return true;
    return switch (message_type) {
        // §4.6.3: `struct { KeyUpdateRequest request_update; }` — one
        // enum byte, and the grammar admits no other size.
        .key_update => declared == 1,
        // §4.4.4: verify_data is exactly the negotiated hash's length.
        // Which hash that is only the caller knows, so this is the
        // ceiling and not the value — enough to stop the buffering,
        // while `ServerHandshake` and `ClientHandshake` check the exact
        // length where the suite is in scope.
        .finished => declared <= cipher_suite.hash_bytes_max,
        else => true,
    };
}

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
        // Before capacity, because the two are different verdicts and
        // the order decides which one the peer hears. A length the
        // message *type* cannot have is a message that cannot exist —
        // §6.2's decode_error, "the length of the message was
        // incorrect" — where the capacity failure below says only that
        // this embedder's buffer is smaller than what arrived. Asking
        // in the other order let a Finished declaring 16 MiB be
        // reported as our own buffer being too small.
        if (!declaredLengthPossible(head[0], declared)) return error.MalformedMessage;
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
    // certificate, because the verdict here is about capacity and a
    // type whose length is fixed would be refused for the other reason
    // first — which is the whole point of the test below.
    try assembler.push(&.{ 11, 0, 0, 64 });
    try std.testing.expectError(error.BufferOverflow, assembler.next());
}

test "a length the message type cannot have is decode_error, not capacity" {
    // §4.6.3: a KeyUpdate is one byte. Zero and two are both refused,
    // and refused as malformed rather than as anything about the body,
    // because four header bytes already settle it.
    for ([_]u8{ 0, 2, 0xff }) |declared| {
        var storage: [64]u8 = undefined;
        var assembler = Assembler.init(&storage);
        try assembler.push(&.{ 24, 0, 0, declared });
        try std.testing.expectError(error.MalformedMessage, assembler.next());
    }

    // §4.4.4: verify_data is the negotiated hash's length, so 48 is the
    // ceiling across every suite here. One past it is malformed.
    {
        var storage: [64]u8 = undefined;
        var assembler = Assembler.init(&storage);
        try assembler.push(&.{ 20, 0, 0, 49 });
        try std.testing.expectError(error.MalformedMessage, assembler.next());
    }

    // And a Finished declaring far more than any buffer holds is the
    // same verdict, not a capacity one. This is the ordering that
    // matters: asked the other way round, a peer's impossible message
    // came back as *our* buffer being too small, which an embedder
    // reads as its own misconfiguration.
    {
        var storage: [64]u8 = undefined;
        var assembler = Assembler.init(&storage);
        try assembler.push(&.{ 20, 0xff, 0xff, 0xff });
        try std.testing.expectError(error.MalformedMessage, assembler.next());
    }

    // The lengths the grammar does admit still pass — 48 exactly, and a
    // one-byte KeyUpdate.
    {
        var storage: [64]u8 = undefined;
        var assembler = Assembler.init(&storage);
        try assembler.push(&.{ 20, 0, 0, 48 });
        try std.testing.expectEqual(@as(?Message, null), try assembler.next());
        try assembler.push(&([_]u8{0xab} ** 48));
        try std.testing.expectEqual(MessageType.finished, (try assembler.next()).?.messageType().?);
        try assembler.push(&.{ 24, 0, 0, 1, 1 });
        try std.testing.expectEqual(MessageType.key_update, (try assembler.next()).?.messageType().?);
    }

    // A type this parser does not know keeps the capacity answer: it is
    // refused as unexpected_message a layer up, and decode_error here
    // would be the wrong alert for the right input.
    {
        var storage: [16]u8 = undefined;
        var assembler = Assembler.init(&storage);
        try assembler.push(&.{ 0x63, 0, 0, 64 });
        try std.testing.expectError(error.BufferOverflow, assembler.next());
    }
}
