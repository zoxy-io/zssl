//! Byte stream → whole records. A peer writes arbitrary chunks; the
//! machine consumes complete records. The header is validated *here*, as
//! bytes arrive — a record the caps forbid is rejected before its body is
//! even buffered, which keeps `record.zig`'s promise at the outermost
//! edge.

const std = @import("std");
const assert = std.debug.assert;

const record = @import("record.zig");

pub const RecordBuffer = struct {
    buffer: []u8,
    start: usize,
    used: usize,

    pub const Error = record.HeaderError || error{BufferOverflow};

    pub fn init(buffer: []u8) RecordBuffer {
        assert(buffer.len >= record.wire_record_bytes_max);
        return .{ .buffer = buffer, .start = 0, .used = 0 };
    }

    pub fn empty(self: *const RecordBuffer) bool {
        assert(self.start <= self.used);
        return self.start == self.used;
    }

    /// Append raw stream bytes. Slices from `next` are invalidated by the
    /// compaction this may perform.
    pub fn push(self: *RecordBuffer, bytes: []const u8) Error!void {
        assert(bytes.len >= 1);
        if (self.buffer.len - self.used < bytes.len) {
            std.mem.copyForwards(u8, self.buffer[0 .. self.used - self.start], self.buffer[self.start..self.used]);
            self.used -= self.start;
            self.start = 0;
        }
        if (self.buffer.len - self.used < bytes.len) return error.BufferOverflow;
        @memcpy(self.buffer[self.used..][0..bytes.len], bytes);
        self.used += bytes.len;
        assert(self.used <= self.buffer.len);
    }

    /// The next complete record (header included), or null while one is
    /// still arriving. Valid until the next `push`.
    pub fn next(self: *RecordBuffer) Error!?[]const u8 {
        assert(self.start <= self.used);
        const available = self.used - self.start;
        if (available < record.header_bytes) return null;
        const head = self.buffer[self.start..self.used];
        // Validation happens the moment the header is whole: caps, types,
        // versions — before the body finishes arriving.
        const header = try record.parseHeader(head[0..record.header_bytes]);
        const total = @as(usize, record.header_bytes) + header.length;
        assert(total <= record.wire_record_bytes_max);
        if (available < total) return null;
        self.start += total;
        assert(self.start <= self.used);
        return head[0..total];
    }
};

test "reassembles a record from dribbled bytes and rejects a forbidden header early" {
    var storage: [record.wire_record_bytes_max]u8 = undefined;
    var records = RecordBuffer.init(&storage);

    // A 3-byte handshake record, delivered one byte at a time.
    const whole = [_]u8{ 0x16, 0x03, 0x03, 0x00, 0x03, 0xaa, 0xbb, 0xcc };
    for (whole, 0..) |byte, index| {
        try records.push(&.{byte});
        const answer = try records.next();
        if (index < whole.len - 1) {
            try std.testing.expectEqual(@as(?[]const u8, null), answer);
        } else {
            try std.testing.expectEqualSlices(u8, &whole, answer.?);
        }
    }
    try std.testing.expect(records.empty());

    // An overlong protected record dies on its header, body unbuffered.
    try records.push(&.{ 0x17, 0x03, 0x03, 0x41, 0x01 });
    try std.testing.expectError(error.RecordOverflow, records.next());
}
