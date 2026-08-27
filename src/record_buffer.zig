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

    /// Where the next read may land its bytes, so a caller can read from
    /// a socket straight into this buffer instead of through one of its
    /// own — the difference between one copy per record and two.
    ///
    /// Reclaims whatever has already been consumed, so a fully drained
    /// buffer offers all of itself and a partly drained one offers
    /// everything past the fragment still arriving. That makes the
    /// region never empty — the buffer holds a whole record with room to
    /// spare (`init` asserts it) — which is what lets a caller treat
    /// this as "somewhere to read into" rather than a maybe.
    ///
    /// Invalidates slices from `next` for the same reason `push` does:
    /// the reclaim moves bytes. Drain before asking for more room.
    /// Pair with `advance`.
    pub fn writable(self: *RecordBuffer) []u8 {
        assert(self.start <= self.used);
        if (self.start >= 1) self.compact();
        const room = self.buffer[self.used..];
        assert(room.len >= 1);
        return room;
    }

    /// Report how many bytes of `writable` a read actually filled.
    pub fn advance(self: *RecordBuffer, bytes: usize) void {
        assert(bytes >= 1);
        assert(self.used + bytes <= self.buffer.len);
        self.used += bytes;
    }

    /// Slide the unconsumed remainder to the front, reclaiming whatever
    /// `next` has already handed out. Invalidates slices from `next`.
    fn compact(self: *RecordBuffer) void {
        assert(self.start <= self.used);
        std.mem.copyForwards(u8, self.buffer[0 .. self.used - self.start], self.buffer[self.start..self.used]);
        self.used -= self.start;
        self.start = 0;
    }

    /// Append raw stream bytes. Slices from `next` are invalidated by the
    /// compaction this may perform.
    pub fn push(self: *RecordBuffer, bytes: []const u8) Error!void {
        assert(bytes.len >= 1);
        if (self.buffer.len - self.used < bytes.len) self.compact();
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

test "writable/advance is the copy-free read path" {
    var storage: [record.wire_record_bytes_max]u8 = undefined;
    var records = RecordBuffer.init(&storage);

    // Two records delivered as one read, straight into the buffer.
    const whole = [_]u8{ 0x16, 0x03, 0x03, 0x00, 0x02, 0xaa, 0xbb } ++
        [_]u8{ 0x16, 0x03, 0x03, 0x00, 0x01, 0xcc };
    const destination = records.writable();
    try std.testing.expect(destination.len >= whole.len);
    @memcpy(destination[0..whole.len], &whole);
    records.advance(whole.len);

    const first = (try records.next()).?;
    try std.testing.expectEqualSlices(u8, whole[0..7], first);
    const second = (try records.next()).?;
    try std.testing.expectEqualSlices(u8, whole[7..], second);
    try std.testing.expectEqual(@as(?[]const u8, null), try records.next());
    try std.testing.expect(records.empty());

    // After draining, the writable region is the whole buffer again —
    // the property that keeps a long-lived connection from starving.
    try std.testing.expectEqual(storage.len, records.writable().len);
}
