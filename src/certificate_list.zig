//! The peer's certificate chain (RFC 8446 §4.4.2), handed to the embedder
//! as an iterator over borrowed DER.
//!
//! zssl checks *possession* — that the peer holds the key its leaf names —
//! and stops there; chain building and RFC 9525 name matching are the
//! embedder's, deliberately (DESIGN.md §1). This is the seam that makes
//! that division workable rather than merely stated: the embedder gets
//! every entry the peer sent, leaf first, in the order §4.4.2 fixes.
//!
//! Nothing here copies. Entries view the handshake's reassembly buffer and
//! die at the next `handleRecord`, which is why `ChainVerifier` is a
//! callback rather than a value the embedder may keep: the decision is due
//! while the bytes are still alive.

const std = @import("std");
const assert = std.debug.assert;

const wire = @import("wire.zig");

/// The `certificate_list` field's bytes — every `CertificateEntry`, with
/// the enclosing u24 length already stripped.
pub const CertificateList = struct {
    bytes: []const u8,

    pub const Error = wire.Error || error{ MalformedEntry, UnsupportedExtension };

    pub fn init(bytes: []const u8) CertificateList {
        return .{ .bytes = bytes };
    }

    pub fn iterator(self: CertificateList) Iterator {
        return .{ .cursor = wire.Cursor.init(self.bytes) };
    }

    /// How many entries the list holds, or an error if its framing is
    /// malformed. Walks the list, so a caller that also iterates pays for
    /// the parse twice — it exists for `chain.len()`-shaped checks, not as
    /// a loop bound.
    pub fn count(self: CertificateList) Error!usize {
        var entries: usize = 0;
        var it = self.iterator();
        while (try it.next()) |_| entries += 1;
        return entries;
    }
};

pub const Iterator = struct {
    cursor: wire.Cursor,
    /// Which entry `next` will return. Only the first is the leaf, and
    /// only the leaf's extensions are ours to refuse.
    entry_index: usize = 0,

    /// The next entry's `cert_data`, or null at the end of the list.
    ///
    /// §4.4.2: a CertificateEntry's extensions must be ones the client
    /// asked for, and a client that receives any other "MUST abort with
    /// an unsupported_extension alert" (§4.2). zssl requests none —
    /// neither status_request nor SCT — so on the leaf the block must be
    /// empty and anything in it is unsolicited.
    ///
    /// Intermediates are exempt, which is not laxity but the rule: §4.4.2
    /// says an extension applying to the chain belongs on the first
    /// entry, so what rides an intermediate is decoration a client is
    /// meant to ignore rather than answer. BoringSSL draws the same line
    /// (`IgnoreExtensionsOnIntermediates-TLS13` against
    /// `SendUnknownExtensionOnCertificate-TLS13`), and refusing both
    /// would fail a legitimate chain.
    pub fn next(self: *Iterator) CertificateList.Error!?[]const u8 {
        if (self.cursor.remaining() == 0) return null;
        const cert_bytes = try self.cursor.takeU24();
        // `<1..2^24-1>`: an empty entry is malformed, and a zero-length
        // leaf would otherwise reach a parser as an empty slice.
        if (cert_bytes == 0) return error.MalformedEntry;
        const cert_data = try self.cursor.takeSlice(cert_bytes);
        const extensions_bytes = try self.cursor.takeU16();
        if (self.entry_index == 0 and extensions_bytes != 0) {
            return error.UnsupportedExtension;
        }
        _ = try self.cursor.takeSlice(extensions_bytes);
        self.entry_index += 1;
        assert(cert_data.len >= 1);
        return cert_data;
    }
};

/// What the embedder installs to have the chain shown to it. Mirrors
/// `ServerHandshake.PskLookup`: an opaque context and a function, so the
/// zero-allocation budget survives contact with embedder policy.
pub const ChainVerifier = struct {
    context: *anyopaque,
    /// Return false to abort the handshake with `error.BadCertificate`.
    /// The entries are borrowed and must not outlive the call.
    verify: *const fn (context: *anyopaque, chain: CertificateList) bool,
};

test "iterator walks entries and skips their extensions" {
    // Two entries: "AB" with no extensions, "CDE" with a 1-byte one.
    const list = CertificateList.init(&.{
        0, 0,    2, 'A', 'B', 0,   0,
        0, 0,    3, 'C', 'D', 'E', 0,
        1, 0xff,
    });
    var it = list.iterator();
    try std.testing.expectEqualSlices(u8, "AB", (try it.next()).?);
    try std.testing.expectEqualSlices(u8, "CDE", (try it.next()).?);
    try std.testing.expectEqual(@as(?[]const u8, null), try it.next());
    try std.testing.expectEqual(@as(usize, 2), try list.count());
}

test "a truncated entry is an error, not a short read" {
    const list = CertificateList.init(&.{ 0, 0, 9, 'A', 'B' });
    var it = list.iterator();
    try std.testing.expectError(error.Truncated, it.next());
}

test "a zero-length entry is malformed" {
    const list = CertificateList.init(&.{ 0, 0, 0, 0, 0 });
    var it = list.iterator();
    try std.testing.expectError(error.MalformedEntry, it.next());
}

test "§4.4.2: an extension on the leaf is refused, one on an intermediate is ignored" {
    // The existing walk test already covers the ignored case from the
    // other side — its second entry carries a one-byte extension — so
    // this pins the asymmetry rather than either half alone. BoGo draws
    // the same line with `SendUnknownExtensionOnCertificate-TLS13`
    // against `IgnoreExtensionsOnIntermediates-TLS13`, and answering both
    // the same way fails one of them whichever way you pick.

    // Leaf first, carrying extension 0x007f with an empty body: exactly
    // the four bytes BoGo sends.
    const leaf_carries = CertificateList.init(&.{
        0,    0,    2,   'A', 'B', 0, 4,
        0x00, 0x7f, 0,   0,   0,   0, 3,
        'C',  'D',  'E', 0,   0,
    });
    var refused = leaf_carries.iterator();
    try std.testing.expectError(error.UnsupportedExtension, refused.next());

    // The same extension one entry later is decoration a client is meant
    // to ignore, and the leaf still comes back whole.
    const intermediate_carries = CertificateList.init(&.{
        0, 0,    2,    'A', 'B', 0,   0,
        0, 0,    3,    'C', 'D', 'E', 0,
        4, 0x00, 0x7f, 0,   0,
    });
    var allowed = intermediate_carries.iterator();
    try std.testing.expectEqualSlices(u8, "AB", (try allowed.next()).?);
    try std.testing.expectEqualSlices(u8, "CDE", (try allowed.next()).?);
    try std.testing.expectEqual(@as(?[]const u8, null), try allowed.next());
}
