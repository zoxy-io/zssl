//! Server credentials: a DER certificate chain and its ECDSA signing key,
//! loaded once from PEM into caller-owned storage. Certificates are
//! opaque DER blobs from here on — zssl emits them in the Certificate
//! message and never parses their insides (validation is the *verifier's*
//! job, and this side is the party being verified).

const std = @import("std");
const assert = std.debug.assert;

const backend = @import("crypto/backend_openssl.zig");
const pem = @import("pem.zig");

certificates: [certificates_max][]const u8,
certificate_count: u8,
signer: backend.Signer,

const Credentials = @This();

pub const certificates_max: u8 = 4;

/// The whole encoded chain must fit one Certificate message inside one
/// protected record with room for the rest of the flight.
pub const chain_bytes_max: u16 = 8192;

pub const Error = backend.SignError || pem.Error || error{
    /// No CERTIFICATE block in the chain PEM, or too many.
    BadCertificateChain,
};

/// `storage` receives the decoded DER and must outlive the credentials;
/// `chain_bytes_max` bytes is always enough.
pub fn load(
    chain_pem: []const u8,
    key_pem: []const u8,
    storage: []u8,
    deterministic_nonces: bool,
) Error!Credentials {
    assert(chain_pem.len >= 1);
    assert(storage.len >= chain_bytes_max);

    var certificates: [certificates_max][]const u8 = undefined;
    var count: u8 = 0;
    var iterator = pem.Iterator.init(chain_pem, storage[0..chain_bytes_max]);
    var blocks: u8 = 0;
    while (try iterator.next()) |block| : (blocks += 1) {
        assert(blocks < pem.blocks_max); // The iterator errors past its own cap first.
        if (!std.mem.eql(u8, block.label, "CERTIFICATE")) continue;
        if (count == certificates_max) return error.BadCertificateChain;
        certificates[count] = block.der;
        count += 1;
    }
    if (count == 0) return error.BadCertificateChain;

    var signer = try backend.Signer.fromPem(key_pem, deterministic_nonces);
    errdefer signer.deinit();
    return .{ .certificates = certificates, .certificate_count = count, .signer = signer };
}

pub fn deinit(self: *Credentials) void {
    assert(self.certificate_count >= 1);
    assert(self.certificate_count <= certificates_max);
    self.signer.deinit();
    self.* = undefined;
}

pub fn chain(self: *const Credentials) []const []const u8 {
    assert(self.certificate_count >= 1);
    assert(self.certificate_count <= certificates_max);
    return self.certificates[0..self.certificate_count];
}

test "loads the fixture pair and refuses a keyless chain" {
    const cert_pem = @embedFile("testdata/cert.pem");
    const key_pem = @embedFile("testdata/key.pem");
    var storage: [chain_bytes_max]u8 = undefined;

    var credentials = try load(cert_pem, key_pem, &storage, true);
    defer credentials.deinit();
    try std.testing.expectEqual(@as(u8, 1), credentials.certificate_count);
    try std.testing.expectEqualSlices(
        backend.SignatureScheme,
        &.{.ecdsa_secp256r1_sha256},
        credentials.signer.supported(),
    );
    try std.testing.expectEqual(@as(u8, 0x30), credentials.chain()[0][0]);

    // Negative space: a chain PEM with no certificate block.
    try std.testing.expectError(
        error.BadCertificateChain,
        load("no armor here at all", key_pem, &storage, false),
    );
}
