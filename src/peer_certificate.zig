//! §4.4.2's Certificate and §4.4.3's CertificateVerify, from whichever
//! side is doing the *checking*.
//!
//! One copy, because both sides check the same way. `ClientHandshake`
//! has always taken a server's certificate this way; a server doing mTLS
//! takes a client's under the same rules — the same DER bounds, the same
//! two key kinds, the same split between possession (ours) and identity
//! (the embedder's). The only differences are which context string
//! §4.4.3 signs and whether an empty list is legal, and both are
//! parameters rather than a second implementation.
//!
//! Nothing here is generic over the machine: it holds the peer's leaf and
//! the verdict on it, and the caller supplies the transcript hash.

const std = @import("std");
const assert = std.debug.assert;

const backend = @import("crypto/backend_openssl.zig");
const certificate_list = @import("certificate_list.zig");
const der_bounds = @import("der_bounds.zig");
const handshake = @import("handshake.zig");
const server_messages = @import("server_messages.zig");
const wire = @import("wire.zig");

pub const CertificateList = certificate_list.CertificateList;
pub const ChainVerifier = certificate_list.ChainVerifier;

/// An RSA-4096 `RSAPublicKey` — two INTEGERs and a SEQUENCE header — is
/// the largest key we accept; the uncompressed P-384 SEC1 point that
/// bounds the EC side is 97.
pub const public_key_bytes_max: u16 = 560;

/// What the checker is willing to do about a certificate at all.
pub const Policy = enum {
    /// Verify CertificateVerify against the leaf's own public key —
    /// ECDSA P-256/P-384 or RSA-PSS. Chain and name validation remain the
    /// embedder's (DESIGN.md §1); see `chain_verifier`.
    leaf_signature,
    /// No certificate checks at all. For tests and pinned transports.
    insecure_no_verification,
};

pub const Error = backend.Error || wire.Error || error{
    /// The Certificate or CertificateVerify message does not parse.
    MalformedMessage,
    /// A certificate we will not use: unknown key algorithm, a key
    /// outside the sizes we hold, an unwalkable chain, or a chain the
    /// embedder's verifier refused.
    BadCertificate,
    /// DER that `std.crypto.Certificate` cannot be pointed at safely.
    MalformedCertificate,
    /// §4.2: an extension on the leaf that was never offered.
    UnsupportedExtension,
    /// CertificateVerify did not verify against the leaf.
    BadSignature,
    /// §4.4.3: a scheme absent from the `signature_algorithms` we
    /// offered. The peer broke the negotiation rather than failing a
    /// check, so the alert is illegal_parameter and nothing was verified.
    UnofferedSignatureScheme,
};

pub const KeyKind = enum { none, ecdsa, rsa };

/// The peer's leaf and what we have concluded about it.
pub const PeerCertificate = struct {
    /// A Certificate message arrived, whatever it contained.
    seen: bool = false,
    /// §4.4.2's `certificate_list` was empty. Legal only from a client
    /// declining a CertificateRequest; a server sending one is refused by
    /// the caller, which is the only side that knows which it is talking
    /// to.
    empty: bool = false,
    /// A CertificateVerify verified against `key`.
    verified: bool = false,
    /// The scheme it verified under, for the embedder to read.
    scheme: ?backend.SignatureScheme = null,
    key: [public_key_bytes_max]u8 = undefined,
    key_bytes: u16 = 0,
    kind: KeyKind = .none,

    pub fn publicKey(self: *const PeerCertificate) []const u8 {
        return self.key[0..self.key_bytes];
    }

    /// Show the chain to the embedder, then pull the leaf's public key out
    /// for CertificateVerify. Under `.insecure_no_verification` the message
    /// is only length-checked and neither step runs.
    pub fn capture(self: *PeerCertificate, body: []const u8, options: CaptureOptions) Error!void {
        assert(self.kind == .none);
        var cursor = wire.Cursor.init(body);
        // §4.4.2's certificate_request_context: empty in a server
        // Certificate, and the echo of ours in a client's. A mismatch is
        // the peer answering a request we did not send.
        const context_bytes = try cursor.takeByte();
        if (context_bytes != options.request_context.len) return error.MalformedMessage;
        const context = try cursor.takeSlice(context_bytes);
        if (!std.mem.eql(u8, context, options.request_context)) return error.MalformedMessage;
        const list_bytes = try cursor.takeU24();
        const list_der = try cursor.takeSlice(list_bytes);
        // Bytes after the chain say nothing about the certificates in it.
        if (cursor.remaining() != 0) return error.MalformedMessage;
        self.seen = true;
        if (options.policy == .insecure_no_verification) return;

        // Identity before possession. The embedder builds the chain and
        // matches the name; we prove the key underneath is held. A chain we
        // would reject is rejected before its leaf's signature is worth
        // checking, and before any of it reaches the transcript.
        if (options.chain_verifier) |verifier| {
            const chain = CertificateList.init(list_der);
            // A list whose framing does not parse is not a chain the
            // embedder can judge — refuse it here rather than hand over
            // entries we could not walk.
            _ = chain.count() catch |err| switch (err) {
                error.UnsupportedExtension => return error.UnsupportedExtension,
                else => return error.BadCertificate,
            };
            if (!verifier.verify(verifier.context, chain)) return error.BadCertificate;
        }

        var entries = CertificateList.init(list_der).iterator();
        // §4.2's refusal travels intact rather than becoming BadCertificate:
        // an unsolicited extension on the leaf says nothing about the
        // certificate, which may be perfectly good, and the alert §4.2 asks
        // for is unsupported_extension rather than bad_certificate.
        const leaf_der = (entries.next() catch |err| switch (err) {
            error.UnsupportedExtension => return error.UnsupportedExtension,
            else => return error.BadCertificate,
        }) orelse {
            // §4.4.2 lets a client answer a CertificateRequest with an
            // empty list, which is a refusal rather than a malformed
            // message. Whether that refusal is acceptable is the
            // caller's call: only it knows if it asked.
            if (options.allow_empty) {
                self.empty = true;
                return;
            }
            return error.BadCertificate;
        };
        // Framing before meaning. `std.crypto.Certificate.parse` computes
        // where one element starts from where the last one ended and reads
        // there unchecked, so a leaf whose lengths point past the end panics
        // rather than erroring — and `catch` cannot answer a safety panic.
        // Seven bytes from a peer were enough (BoGo's
        // `GarbageCertificate-Client-TLS13`).
        der_bounds.validate(leaf_der) catch return error.MalformedCertificate;
        const certificate: std.crypto.Certificate = .{ .buffer = leaf_der, .index = 0 };
        const parsed = certificate.parse() catch return error.MalformedCertificate;
        const public_key = parsed.pubKey();
        if (public_key.len > public_key_bytes_max) return error.BadCertificate;
        switch (parsed.pub_key_algo) {
            .X9_62_id_ecPublicKey => |curve| switch (curve) {
                .X9_62_prime256v1, .secp384r1 => {
                    // Uncompressed P-256 floor; `fromSec1` rejects the rest.
                    if (public_key.len < 65) return error.BadCertificate;
                    self.kind = .ecdsa;
                },
                else => return error.BadCertificate,
            },
            // The key is a DER `RSAPublicKey`. Only a sanity floor here — two
            // INTEGERs and a SEQUENCE header cannot be shorter and still be
            // one — because the length that actually matters is the *modulus*,
            // and `verifyRsaPss` is where that is read and bounded to the four
            // sizes std supports. Nothing downstream may key an assertion off
            // this number: it is the peer's to choose.
            .rsaEncryption => {
                if (public_key.len < 64) return error.BadCertificate;
                self.kind = .rsa;
            },
            else => return error.BadCertificate,
        }
        @memcpy(self.key[0..public_key.len], public_key);
        self.key_bytes = @intCast(public_key.len);
    }

    /// §4.4.3, taken against the *presented* leaf: possession, not identity.
    pub fn verify(self: *PeerCertificate, message: handshake.Message, options: VerifyOptions) Error!void {
        if (options.policy == .insecure_no_verification) return;
        // A leaf was captured — the flight ordering in `drainFlight` guarantees
        // it. Deliberately *not* an assertion about the key's length: that is a
        // number the peer chooses, and the previous `>= 65` here was an ECDSA
        // floor left standing when RSA leaves arrived with a floor of 64. A
        // leaf whose `RSAPublicKey` DER is exactly 64 bytes would have reached
        // it and panicked. Each verifier asserts its own precondition instead,
        // where the kind is known.
        assert(self.kind != .none);
        var body = wire.Cursor.init(message.body());
        const scheme_wire = try body.takeU16();
        const signature = try body.takeSlice(try body.takeU16());
        // Bytes after the signature are a framing fault; the signature
        // itself may be perfectly good and has not been checked yet.
        if (body.remaining() != 0) return error.MalformedMessage;
        // §4.4.3: "If the CertificateVerify message contains a signature
        // algorithm that was not offered in the signature_algorithms
        // extension, the receiver MUST abort with an illegal_parameter
        // alert." That is a negotiation the peer broke, and it is not the
        // same event as a signature that failed to verify — which is why it
        // is its own error rather than the `BadSignature` this used to
        // return for every unrecognised code point. Conflating them sent
        // decrypt_error where §4.4.3 asks for illegal_parameter, and told
        // the embedder a signature was bad when none had been checked.
        const scheme = backend.SignatureScheme.fromWire(scheme_wire) orelse
            return error.UnofferedSignatureScheme;
        if (!offeredScheme(options.accepted, scheme)) return error.UnofferedSignatureScheme;
        var content_buffer: [server_messages.certificate_verify_content_bytes_max]u8 = undefined;
        const content = server_messages.certificateVerifyContent(options.side, options.transcript_hash, &content_buffer);
        const public_key = self.publicKey();
        // The scheme must match the key the leaf actually carries: an ECDSA
        // scheme over an RSA key (or the reverse) is a peer error, not a
        // parse to attempt. Checked here so each verifier's precondition is
        // the kind it was written for. Distinct from the check above: the
        // scheme *was* offered, so the fault is the certificate it arrived
        // beside rather than the negotiation.
        switch (scheme.keyKind()) {
            .ecdsa => if (self.kind != .ecdsa) return error.BadSignature,
            .rsa => if (self.kind != .rsa) return error.BadSignature,
        }
        switch (scheme) {
            .ecdsa_secp256r1_sha256, .ecdsa_secp384r1_sha384 => try verifyEcdsa(scheme, public_key, content, signature),
            .rsa_pss_rsae_sha256 => try verifyRsaPss(std.crypto.hash.sha2.Sha256, public_key, content, signature),
            .rsa_pss_rsae_sha384 => try verifyRsaPss(std.crypto.hash.sha2.Sha384, public_key, content, signature),
            .rsa_pss_rsae_sha512 => try verifyRsaPss(std.crypto.hash.sha2.Sha512, public_key, content, signature),
        }
        self.scheme = scheme;
        self.verified = true;
    }
};

/// What `capture` needs from the caller. `request_context` is what our
/// own CertificateRequest carried and the peer must echo — empty for a
/// server's certificate, which answers no request.
pub const CaptureOptions = struct {
    policy: Policy,
    chain_verifier: ?ChainVerifier,
    request_context: []const u8 = &.{},
    /// Whether an empty `certificate_list` is a legal answer. True only
    /// for a client declining our CertificateRequest (§4.4.2).
    allow_empty: bool = false,
};

/// What `verify` needs. `accepted` is the `signature_algorithms` *we*
/// offered, which §4.4.3 turns from a hint into an abort.
pub const VerifyOptions = struct {
    policy: Policy,
    side: server_messages.Side,
    transcript_hash: []const u8,
    accepted: []const backend.SignatureScheme,
};

/// Whether `scheme` was in the `signature_algorithms` we advertised.
/// §4.4.3 turns this into an abort, so it reads `Config.verify_schemes`
/// rather than the set the code happens to implement — an embedder that
/// narrowed the list meant it. On a server it is `client_auth`'s list.
fn offeredScheme(accepted: []const backend.SignatureScheme, scheme: backend.SignatureScheme) bool {
    for (accepted) |offered| {
        if (offered == scheme) return true;
    }
    return false;
}

/// ECDSA (§4.4.3's `ecdsa_secp*`), through libcrypto.
///
/// This ran on `std.crypto.sign.ecdsa` until `bench/` priced it. §2's
/// exemption for verification is an argument about *constant time* — a
/// public-length message is not where that bites — and it still holds;
/// what it was never an argument for was being seven times slower. Zig's
/// P-256 verifier costs ~333 µs against libcrypto's ~44 µs on the same
/// machine, and that one call was two thirds of a full handshake.
///
/// The memory-safety cost is real and is why this note exists: the key
/// and the signature are the peer's bytes, and they now reach C. Both are
/// bounded before they get there — `capture` caps the key at
/// `public_key_bytes_max` and floors it at 65, the signature is a
/// §4.4.3-framed slice, and `ecFromPublic` validates the point at import
/// rather than trusting it. `verifyRsaPss` below has *not* moved, and the
/// same measurement has not been taken for it.
fn verifyEcdsa(
    scheme: backend.SignatureScheme,
    public_key: []const u8,
    content: []const u8,
    signature_der: []const u8,
) Error!void {
    assert(content.len >= 98); // 64 spaces, the context string, a hash.
    assert(public_key.len >= 65);
    if (signature_der.len < 8) return error.BadSignature;
    backend.verifyEcdsa(scheme, public_key, content, signature_der) catch |err| return switch (err) {
        // The same split `fromSec1` and `verify` gave, and the same two
        // alerts: a point we cannot import is a certificate we cannot
        // use, not a signature that failed.
        error.BadPublicKey => error.BadCertificate,
        error.SignatureInvalid => error.BadSignature,
        // Enumerated rather than an `else`: the else arm would carry the
        // two names above into the return type, which this function
        // exists to translate away.
        error.LibcryptoFailed,
        error.AuthenticationFailed,
        error.IdentityElement,
        => |rest| rest,
    };
}

/// RSA-PSS (§4.4.3's `rsa_pss_rsae_*`), through `std.crypto`'s
/// implementation rather than libcrypto's: verification of a
/// public-length message is not where the constant-time argument bites.
/// The ECDSA side above made the same choice until its cost was measured;
/// this one's has not been, and moving it on the strength of the other's
/// number would be guessing.
///
/// `public_key` is the leaf's DER `RSAPublicKey`. The modulus lengths are
/// the four `std.crypto.Certificate.rsa` supports, 1024 through 4096
/// bits; anything else is a certificate we cannot check rather than a
/// signature that failed, hence `BadCertificate`.
fn verifyRsaPss(comptime Hash: type, public_key: []const u8, content: []const u8, signature: []const u8) Error!void {
    assert(content.len >= 98);
    const rsa = std.crypto.Certificate.rsa;
    const components = rsa.PublicKey.parseDer(public_key) catch return error.BadCertificate;
    switch (components.modulus.len) {
        inline 128, 256, 384, 512 => |modulus_bytes| {
            // §4.4.3 fixes the signature at exactly one modulus wide;
            // `PSSSignature.fromBytes` would zero-pad a short one into a
            // different signature, so the length is checked, not coerced.
            if (signature.len != modulus_bytes) return error.BadSignature;
            const key = rsa.PublicKey.fromBytes(components.exponent, components.modulus) catch
                return error.BadCertificate;
            const sig = rsa.PSSSignature.fromBytes(modulus_bytes, signature);
            rsa.PSSSignature.verify(modulus_bytes, sig, content, key, Hash) catch
                return error.BadSignature;
        },
        else => return error.BadCertificate,
    }
}
