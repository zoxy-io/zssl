//! The client-side TLS 1.3 handshake (RFC 8446 §4), sans-I/O — the
//! origination half, for speaking to upstreams. Same contract as
//! `ServerHandshake`: whole wire records in, events out, no randomness of
//! its own (client random and the x25519 ephemeral arrive via `Config`).
//!
//! Two deliberate shapes:
//!
//! - **HelloRetryRequest is answered when the embedder supplies a second
//!   scalar.** This client shares x25519 and advertises secp256r1 and
//!   secp384r1 beside it, so a server may legally retry it into either.
//!   `Config.retry_key_share_private` is the switch: with it, the retry
//!   earns a second ClientHello carrying the named group's share and any
//!   cookie; without it the old structural refusal stands, because
//!   inventing a scalar would break §1's no-randomness rule.
//!
//!   §4.1.4's illegal shapes stay refused and are told apart: a retry
//!   naming the group we already shared, or one naming a group we never
//!   advertised, is `IllegalRetry` (illegal_parameter); a second retry
//!   is `UnexpectedMessage`. A cookie-only retry is legal — the cookie
//!   is the change — and re-sends the same share.
//!
//!   The PSK comes along, bound to §4.4.1's reconstructed transcript —
//!   message_hash(CH1), the retry, then the truncated CH2 — which is
//!   the surgery the server half verifies from the other side. It stays
//!   behind in one case, and that one is §4.2.11's: a PSK whose hash is
//!   not the retry's suite has nowhere to go, so the offer is dropped
//!   and the handshake degrades to a full one.
//! - **Certificate policy is an explicit seam.** `.leaf_signature` proves
//!   the peer holds the key its leaf names, via `std.crypto`'s ECDSA or
//!   RSA-PSS over the leaf's own SPKI; chain building and RFC 9525 name
//!   matching are the embedder's, deferred with reasons in DESIGN.md §1
//!   and reachable through `Config.chain_verifier`.
//!   `.insecure_no_verification` is for pinned-transport tests and says
//!   so in its name.
//!
//! RSA leaves are accepted here and nowhere else in zssl. The server half
//! signs with ECDSA only, on a latency argument (DESIGN.md §1) that is
//! about *our* signing cost; a client originating to arbitrary upstreams
//! does not get to pick what the far side presents, and most of the
//! public web presents RSA. Verification is RSA-PSS only — §4.4.3 bans
//! rsa_pkcs1_* in CertificateVerify.

const std = @import("std");
const assert = std.debug.assert;

const alert = @import("alert.zig");
const backend = @import("crypto/backend_openssl.zig");
const certificate_list = @import("certificate_list.zig");
const peer_certificate = @import("peer_certificate.zig");
const der_bounds = @import("der_bounds.zig");
const cipher_suite = @import("cipher_suite.zig");
const Credentials = @import("Credentials.zig");
const client_hello = @import("client_hello.zig");
const client_messages = @import("client_messages.zig");
const flood = @import("flood.zig");
const handshake = @import("handshake.zig");
const key_schedule = @import("key_schedule.zig");
const ktls = @import("ktls.zig");
const protect = @import("protect.zig");
const record = @import("record.zig");
const server_messages = @import("server_messages.zig");
const session_keys = @import("session_keys.zig");
const transcript = @import("transcript.zig");
const wire = @import("wire.zig");
const CipherSuite = cipher_suite.CipherSuite;

state: State,
config: Config,
assembler: handshake.Assembler,
ladder: ?Ladder,
/// §5.1 and §4.6.3 flood ceilings: consecutive empty records and
/// consecutive KeyUpdates, both bounded so a peer cannot buy unbounded
/// work with records that deliver nothing. See flood.zig.
flood_guard: flood.Guard,
ccs_seen: u8,
/// Whether our own compatibility ChangeCipherSpec has gone out. D.4
/// puts it before the client's first *protected* record, which is the
/// Finished flight on a handshake that completes and the alert on one
/// that does not — a peer in compatibility mode is waiting for it either
/// way, and will not read a protected record that arrives ahead of it.
ccs_sent: bool,
hello_storage: [client_messages.hello_bytes_max]u8,
hello_bytes: u16,
/// §4.1.4 allows exactly one HelloRetryRequest. A second is a server
/// that cannot make up its mind, and the RFC calls it unexpected_message.
retried: bool,
/// The group our *current* key_share is for — x25519 on the first hello,
/// whatever the retry named on the second.
share_group: u16,
/// The keypair behind `share_group`: built once when the share is put on
/// the wire, kept so the agreement does not rebuild it. `null` until
/// `start`, and replaced rather than added to by a retry — CH2 carries
/// exactly one share, so exactly one is ever live.
key_share: ?backend.KeyShare,
/// The description byte of the fatal alert the peer sent, or null while
/// it has sent none.
///
/// It exists because a Zig error carries no payload: `PeerAlert` says
/// the peer refused us and never which refusal it was, so an embedder
/// that logs or re-maps the peer's alert had nothing to read. The wire
/// byte rather than an `alert.Description`, because §6 lets a peer send
/// any byte and this library names only the ones it uses — a caller
/// wanting the name asks `alert.Description` and gets null for the rest.
///
/// Fatal alerts only, and that is a line rather than an omission: a
/// warning-level alert we decline to interpret earns `BadAlert`, where
/// the alert that follows is *ours*, and recording the peer's byte
/// there would describe a refusal it did not make.
peer_alert_description: ?u8,
/// §7.1's `c e traffic` protector, built at `start` when 0-RTT is
/// offered and retired when EndOfEarlyData goes out — or when the
/// server declines, which it does by saying nothing.
///
/// Send-only: 0-RTT is one direction by construction. Built without a
/// ladder because there is no ladder yet — the suite is the server's to
/// pick, and §4.2.11.2 settles the hash from the PSK instead.
early_send: ?protect.Protector,
/// Bytes handed to `sendEarlyData`, against the ticket's own limit.
early_data_bytes: u32,
/// §4.2.10: the hello on the wire carries `early_data`.
///
/// Not the same question as `early_send != null`, and the difference is
/// an alert: the extension is written before the protector is built, so
/// a protector that failed to build leaves an offer standing that we
/// would otherwise call unsolicited when the server accepted it. The
/// server keeps the same distinction for the same reason.
early_data_offered: bool,
/// §4.2.10: the server answered `early_data` in EncryptedExtensions.
/// Until then an offer is only an offer.
early_data_accepted: bool,
/// Whether the hello now on the wire carries a `pre_shared_key`.
///
/// Not the same question as `config.resume_session != null`, and the
/// difference is a security one: §4.2.11 forbids a server to "select an
/// identity that the client did not offer", and a second ClientHello may
/// legitimately drop the offer the first one made — §4.2.11 says a
/// client SHOULD NOT carry a PSK whose hash is not the retry's suite.
/// The config still holds the resumption in that case, so gating the
/// server's `selected_identity` on the config would let it name an
/// identity CH2 never sent and still reach `connected` unauthenticated.
psk_offered: bool,
/// Whether this session came up on our offered PSK.
resumed: bool,
/// True once the leaf's CertificateVerify checked out under the policy.
peer: peer_certificate.PeerCertificate,
/// §4.3.2 arrived, so the client flight owes a Certificate — even an
/// empty one. Distinct from holding credentials: a client with none
/// still has to answer.
certificate_requested: bool,
/// The schemes the request named, narrowed to those our own key can
/// produce. Empty with no request, and empty when nothing intersects —
/// which is a refusal to sign rather than a handshake failure, because
/// §4.4.2's empty certificate_list is still a legal answer.
signable: [signable_max]backend.SignatureScheme,
signable_count: u8,
/// True once the peer's Certificate message was seen. Tracked apart from
/// the captured key because `.insecure_no_verification` captures no key
/// and the flight's ordering still has to be checked.
/// Which of `Config.alpn_protocols` the server selected in
/// EncryptedExtensions, if any; the embedder decides whether absence is
/// fatal. An index rather than a slice: the offered names are the
/// embedder's memory and this must not imply a lifetime it cannot keep.
alpn_selected: ?u8,
/// The leaf's public key as CertificateVerify needs it: a SEC1 point for
/// ECDSA, a DER `RSAPublicKey` for RSA.
leaf_public_key: [leaf_public_key_bytes_max]u8,
leaf_public_key_bytes: u16,
leaf_key_kind: LeafKeyKind,
/// The scheme the server signed its CertificateVerify with, once one has
/// verified. Null before that and on a resumed handshake, which carries
/// no CertificateVerify at all. Read-only to the embedder, and the
/// mirror of `ServerHandshake.signature_scheme`.
const extension_signature_algorithms: u16 = 13;

const ClientHandshake = @This();

/// Every code point `SignatureScheme` has: the intersection can be no
/// wider than what our own key could sign with.
const signable_max = @typeInfo(backend.SignatureScheme).@"enum".fields.len;

/// An RSA-4096 `RSAPublicKey` — two INTEGERs and a SEQUENCE header — is
/// the largest key we accept; the uncompressed P-384 SEC1 point that
/// bounds the EC side is 97.
const leaf_public_key_bytes_max: u16 = 560;

const LeafKeyKind = enum { none, ecdsa, rsa };

/// draft-ietf-tls-tlsflags. Not a flag zssl acts on — the extension is
/// validated and dropped — but §4.6.1's block is checked rather than
/// skipped, so its grammar has to be known.
/// §4.2.10, and its shape is the message's: empty in a ClientHello, a
/// `uint32 max_early_data_size` in a NewSessionTicket.
const extension_early_data: u16 = 42;
const extension_tls_flags: u16 = 62;

/// A NewSessionTicket's extension block is short by nature: early data,
/// flags, and whatever a future draft adds. The bound is a refusal, not
/// an invariant.
const ticket_extensions_max: u16 = 16;

pub const State = enum(u8) {
    idle,
    awaiting_server_hello,
    // §Appendix A.1's client flight, transcribed. These five used to be
    // one `awaiting_flight` state with the order reconstructed at each
    // message arm by `encrypted_extensions_seen`, `peer.seen`,
    // `peer.verify_seen` and `resumed`. That cost three defects in one
    // review round — a duplicate CertificateVerify and a duplicate
    // EncryptedExtensions, both remote panics on a compliant peer, and a
    // resumed handshake that accepted a certificate nobody asked for —
    // so the order lives in the type now and the guards are gone.
    /// WAIT_EE.
    awaiting_encrypted_extensions,
    /// WAIT_CERT_CR: a full handshake may answer with either, and the
    /// CertificateRequest is optional. A resumed one never arrives here,
    /// which is what makes an unrequested certificate unrepresentable
    /// rather than merely refused.
    awaiting_certificate_or_request,
    /// WAIT_CERT: the request came first, so only the Certificate is
    /// left. A second CertificateRequest has nowhere to land.
    awaiting_certificate,
    /// WAIT_CV: §4.4.3 signs what §4.4.2 presented, so this is reachable
    /// only from a Certificate, and leaving it is the only way to a
    /// Finished on an authenticated handshake.
    awaiting_certificate_verify,
    /// WAIT_FINISHED.
    awaiting_finished,
    connected,
    /// §6.1 closes one direction at a time, so a close is two states
    /// before it is one. We sent close_notify: our write side is done
    /// and nothing further may go out, but the peer's records still
    /// arrive and the embedder still needs to read them — its own
    /// close_notify above all, which is the only way an orderly
    /// shutdown can be told from a truncated one.
    close_sent,
    /// The peer sent close_notify: our read side is done, and we may
    /// still write. Answering with a close_notify of our own is the
    /// ordinary thing to do from here, and asserting `.connected` in
    /// `sendClose` used to make that an abort.
    close_received,
    /// Both directions closed.
    closed,
    failed,
};

/// Whether the server's flight is still being read. Five states answer
/// yes; the call sites that used to compare against `awaiting_flight`
/// ask this instead, so adding a flight state cannot silently skip one.
fn inFlight(self: *const ClientHandshake) bool {
    return switch (self.state) {
        .awaiting_encrypted_extensions,
        .awaiting_certificate_or_request,
        .awaiting_certificate,
        .awaiting_certificate_verify,
        .awaiting_finished,
        => true,
        .idle, .awaiting_server_hello, .connected, .close_sent, .close_received, .closed, .failed => false,
    };
}

/// §6.1's two halves, asked rather than pattern-matched. Every entry
/// point below is gated on one of these instead of on `.connected`,
/// which is what finding 6 was: a single `.closed` state cannot say
/// which direction closed, so it said both and closed neither properly.
pub fn writable(self: *const ClientHandshake) bool {
    return self.state == .connected or self.state == .close_received;
}

pub fn readable(self: *const ClientHandshake) bool {
    return self.state == .connected or self.state == .close_sent;
}

/// Where a close_notify leaves us, by which direction closed *and*
/// whether there was a live connection to half-close at all.
///
/// The second half is load-bearing. `writable()` and `readable()` are
/// read as "the keys for that direction exist", and every write entry
/// point unwraps `ladder.?` behind one of them. A close_notify arriving
/// before the session keys do — a plaintext one as the first record on
/// the wire, say — has no half to keep open: there is nothing to read
/// with and nothing to send with. Half-closing there would make
/// `writable()` true over a null ladder, and the embedder doing the
/// ordinary thing next would abort the process on peer input.
fn afterCloseSent(self: *const ClientHandshake) State {
    return switch (self.state) {
        .connected => .close_sent,
        .close_received => .closed,
        else => .closed,
    };
}

fn afterCloseReceived(self: *const ClientHandshake) State {
    return switch (self.state) {
        .connected => .close_received,
        .close_sent => .closed,
        else => .closed,
    };
}

/// One enum, defined where the checking happens. Re-exported here
/// because `Config.certificate_policy` is the name embedders write, and
/// the server half names the same type for its own client-auth policy.
pub const CertificatePolicy = peer_certificate.Policy;

pub const CertificateList = certificate_list.CertificateList;
pub const ChainVerifier = certificate_list.ChainVerifier;

pub const Resumption = struct {
    identity: []const u8,
    obfuscated_age: u32,
    psk: [cipher_suite.hash_bytes_max]u8,
    psk_bytes: u8,
    /// §4.2.10: offer 0-RTT on this session, or null — the default —
    /// to offer none.
    early_data: ?EarlyData = null,
};

/// The terms a ticket named, handed back to offer 0-RTT against it.
///
/// The two fields travel together because neither is enough alone. The
/// limit is what the server advertised in `Ticket.early_data_bytes_max`,
/// and offering past it is offering against terms nobody agreed to. The
/// suite is `Ticket.suite`, and it is what the early keys are actually
/// derived under: a PSK's length settles only the hash, and
/// `chacha20_poly1305_sha256` shares SHA-256 with `aes_128_gcm_sha256`
/// while using a different AEAD and a different key length. Guessing
/// from the length seals 0-RTT under keys the server will not have, and
/// the server has no way to tell that from a forgery — it answers
/// bad_record_mac and the connection dies.
pub const EarlyData = struct {
    bytes_max: u32,
    suite: CipherSuite,
};

pub const Config = struct {
    /// Embedder-supplied entropy; zssl generates none.
    client_random: [32]u8,
    x25519_private: [32]u8,
    /// The scalar for a second key_share, and the switch that turns
    /// HelloRetryRequest support on. Null keeps the structural refusal
    /// this client shipped with: a retry it cannot answer is a handshake
    /// failure, and saying so is better than pretending.
    ///
    /// Embedder-supplied like every other secret here, because §1's
    /// no-randomness rule does not get an exception for the second
    /// flight — a seeded simulation must replay a retried handshake as
    /// exactly as a straight one. Sized for the widest group we
    /// advertise; a narrower one takes the prefix, the same way
    /// `ServerHandshake.Config.key_share_private` does.
    retry_key_share_private: ?[backend.group_private_bytes_max]u8 = null,
    /// What `supported_groups` offers, in preference order. The share
    /// goes to x25519 either way; the rest are what a server may retry
    /// us into, and only if `retry_key_share_private` is set.
    groups: []const u16 = &.{
        client_hello.group_x25519,
        client_hello.group_secp256r1,
        client_hello.group_secp384r1,
    },
    /// §4.2.3's `signature_algorithms`: what we will accept in the
    /// server's CertificateVerify, in preference order. Narrowing it is
    /// how a deployment refuses a scheme it holds the code for — and
    /// §4.4.3 makes the list load-bearing rather than advisory, because
    /// a signature under a scheme *absent from here* is an
    /// illegal_parameter abort, not a verification that failed.
    verify_schemes: []const backend.SignatureScheme = &client_messages.signature_schemes_default,
    /// Our own certificate and key, for a server that asks (§4.3.2).
    /// Null answers every CertificateRequest with §4.4.2's empty list —
    /// which is a legal answer, and whether the server then continues is
    /// its `require` to decide.
    ///
    /// mTLS only. A client that never meets a CertificateRequest never
    /// touches this, and leaving it null is not a downgrade: a server
    /// that did not ask gets nothing either way.
    client_credentials: ?*const Credentials = null,
    /// Caller-owned space for the client's own Certificate and
    /// CertificateVerify, needed only when `client_credentials` is set —
    /// the chain plus ~1 KiB, exactly as the server's `flight` is sized.
    /// `init` asserts it, because a buffer too small for a chain is an
    /// out-of-bounds write rather than a handshake failure.
    client_auth_flight: []u8 = &.{},
    /// Compatibility session id to send and expect echoed (§4.1.3);
    /// embedder-random, may be empty.
    session_id: []const u8 = &.{},
    server_name: ?[]const u8 = null,
    /// Offered in preference order (RFC 7301 §3.1); empty offers none.
    /// The slices are the embedder's and must outlive the handshake.
    alpn_protocols: []const []const u8 = &.{},
    certificate_policy: CertificatePolicy,
    /// Shown the peer's chain, leaf first, while the Certificate message
    /// is still in reassembly — the seam for chain building and RFC 9525
    /// name matching, which are the embedder's by design. Returning false
    /// aborts with `error.BadCertificate`. Not consulted under
    /// `.insecure_no_verification`, which is what that policy means.
    chain_verifier: ?ChainVerifier = null,
    resume_session: ?Resumption = null,
    send_change_cipher_spec: bool = true,
    /// Caller-owned reassembly space; must hold the server's certificate
    /// chain, so size it like a flight (8 KiB minimum).
    reassembly: []u8,
};

/// A captured NewSessionTicket. The slices view the reassembly buffer
/// and are valid only until the next `handleRecord` — the embedder
/// copies what it keeps.
pub const Ticket = struct {
    lifetime_s: u32,
    age_add: u32,
    nonce: []const u8,
    ticket: []const u8,
    /// The suite this session negotiated, which is the suite the ticket
    /// was issued under. §4.2.10 requires a resumption offering 0-RTT to
    /// negotiate it again, and — the part that bites — the *client* needs
    /// it to key the early data at all. A PSK's length gives only the
    /// hash, and two of the three suites share one.
    suite: CipherSuite,
    /// §4.6.1's `max_early_data_size`, or null where the ticket
    /// advertised none — which is every ticket from a server that does
    /// not accept 0-RTT.
    ///
    /// Surfaced rather than acted on: what a client may offer next time
    /// is a fact about the ticket, and the ticket is the embedder's to
    /// store. §4.2.10 lets a client offer early data only against a
    /// ticket that named a limit, so an embedder that drops this number
    /// has decided against 0-RTT whether it meant to or not.
    early_data_bytes_max: ?u32 = null,
};

/// One thing that happened, as `handleRecord` and `drain` hand it back.
///
/// Neither carries a "nothing happened" member: both answer null for
/// that, so a caller's `while (event) |ready|` ends rather than running
/// a pass over a member with nothing in it. What null means is spelled
/// out on `drain`, and it is the same statement from both.
pub const Event = union(enum) {
    /// Bytes to transmit, sliced from the caller's `out`.
    send: []const u8,
    /// Handshake complete; the payload is the client flight to transmit.
    connected: []const u8,
    application_data: []const u8,
    /// A NewSessionTicket arrived; views die at the next handleRecord.
    ticket: Ticket,
    closed,
};

pub const Error = backend.Error || backend.SignError || protect.Error || session_keys.Error ||
    handshake.Assembler.Error || alert.Error || wire.Error || wire.DuplicateError ||
    flood.Error || error{
    UnexpectedMessage,
    /// `handleRecord` was called while a post-handshake message from the
    /// previous record was still waiting. Not the peer's fault and not a
    /// protocol error: the embedder skipped `drain`. §6 has no alert for
    /// it, and the connection is still intact — drain, then carry on.
    EventsPending,
    /// The ServerHello broke a rule: bad echo, unknown suite, missing or
    /// wrong supported_versions, a PSK we never offered.
    BadServerHello,
    /// §4.1.4: a HelloRetryRequest that cannot be answered because it
    /// changes nothing — it names the group we already shared — or names
    /// a group we never advertised. Distinct from `HandshakeFailure`,
    /// which is what a retry we simply have no scalar for earns.
    IllegalRetry,
    /// HelloRetryRequest — see the file comment for why this is final.
    HandshakeFailure,
    /// More early data offered than the ticket advertised room for.
    /// Ours, not the peer's: a server sizes its own ceiling against the
    /// number it put in the ticket, so going past it is this embedder
    /// writing a cheque the ticket did not sign.
    TooMuchEarlyData,
    /// §4.2: the peer sent an extension we did not offer, or one that
    /// does not belong in the message carrying it. Distinct from
    /// `MalformedExtension`, which is a body we could not read.
    UnsupportedExtension,
    /// A handshake message whose framing does not decode — trailing
    /// bytes, a length that disagrees with its container. §6.2's
    /// decode_error, and deliberately not a verdict about whatever the
    /// message was carrying.
    MalformedMessage,
    /// A certificate whose DER framing does not decode. Separate from
    /// `BadCertificate`, which is a judgement about a certificate we
    /// could read: wrong key size, unusable algorithm, a chain the
    /// embedder refused.
    MalformedCertificate,
    /// An extension whose body does not parse as its type requires.
    MalformedExtension,
    /// §4.3.2: a CertificateRequest without `signature_algorithms`. The
    /// RFC makes it mandatory, and without it the server has asked for a
    /// signature under no algorithm at all.
    MissingExtension,
    /// The certificate could not be read or its key is outside policy.
    BadCertificate,
    /// CertificateVerify did not verify against the leaf.
    BadSignature,
    /// §4.4.3: the CertificateVerify named a signature algorithm absent
    /// from the `signature_algorithms` we offered. The peer broke the
    /// negotiation rather than failing a check, so the alert is
    /// illegal_parameter and no signature was attempted. Distinct from
    /// `BadSignature`, which is a scheme we did offer whose signature did
    /// not verify, or one paired with the wrong kind of leaf key.
    UnofferedSignatureScheme,
    /// The server's Finished MAC did not verify.
    DecryptError,
    /// `exporter` was called before §7.5's secret exists — before the
    /// server Finished that its transcript names. Not the peer's fault
    /// and not a protocol error: the connection is intact and the answer
    /// is "ask again once you are connected". Zeroes would be worse:
    /// they look like keying material.
    HandshakeNotComplete,
    /// The server selected an ALPN protocol we did not offer (RFC 7301).
    BadAlpn,
    /// A field that parses but is not minimally encoded, where its
    /// grammar demands that it be — a NewSessionTicket flag list ending
    /// in a zero byte. Well-framed and still wrong, so §6.2's
    /// illegal_parameter rather than decode_error.
    NonMinimalEncoding,
    /// More extensions in a block than the bound above admits.
    ExtensionOverflow,
    PeerAlert,
};

pub const out_bytes_min: u32 = record.wire_record_bytes_max;

pub fn init(config: *const Config) ClientHandshake {
    assert(config.session_id.len <= 32);
    assert(config.reassembly.len >= 8192);
    assert(config.alpn_protocols.len <= client_messages.alpn_protocols_max);
    for (config.alpn_protocols) |protocol| {
        assert(protocol.len >= 1);
        assert(protocol.len <= client_messages.alpn_protocol_bytes_max);
    }
    assert(!std.mem.allEqual(u8, &config.x25519_private, 0));
    // Only when it can be reached. `wire.Builder` bounds nothing, so a
    // buffer too small for the chain is an out-of-bounds write rather
    // than a handshake failure — and a client that configured
    // credentials without a buffer has made exactly that mistake.
    if (config.client_credentials != null) {
        assert(config.client_auth_flight.len >= Credentials.chain_bytes_max + 1024);
    }
    // `groups` is the embedder's, and three things about it are load
    // bearing. It must name the group we actually share, because §4.2.8
    // requires every key_share entry to appear in supported_groups and
    // this client always shares x25519. Every entry must be one we can
    // complete, for the reason `ServerHandshake` asserts the same: a
    // group we advertise is a retry we may have to answer. And the list
    // is bounded because `wire.Builder` bounds nothing — the hello is
    // built into a fixed buffer.
    assert(config.groups.len >= 1);
    assert(config.groups.len <= client_hello.groups_supported.len);
    // Bounded for the reason `groups` is: the hello is built into a
    // fixed buffer and `wire.Builder` bounds nothing. An empty list is
    // refused rather than silently meaning "all" — a client that accepts
    // no signature can complete no handshake, and saying so at `init` is
    // better than a handshake_failure three flights later.
    assert(config.verify_schemes.len >= 1);
    assert(config.verify_schemes.len <= @typeInfo(backend.SignatureScheme).@"enum".fields.len);
    var shares_an_advertised_group = false;
    for (config.groups) |group| {
        assert(client_hello.groupShareBytes(group) != null);
        if (group == client_hello.group_x25519) shares_an_advertised_group = true;
    }
    assert(shares_an_advertised_group);
    if (config.resume_session) |resumption| {
        assert(resumption.psk_bytes == 32 or resumption.psk_bytes == 48);
        assert(resumption.identity.len >= 1);
        // The ticket's size is the issuing server's choice, and offering
        // one too large for the hello buffer would assert deep inside the
        // encoder. Checked here, where the embedder can see which value
        // was wrong.
        assert(resumption.identity.len <= client_messages.psk_identity_bytes_max);
    }
    return .{
        .state = .idle,
        .config = config.*,
        .assembler = handshake.Assembler.init(config.reassembly),
        .ladder = null,
        .flood_guard = .{},
        .ccs_seen = 0,
        .ccs_sent = false,
        .hello_storage = undefined,
        .hello_bytes = 0,
        .retried = false,
        .share_group = client_hello.group_x25519,
        .key_share = null,
        .peer_alert_description = null,
        .early_send = null,
        .early_data_bytes = 0,
        .early_data_offered = false,
        .early_data_accepted = false,
        .psk_offered = false,
        .resumed = false,
        .peer = .{},
        .certificate_requested = false,
        .signable = undefined,
        .signable_count = 0,
        .alpn_selected = null,
        .leaf_public_key = undefined,
        .leaf_public_key_bytes = 0,
        .leaf_key_kind = .none,
    };
}

/// The protocol the server selected from `Config.alpn_protocols`, or
/// null if it named none. Whether that absence is fatal is the
/// embedder's call — a server that ignores an `h2` offer and answers
/// HTTP/1.1 is a real thing to meet, and reporting it beats refusing it.
pub fn alpnSelected(self: *const ClientHandshake) ?[]const u8 {
    const index = self.alpn_selected orelse return null;
    assert(index < self.config.alpn_protocols.len);
    return self.config.alpn_protocols[index];
}

pub fn deinit(self: *ClientHandshake) void {
    assert(self.ccs_seen <= ccs_seen_max);
    if (self.early_send) |*protector| protector.deinit();
    if (self.ladder) |*ladder| switch (ladder.*) {
        inline else => |*arm| arm.deinit(),
    };
    if (self.key_share) |*share| share.deinit();
    // The scalars themselves, not just `KeyShare`'s copy of them.
    // `Config` is taken by value at `init`, so this machine holds the
    // (EC)DHE private keys for its whole life — and disposing of them is
    // the entire content of the word "ephemeral". `self.* = undefined`
    // is not a wipe: it is a value assignment the compiler may elide,
    // which is why every other secret here is `secureZero`'d before it.
    std.crypto.secureZero(u8, &self.config.x25519_private);
    if (self.config.retry_key_share_private) |*scalar| std.crypto.secureZero(u8, scalar);
    self.* = undefined;
}

const ccs_seen_max: u8 = 2;

/// Build and frame the opening ClientHello. The message is kept whole in
/// `hello_storage`: the transcript can only absorb it once the server
/// has picked a suite.
pub fn start(self: *ClientHandshake, out: []u8) []const u8 {
    assert(self.state == .idle);
    assert(out.len >= record.header_bytes + client_messages.hello_bytes_max);
    // The private key was asserted nonzero at init; what remains is a
    // libcrypto fault, which no peer caused and no alert can express.
    //
    // Kept rather than discarded: the agreement three flights from now
    // needs this keypair, and rebuilding it from the scalar alone would
    // make libcrypto multiply by the base point a second time to recover
    // the public half it is about to be handed (bench/README.md).
    assert(self.key_share == null);
    self.key_share = backend.KeyShare.init(
        .x25519,
        &self.config.x25519_private,
    ) catch unreachable;
    const psk: ?client_messages.PskParams = if (self.config.resume_session) |resumption| .{
        .identity = resumption.identity,
        .obfuscated_age = resumption.obfuscated_age,
        .binder_bytes = resumption.psk_bytes,
        // §4.2.10 offers 0-RTT by the extension's presence. A limit of
        // zero is a server that advertised none, so there is nothing to
        // offer against.
        .early_data = if (resumption.early_data) |terms| terms.bytes_max > 0 else false,
    } else null;
    const message = client_messages.clientHello(&self.hello_storage, &.{
        .random = &self.config.client_random,
        .session_id = self.config.session_id,
        .share_group = client_hello.group_x25519,
        .share_public = self.key_share.?.publicValue(),
        .groups = self.config.groups,
        .signature_schemes = self.config.verify_schemes,
        .server_name = self.config.server_name,
        .alpn_protocols = self.config.alpn_protocols,
        .psk = psk,
    });
    self.hello_bytes = @intCast(message.len);
    self.psk_offered = psk != null;
    if (self.config.resume_session) |resumption| {
        // Null: nothing precedes a first ClientHello, so §4.2.11.2's
        // transcript is the truncation alone.
        client_messages.patchBinder(
            self.hello_storage[0..self.hello_bytes],
            resumption.psk[0..resumption.psk_bytes],
            null,
        );
    }
    // §7.1's `c e traffic`, over the ClientHello alone — which is the
    // whole reason 0-RTT can put data on the wire before a ServerHello
    // answers. Derived here because here is the only moment the
    // transcript *is* that hello, and keyed off the PSK's own hash: the
    // suite is the server's to pick and has not been picked.
    if (psk) |offer| {
        // Set from the wire, not from what follows: the extension is
        // already written, so this is true even if the protector below
        // cannot be built.
        self.early_data_offered = offer.early_data;
        if (offer.early_data) self.startEarlyKeys() catch {
            // A protector we could not build is not a handshake we must
            // fail: the offer stands on the wire, nothing has been sent
            // under it, and the server accepting costs us one round trip
            // when `sendEarlyData` answers null.
            self.early_send = null;
        };
    }
    var builder = wire.Builder.init(out);
    appendPlaintextRecord(&builder, .handshake, self.hello_storage[0..self.hello_bytes]);
    self.state = .awaiting_server_hello;
    return builder.written();
}

/// Feed one whole wire record. On any error the machine is `failed` and
/// must not be fed again.
///
/// Null is "this record produced nothing", and it is the same null
/// `drain` answers, so the two compose into one loop:
///
///     var event = try client.handleRecord(wire_record, &out);
///     while (event) |ready| : (event = try client.drain(&out)) { … }
pub fn handleRecord(self: *ClientHandshake, wire_record: []const u8, out: []u8) Error!?Event {
    assert(out.len >= out_bytes_min);
    assert(self.state != .failed);
    assert(self.state != .idle);
    errdefer self.state = .failed;
    // A caller that stopped draining is told so here, rather than
    // finding out one record later. The extra message is still buffered
    // and would be taken ahead of this record's, so the peer's KeyUpdate
    // would rotate its keys while ours stayed put and the *next* record
    // would fail to open — a decryption failure that says nothing about
    // its cause. `drain` until null.
    if (self.assembler.hasComplete()) return error.EventsPending;
    const header = try record.parseHeader(wire_record[0..record.header_bytes]);
    if (wire_record.len != @as(usize, record.header_bytes) + header.length) {
        return error.UnexpectedMessage;
    }
    switch (header.content_type) {
        .change_cipher_spec => {
            // §5 bounds the window, and the comment here used to say
            // "ignored wherever it lands", which is not what it says:
            //
            //   An implementation may receive an unencrypted record of
            //   type change_cipher_spec ... at any time after the first
            //   ClientHello message has been sent or received and before
            //   the peer's Finished message has been received and MUST
            //   simply drop it ... If an implementation detects a
            //   change_cipher_spec record received before the first
            //   ClientHello message or after the peer's Finished
            //   message, it MUST be treated as an unexpected record type.
            //
            // Outside that window it is unexpected_message, and the
            // count still bounds it inside. TLS-Anvil found this, and
            // only after a harness deadline stopped hiding it: the
            // connection used to close on its own before the corpus
            // could see that we had accepted the record.
            //
            // What the record *contains* is asked first, and before
            // anything about where we are — see the server side, which
            // had the same hole and is where tlsfuzzer found it.
            if (!record.isCompatibilityCcs(wire_record[record.header_bytes..])) {
                return error.UnexpectedMessage;
            }
            // `.closed` counts as after it too: the only way to reach
            // that state from a protected close_notify is with the
            // peer's Finished already behind us, and a machine in it
            // may still be fed records.
            switch (self.state) {
                // Every state at or past the peer's Finished. §5 puts
                // the window's far edge there, and a half-closed
                // connection is well past it.
                .connected, .close_sent, .close_received, .closed => return error.UnexpectedMessage,
                else => {},
            }
            if (self.ccs_seen == ccs_seen_max) return error.UnexpectedMessage;
            // §5's tolerance is for a record between *flights*, not one
            // wedged into a message being reassembled.
            try self.refuseInterleavedRecord();
            self.ccs_seen += 1;
            return null;
        },
        .alert => {
            try self.refuseInterleavedRecord();
            return self.handleAlertPayload(wire_record[record.header_bytes..]);
        },
        .handshake => {
            if (self.state != .awaiting_server_hello) return error.UnexpectedMessage;
            try self.assembler.push(wire_record[record.header_bytes..]);
            const message = (try self.assembler.next()) orelse return null;
            if (message.messageType() != .server_hello) return error.UnexpectedMessage;
            if (!self.assembler.empty()) return error.UnexpectedMessage;
            return self.handleServerHello(message.bytes, out);
        },
        .application_data => return self.handleProtectedRecord(wire_record, out),
    }
}

/// §5.1: "Handshake messages MUST NOT be interleaved with other record
/// types. That is, if a handshake message is split over two or more
/// records, there MUST NOT be any other records between them."
///
/// See `ServerHandshake.refuseInterleavedRecord`; both machines had the
/// hole and both close it the same way.
fn refuseInterleavedRecord(self: *const ClientHandshake) Error!void {
    if (!self.assembler.empty()) return error.UnexpectedMessage;
}

fn handleAlertPayload(self: *ClientHandshake, payload: []const u8) Error!?Event {
    assert(self.state != .failed);
    assert(payload.len >= 1);
    const parsed = try alert.parse(payload);
    switch (alert.disposition(parsed)) {
        .close => {
            self.state = self.afterCloseReceived();
            return .closed;
        },
        // §6.1's user_canceled, which real peers send and this library
        // has no use for. Counted, because ignoring is work too.
        .ignore => {
            try self.flood_guard.observeWarningAlert();
            return null;
        },
        .refuse => return error.BadAlert,
        .peer_fatal => {
            self.peer_alert_description = parsed.description_wire;
            return error.PeerAlert;
        },
    }
}

/// §7.1's other child of the early secret, on the client's side of it.
///
/// The suite comes from the *ticket*, not from anything negotiated —
/// there is no negotiated suite yet — and not from the PSK's length
/// either, which is the trap `patchBinder` two functions away can afford
/// to fall into and this cannot. A binder needs only the hash, so a
/// 32-byte PSK settles it; early *records* need the AEAD as well, and
/// `chacha20_poly1305_sha256` shares SHA-256 with `aes_128_gcm_sha256`.
/// Sealing under the wrong one produces records the server cannot open
/// and cannot tell from a forgery, so it answers bad_record_mac and the
/// connection dies rather than falling back.
///
/// The transcript is the ClientHello alone, which `start` has just
/// written and not yet absorbed anywhere.
fn startEarlyKeys(self: *ClientHandshake) protect.Error!void {
    assert(self.early_send == null);
    assert(self.state == .idle);
    const resumption = self.config.resume_session.?;
    const psk = resumption.psk[0..resumption.psk_bytes];
    const named = resumption.early_data.?.suite;
    // The PSK is bound to its hash by §4.6.1's derivation, so a ticket
    // naming a suite that hashes to another length is an embedder that
    // paired the wrong two things.
    assert(named.hashBytes() == psk.len);
    switch (named) {
        inline else => |suite| {
            const Hash = CipherSuite.HashType(suite);
            const Schedule = key_schedule.KeySchedule(suite);
            var hello_hash: [Hash.digest_length]u8 = undefined;
            Hash.hash(self.hello_storage[0..self.hello_bytes], &hello_hash, .{});
            var schedule = Schedule.initEarly(psk);
            defer schedule.wipe();
            const early_traffic = schedule.deriveAt(.early, "c e traffic", &hello_hash);
            const keys = Schedule.trafficKeys(&early_traffic);
            self.early_send = try protect.Protector.init(suite, &keys.key, &keys.iv);
        },
    }
}

/// Seal one 0-RTT record (§4.2.10), or answer null when there is no
/// offer to send it under.
///
/// Null rather than an error, because "this connection is not doing
/// 0-RTT" is an ordinary answer: the embedder offered, the ticket may
/// not have permitted it, and the data belongs on the 1-RTT stream
/// instead. What *is* an error is going past the limit the ticket named
/// — that is a promise the server sized its own ceiling against.
///
/// Callable only before the ServerHello. The keys are derived over the
/// hello alone and the transcript stops being that the moment a
/// ServerHello lands in it.
pub fn sendEarlyData(self: *ClientHandshake, bytes: []const u8, out: []u8) Error!?[]const u8 {
    assert(self.state == .awaiting_server_hello);
    assert(bytes.len <= record.plaintext_bytes_max);
    const protector = &(self.early_send orelse return null);
    const bytes_max = self.config.resume_session.?.early_data.?.bytes_max;
    errdefer self.state = .failed;
    self.early_data_bytes +|= @intCast(bytes.len);
    if (self.early_data_bytes > bytes_max) return error.TooMuchEarlyData;
    return try protector.seal(.application_data, bytes, out);
}

/// §4.1.4. The retry names a group we advertised but did not share, and
/// the answer is a second ClientHello carrying that share and whatever
/// cookie came with it.
///
/// Three ways a retry is illegal and all three are the RFC's, not ours:
/// a second retry in one handshake ("the client MUST abort ... with an
/// unexpected_message alert"); a group we never advertised; and a group
/// we *did* already share, which §4.1.4 calls out by name because such a
/// retry asks the client to change nothing and would loop.
///
/// The fourth refusal is ours and is a configuration answer rather than
/// a protocol one: with no `retry_key_share_private` there is no second
/// scalar to build a share from, and inventing one would break §1's
/// no-randomness rule. That is `HandshakeFailure`, and it is what this
/// client did for every retry before it could answer any.
/// Swap the key share CH2 will carry, and hand back its public value.
///
/// Replaced rather than added to: CH2 carries one share, and after this
/// the old keypair can never be the one the ServerHello answers. A
/// cookie-only retry re-derives the same x25519 pair it already had,
/// which is a multiplication rather than a correctness question — the
/// alternative is a branch that has to be right about when the group did
/// *not* change, and being wrong about that is the bug
/// `handleServerHello` still carries a comment about.
///
/// The new share is built *before* the old one is torn down, so a
/// libcrypto failure here leaves the handshake holding the share it
/// already had rather than a `key_share` that is non-null and undefined.
/// The optional's tag survives `deinit` — it only wipes the payload — so
/// deinit-then-assign would leave `ClientHandshake.deinit` a second
/// `deinit` to run over dead bytes on the way out.
fn replaceKeyShare(
    self: *ClientHandshake,
    group: backend.Group,
    private_key: []const u8,
) Error![]const u8 {
    assert(self.key_share != null); // `start` built one before any retry.
    const replacement = backend.KeyShare.init(group, private_key) catch
        return error.HandshakeFailure;
    self.key_share.?.deinit();
    self.key_share = replacement;
    assert(self.key_share.?.group == group);
    return self.key_share.?.publicValue();
}

fn handleHelloRetryRequest(
    self: *ClientHandshake,
    message: []const u8,
    body: *wire.Cursor,
    out: []u8,
) Error!Event {
    if (self.retried) return error.UnexpectedMessage;
    const echo = try body.takeSlice(try body.takeByte());
    if (!std.mem.eql(u8, echo, self.config.session_id)) return error.BadServerHello;
    const suite = CipherSuite.fromWire(try body.takeU16()) orelse return error.BadServerHello;
    // §4.1.3: legacy_compression_method "MUST be a single byte with
    // value 0". A field with exactly one legal value carrying another is
    // a message that could not be decoded (§6.2), not a parameter we
    // disagree with — BoGo's TLS13-HRR-InvalidCompressionMethod is where
    // the difference is visible.
    if (try body.takeByte() != 0) return error.MalformedMessage;
    const retry = try self.readRetryExtensions(body);
    if (!retry.tls13_selected) return error.BadServerHello;

    // §4.1.4 turns on one question: does this retry change the hello? A
    // `key_share` naming a different group does. A `cookie` does too,
    // all by itself — the retry is then "send that again and carry
    // this", which is how a stateless server keeps its retry state on
    // the client. Neither present changes nothing, and neither does a
    // key_share naming the group we already shared; the RFC's answer to
    // both is illegal_parameter.
    const selected = retry.selected_group orelse self.share_group;
    if (retry.selected_group) |named| {
        if (named == self.share_group) return error.IllegalRetry;
    } else {
        if (retry.cookie == null) return error.IllegalRetry;
    }
    var advertised = false;
    for (self.config.groups) |group| {
        if (group == selected) advertised = true;
    }
    if (!advertised) return error.IllegalRetry;
    const group = backend.Group.fromWire(selected) orelse return error.IllegalRetry;
    // A cookie-only retry re-sends the share it already sent, so the
    // scalar is the one that built it; a group change needs the second.
    const scalar: [backend.group_private_bytes_max]u8 = if (selected == client_hello.group_x25519)
        self.config.x25519_private ++ [_]u8{0} ** (backend.group_private_bytes_max - 32)
    else
        self.config.retry_key_share_private orelse return error.HandshakeFailure;

    // §4.4.1's surgery, and the reason the ladder is built here rather
    // than at the ServerHello: CH1 is replaced in the transcript by a
    // synthetic message_hash, and hashing needs the suite — which the
    // retry names, so this is the first moment it can be done.
    self.ladder = Ladder.initFor(suite);
    switch (self.ladder.?) {
        inline else => |*arm| arm.absorbRetryClientHello(
            self.hello_storage[0..self.hello_bytes],
            message,
        ),
    }

    const share = try self.replaceKeyShare(group, scalar[0..group.privateBytes()]);

    // §4.2.11 on which offers may travel: "the client SHOULD NOT offer
    // any pre-shared keys associated with a hash other than that of the
    // selected cipher suite". A ticket's PSK is a hash long by §4.6.1's
    // derivation, so its length *is* its hash, and a retry that names a
    // suite hashing to another length leaves the offer behind. Dropping
    // it degrades to a full handshake; carrying it would offer a binder
    // the server cannot even parse against its own schedule.
    const carried: ?client_messages.PskParams = if (self.config.resume_session) |resumption|
        if (resumption.psk_bytes == suite.hashBytes()) .{
            .identity = resumption.identity,
            .obfuscated_age = resumption.obfuscated_age,
            .binder_bytes = resumption.psk_bytes,
        } else null
    else
        null;
    const second = client_messages.clientHello(&self.hello_storage, &.{
        .random = &self.config.client_random,
        .session_id = self.config.session_id,
        .share_group = selected,
        .share_public = share,
        .groups = self.config.groups,
        .signature_schemes = self.config.verify_schemes,
        .cookie = retry.cookie,
        .server_name = self.config.server_name,
        .alpn_protocols = self.config.alpn_protocols,
        .psk = carried,
    });
    self.hello_bytes = @intCast(second.len);
    self.share_group = selected;
    self.retried = true;
    // §4.1.2's exception list removes `early_data` from a second
    // ClientHello, and CH2 above does not carry it. Withdrawing it on
    // the wire is only half: the keys were derived over CH1, whose
    // transcript this retry has just replaced, so anything still holding
    // them would seal against a hello the server never saw.
    if (self.early_send) |*protector| {
        protector.deinit();
        self.early_send = null;
    }
    self.early_data_offered = false;
    self.early_data_bytes = 0;
    self.psk_offered = carried != null;
    self.resumed = false;
    // §4.2.11.2's binder over §4.4.1's transcript, which is the whole of
    // what kept a PSK from crossing a retry: the hash is not the
    // truncated CH2 alone but message_hash(CH1), the retry, and *then*
    // the truncation. The ladder is standing at exactly that point — the
    // surgery above absorbed both and CH2 has not gone in yet — so the
    // prefix is asked for rather than rebuilt, and the two can never
    // disagree about what CH1 hashed to.
    //
    // Ordered before the transcript takes CH2 because it must be: the
    // binder is part of the message the transcript absorbs.
    if (carried) |offer| {
        // `carried` is built from `config.resume_session` and is null
        // without it, so the unwrap below is that construction restated
        // rather than a second assumption.
        assert(self.config.resume_session != null);
        assert(offer.binder_bytes == self.config.resume_session.?.psk_bytes);
        const psk = self.config.resume_session.?.psk[0..offer.binder_bytes];
        switch (self.ladder.?) {
            inline else => |*arm| {
                const hello = self.hello_storage[0..self.hello_bytes];
                const digest = arm.transcript.hashWith(
                    client_messages.binderTruncation(hello, offer.binder_bytes),
                );
                client_messages.patchBinder(hello, psk, &digest);
            },
        }
    }
    // CH2 joins the transcript now; the ServerHello that answers it will
    // be absorbed on top, and `handleServerHello` must not re-absorb CH1.
    switch (self.ladder.?) {
        inline else => |*arm| arm.transcript.update(self.hello_storage[0..self.hello_bytes]),
    }
    // §D.4: our own compatibility CCS goes before the first *protected*
    // record, and the second hello is not one — but a peer in
    // compatibility mode expects it after the retry, which is where
    // every other 1.3 client puts it.
    var builder = wire.Builder.init(out);
    if (self.config.send_change_cipher_spec and !self.ccs_sent) {
        builder.putSlice(&server_messages.change_cipher_spec_record);
        self.ccs_sent = true;
    }
    appendPlaintextRecord(&builder, .handshake, self.hello_storage[0..self.hello_bytes]);
    return .{ .send = builder.written() };
}

const RetryExtensions = struct {
    selected_group: ?u16,
    cookie: ?[]const u8,
    tls13_selected: bool,
};

/// §4.1.4's HelloRetryRequest extension block: `key_share` carries a
/// bare group here rather than a share, `cookie` is opaque and echoed,
/// and `supported_versions` still has to select 1.3.
fn readRetryExtensions(self: *ClientHandshake, body: *wire.Cursor) Error!RetryExtensions {
    _ = self;
    const extensions_bytes = try body.takeU16();
    if (extensions_bytes != body.remaining()) return error.BadServerHello;
    var result: RetryExtensions = .{ .selected_group = null, .cookie = null, .tls13_selected = false };
    try wire.refuseDuplicateExtensions(8, body.rest());
    var seen: u8 = 0;
    while (body.remaining() > 0) : (seen += 1) {
        if (seen == 8) return error.BadServerHello;
        const extension_type = try body.takeU16();
        const data = try body.takeSlice(try body.takeU16());
        switch (extension_type) {
            51 => {
                if (data.len != 2) return error.BadServerHello;
                result.selected_group = std.mem.readInt(u16, data[0..2], .big);
            },
            44 => {
                if (data.len < 2) return error.BadServerHello;
                const cookie_bytes = std.mem.readInt(u16, data[0..2], .big);
                if (cookie_bytes == 0) return error.BadServerHello;
                if (@as(usize, cookie_bytes) + 2 != data.len) return error.BadServerHello;
                // §4.2.2 says we echo it verbatim in the second hello, so
                // its size is a length the *server* picks for a buffer
                // *we* fixed. Bounded here rather than in the encoder,
                // where `wire.Builder` would have taken it as an
                // assertion — the same shape as the oversized ticket, and
                // reachable from any server generous with retry state.
                if (cookie_bytes > client_messages.cookie_bytes_max) return error.BadServerHello;
                result.cookie = data[2..];
            },
            43 => {
                if (data.len != 2) return error.BadServerHello;
                if (std.mem.readInt(u16, data[0..2], .big) != 0x0304) return error.BadServerHello;
                result.tls13_selected = true;
            },
            else => return error.UnsupportedExtension,
        }
    }
    return result;
}

fn handleServerHello(self: *ClientHandshake, message: []const u8, out: []u8) Error!?Event {
    assert(self.state == .awaiting_server_hello);
    // After a retry the ladder already exists: the surgery in §4.4.1
    // needs the suite, the HelloRetryRequest names it, and so the
    // transcript starts one message earlier than it used to.
    assert(self.retried or self.ladder == null);
    var body = wire.Cursor.init(message[handshake.header_bytes..]);
    if (try body.takeU16() != 0x0303) return error.BadServerHello;
    const random = try body.takeSlice(32);
    if (std.mem.eql(u8, random, &server_messages.hello_retry_magic)) {
        return try self.handleHelloRetryRequest(message, &body, out);
    }
    const echo = try body.takeSlice(try body.takeByte());
    if (!std.mem.eql(u8, echo, self.config.session_id)) return error.BadServerHello;
    const suite = CipherSuite.fromWire(try body.takeU16()) orelse return error.BadServerHello;
    // §4.1.3: legacy_compression_method "MUST be a single byte with
    // value 0". A field with exactly one legal value carrying another is
    // a message that could not be decoded (§6.2), not a parameter we
    // disagree with — BoGo's TLS13-HRR-InvalidCompressionMethod is where
    // the difference is visible.
    if (try body.takeByte() != 0) return error.MalformedMessage;
    const extensions = try self.readServerHelloExtensions(&body);
    // §4.2.1: no supported_versions selecting 1.3 means a 1.2 server —
    // and this library has nothing to say to one.
    if (!extensions.tls13_selected) return error.BadServerHello;
    const server_share = extensions.server_share orelse return error.BadServerHello;
    // §4.1.4: the ServerHello answering a retry keeps the suite the retry
    // named. Letting it change would let a server pick one suite to
    // compute the message_hash under and another to finish with.
    if (self.retried and std.meta.activeTag(self.ladder.?) != suite) return error.BadServerHello;
    if (self.resumed) {
        // §4.2.11: the selected PSK's hash and the suite's must agree.
        if (self.config.resume_session.?.psk_bytes != suite.hashBytes()) return error.BadServerHello;
    }
    // The share must be for the group our *current* key_share names —
    // x25519 on a straight handshake, the retried group after one.
    if (server_share.group != self.share_group) return error.BadServerHello;
    const group = backend.Group.fromWire(server_share.group) orelse return error.BadServerHello;
    // The keypair that built the share on the wire, not one rebuilt from
    // a scalar picked here. Which scalar that was used to be re-decided
    // at this line, by the *group* rather than by `retried` — a
    // cookie-only retry re-sends the x25519 share it already sent, so
    // `retried` says nothing about it, and choosing by `retried` derived
    // the shared secret from the wrong key and surfaced as a bad record
    // MAC on the server's first flight. `start` and `handleRetry` are
    // now the only two places that answer the question, each right where
    // it puts a share on the wire, and the check above has already
    // established that this is the group they answered it for.
    const key_share = &self.key_share.?;
    assert(key_share.group == group);

    var shared_storage: [backend.group_shared_bytes_max]u8 = undefined;
    const shared = try key_share.agree(
        server_share.value[0..server_share.bytes],
        &shared_storage,
    );
    defer std.crypto.secureZero(u8, &shared_storage);
    if (!self.retried) self.ladder = Ladder.initFor(suite);
    switch (self.ladder.?) {
        inline else => |*arm| {
            // A retried handshake already holds message_hash(CH1), the
            // retry, and CH2; a straight one starts here.
            if (!self.retried) arm.transcript.update(self.hello_storage[0..self.hello_bytes]);
            arm.transcript.update(message);
            const psk: ?[]const u8 = if (self.resumed)
                self.config.resume_session.?.psk[0..self.config.resume_session.?.psk_bytes]
            else
                null;
            try arm.startHandshakeKeys(shared, psk);
        },
    }
    // §Appendix A.1: ServerHello leaves WAIT_SH for WAIT_EE.
    self.state = .awaiting_encrypted_extensions;
    return null;
}

/// A KeyShareEntry as the ServerHello carries it: the group, and the
/// peer's public value at whatever length that group fixes.
const ServerShare = struct {
    group: u16,
    value: [backend.group_public_bytes_max]u8,
    bytes: u8,
};

const ServerHelloExtensions = struct {
    server_share: ?ServerShare,
    tls13_selected: bool,
};

fn readServerHelloExtensions(self: *ClientHandshake, body: *wire.Cursor) Error!ServerHelloExtensions {
    const extensions_bytes = try body.takeU16();
    if (extensions_bytes != body.remaining()) return error.BadServerHello;
    var result: ServerHelloExtensions = .{ .server_share = null, .tls13_selected = false };
    try wire.refuseDuplicateExtensions(8, body.rest());
    var extensions_seen: u8 = 0;
    while (body.remaining() > 0) : (extensions_seen += 1) {
        if (extensions_seen == 8) return error.BadServerHello;
        assert(extensions_seen < 8);
        const extension_type = try body.takeU16();
        const data = try body.takeSlice(try body.takeU16());
        switch (extension_type) {
            51 => {
                var share = wire.Cursor.init(data);
                const group = try share.takeU16();
                const value_bytes = try share.takeU16();
                // The length the group fixes, checked here rather than
                // trusted: `keyShareShared` would refuse a wrong one, but
                // this is the boundary that owns the peer's framing.
                const known = backend.Group.fromWire(group) orelse return error.BadServerHello;
                if (value_bytes != known.publicBytes()) return error.BadServerHello;
                const value = try share.takeSlice(value_bytes);
                if (share.remaining() != 0) return error.BadServerHello;
                var entry: ServerShare = .{ .group = group, .value = undefined, .bytes = @intCast(value_bytes) };
                @memcpy(entry.value[0..value.len], value);
                result.server_share = entry;
            },
            43 => {
                var version = wire.Cursor.init(data);
                if (try version.takeU16() != 0x0304) return error.BadServerHello;
                if (version.remaining() != 0) return error.BadServerHello;
                result.tls13_selected = true;
            },
            41 => {
                // §4.2.11: "the server MUST NOT select an identity that
                // the client did not offer". The question is what *this*
                // hello offered, not what the config holds — and those
                // stopped being the same thing when a retry began
                // deciding for itself whether the PSK comes along.
                // Gating on the config alone let a server answer a hello
                // with no identities at all and still set `resumed`,
                // which is the flag `completeHandshake` reads to decide
                // a certificate was not required. An unauthenticated
                // connection reaching `connected` is the one thing that
                // must not happen.
                //
                // `psk_offered` is that question asked of the hello
                // itself, which is why it survived a retry learning to
                // carry the PSK: the answer moved, the guard did not.
                if (!self.psk_offered) return error.BadServerHello;
                var selected = wire.Cursor.init(data);
                // We offer exactly one identity, so index 0 is the only
                // selection that can be answering us.
                if (try selected.takeU16() != 0) return error.BadServerHello;
                if (selected.remaining() != 0) return error.BadServerHello;
                self.resumed = true;
            },
            else => return error.BadServerHello, // A ServerHello has exactly these three.
        }
    }
    return result;
}

fn handleProtectedRecord(self: *ClientHandshake, wire_record: []const u8, out: []u8) Error!?Event {
    // Readable, not connected: §6.1 leaves the read side open after our
    // own close_notify, and closing it there is what made a truncated
    // shutdown indistinguishable from an orderly one.
    if (!self.inFlight() and self.state != .connected and self.state != .close_sent) {
        return error.UnexpectedMessage;
    }
    assert(self.ladder != null);
    switch (self.ladder.?) {
        inline else => |*arm| {
            const opened = if (self.inFlight())
                try arm.recv.?.open(wire_record, out)
            else switch (self.state) {
                .connected, .close_sent => try arm.session.?.recv.open(wire_record, out),
                else => unreachable,
            };
            const plaintext = out[0..opened.plaintext_bytes];
            // §5.1/§4.6.3 flood ceilings, counted on every opened
            // record so that padding-only and empty ones — the cheapest
            // thing a peer can send us — are bounded before they are
            // dispatched. `content_type` decides only what counts as
            // progress; see flood.zig.
            try self.flood_guard.observeRecord(plaintext.len, opened.content_type);
            // §5.4: only application_data may carry a zero-length
            // TLSInnerPlaintext.content; a handshake or alert record that
            // is nothing but its content-type byte is unexpected_message.
            // Here is the only place that can tell — the length on the
            // wire covers padding this one does not.
            if (plaintext.len == 0 and opened.content_type != .application_data) {
                return error.UnexpectedMessage;
            }
            switch (opened.content_type) {
                .alert => {
                    try self.refuseInterleavedRecord();
                    return self.handleAlertPayload(plaintext);
                },
                .handshake => {
                    try self.assembler.push(plaintext);
                    if (!self.inFlight()) return self.nextPostHandshake(arm, out);
                    return self.drainFlight(arm, out);
                },
                .application_data => {
                    try self.refuseInterleavedRecord();
                    // Readable, not connected: our own close_notify
                    // shuts the write side, and the peer is entitled to
                    // keep sending until it closes its own (§6.1).
                    if (!self.readable()) return error.UnexpectedMessage;
                    return .{ .application_data = plaintext };
                },
                .change_cipher_spec => return error.UnexpectedMessage,
            }
        },
    }
}

/// §4.3.2, from the client's side: the context we must echo and the
/// schemes we may sign with.
///
/// The context is required to be empty. §4.3.2 makes it zero length
/// "unless used for the post-handshake authentication exchanges", which
/// DESIGN.md §1 puts out of scope — so a non-empty one is a server
/// starting an exchange we do not implement, and answering it with a
/// certificate would be worse than refusing.
///
/// `signature_algorithms` is the only extension we read, and §4.3.2
/// makes it mandatory: without it the request names nothing we could
/// sign with. `certificate_authorities` and `oid_filters` are ignored
/// deliberately — they narrow *which* certificate to send, and this
/// client has exactly one.
/// What the client flight owes §4.3.2, resolved once so the ladder does
/// not reach back into `Config`.
///
/// Null when no request arrived, which is every ordinary handshake. A
/// request with credentials we cannot use under any scheme the server
/// named still answers — with an empty list — because §4.4.2 wants an
/// answer and silence would look like a truncated flight.
const ClientAuthFlight = struct {
    credentials: ?*const Credentials,
    scheme: ?backend.SignatureScheme,
    flight: []u8,
};

fn clientAuthFlight(self: *const ClientHandshake) ?ClientAuthFlight {
    if (!self.certificate_requested) return null;
    const usable = self.signable_count >= 1;
    return .{
        .credentials = if (usable) self.config.client_credentials else null,
        .scheme = if (usable) self.signable[0] else null,
        .flight = self.config.client_auth_flight,
    };
}

fn readCertificateRequest(self: *ClientHandshake, body: []const u8) Error!void {
    var cursor = wire.Cursor.init(body);
    const context_bytes = try cursor.takeByte();
    if (context_bytes != 0) return error.UnexpectedMessage;
    const extensions_bytes = try cursor.takeU16();
    const extensions = try cursor.takeSlice(extensions_bytes);
    if (cursor.remaining() != 0) return error.MalformedMessage;

    self.certificate_requested = true;
    const can_sign: []const backend.SignatureScheme = if (self.config.client_credentials) |credentials|
        credentials.signer.supported()
    else
        &.{};

    var seen_signature_algorithms = false;
    var extension_cursor = wire.Cursor.init(extensions);
    while (extension_cursor.remaining() != 0) {
        const extension_type = try extension_cursor.takeU16();
        const data = try extension_cursor.takeSlice(try extension_cursor.takeU16());
        if (extension_type != extension_signature_algorithms) continue;
        // §4.2: one of each. A duplicate is the peer contradicting
        // itself, and taking the first would be choosing which half to
        // believe.
        if (seen_signature_algorithms) return error.DuplicateExtension;
        seen_signature_algorithms = true;
        var list = wire.Cursor.init(data);
        const list_bytes = try list.takeU16();
        var schemes = wire.Cursor.init(try list.takeSlice(list_bytes));
        if (list.remaining() != 0) return error.MalformedExtension;
        while (schemes.remaining() != 0) {
            const wire_scheme = try schemes.takeU16();
            const scheme = backend.SignatureScheme.fromWire(wire_scheme) orelse continue;
            for (can_sign) |ours| {
                if (ours != scheme) continue;
                // The server's order is the server's preference, and
                // §4.4.2 leaves the choice to us among what it allows —
                // so first match wins and duplicates are skipped.
                for (self.signable[0..self.signable_count]) |already| {
                    if (already == scheme) break;
                } else if (self.signable_count < self.signable.len) {
                    self.signable[self.signable_count] = scheme;
                    self.signable_count += 1;
                }
            }
        }
    }
    // §4.3.2: "The 'signature_algorithms' extension MUST be specified".
    // A request without one asks for a signature under no algorithm.
    if (!seen_signature_algorithms) return error.MissingExtension;
}

fn drainFlight(self: *ClientHandshake, arm: anytype, out: []u8) Error!?Event {
    assert(self.inFlight());
    var messages_seen: u8 = 0;
    while (try self.assembler.next()) |message| : (messages_seen += 1) {
        assert(messages_seen < 8); // EE, Certificate, CertificateVerify, Finished.
        switch (message.messageType() orelse return error.UnexpectedMessage) {
            .encrypted_extensions => {
                if (self.state != .awaiting_encrypted_extensions) return error.UnexpectedMessage;
                try self.checkEncryptedExtensions(message.body());
                arm.transcript.update(message.bytes);
                // §Appendix A.1's fork. §4.3.2 forbids a
                // CertificateRequest under a PSK and §4.4.2 the
                // Certificate with it, so a resumed session leaves WAIT_EE
                // for WAIT_FINISHED and never passes through a state that
                // accepts either. That missing edge is the authentication
                // gap this refactor deletes rather than guards.
                self.state = if (self.resumed)
                    .awaiting_finished
                else
                    .awaiting_certificate_or_request;
            },
            // §4.3.2, and optional: the server may go straight to its
            // Certificate. Arriving here is the only way to WAIT_CERT,
            // which is why a second one has nowhere to land.
            .certificate_request => {
                if (self.state != .awaiting_certificate_or_request) return error.UnexpectedMessage;
                try self.readCertificateRequest(message.body());
                arm.transcript.update(message.bytes);
                self.state = .awaiting_certificate;
            },
            .certificate => {
                switch (self.state) {
                    .awaiting_certificate_or_request, .awaiting_certificate => {},
                    else => return error.UnexpectedMessage,
                }
                try self.peer.capture(message.body(), .{
                    .policy = self.config.certificate_policy,
                    .chain_verifier = self.config.chain_verifier,
                });
                arm.transcript.update(message.bytes);
                self.state = .awaiting_certificate_verify;
            },
            .certificate_verify => {
                // §4.4.3 signs what §4.4.2 presented. WAIT_CV is
                // reachable only from a Certificate and is left by this
                // message, so "no Certificate yet" and "a second copy"
                // are both simply not this state — the two guards that
                // used to say so, one of which was a remote panic before
                // it was written, are the transition.
                if (self.state != .awaiting_certificate_verify) return error.UnexpectedMessage;
                try self.peer.verify(message, .{
                    .policy = self.config.certificate_policy,
                    .side = .server,
                    .transcript_hash = &arm.transcriptHash(),
                    .accepted = self.config.verify_schemes,
                });
                arm.transcript.update(message.bytes);
                self.state = .awaiting_finished;
            },
            // Deliberately not restricted to WAIT_FINISHED.
            // `.insecure_no_verification` lets a server skip the
            // certificate leg outright, and which fault a Finished
            // standing in the wrong place earns — `unexpected_message`
            // for an inverted flight, `bad_certificate` for one that
            // never authenticated — is a policy question that already
            // lives in `completeHandshake`. Moving it here would change
            // the alert, which BoGo grades.
            .finished => return try self.completeHandshake(arm, message, out),
            else => return error.UnexpectedMessage,
        }
    }
    return null;
}

/// §4.2: EncryptedExtensions carries only extensions the client offered
/// *and* that §4.2's table permits there. A client receiving any other
/// "MUST abort the handshake with an unsupported_extension alert".
///
/// The intersection is small, which is the point — of everything zssl
/// offers, only `server_name`, `supported_groups` and ALPN are legal
/// here. `key_share`, `supported_versions` and `pre_shared_key` are
/// offered but belong to ServerHello, so seeing one here is as
/// unsolicited as an extension we never sent at all.
///
/// This ignored every extension but ALPN until BoGo's finding 2 was
/// measured: a server could hand our client anything it liked and we
/// took it.
fn checkEncryptedExtensions(self: *ClientHandshake, body: []const u8) Error!void {
    var cursor = wire.Cursor.init(body);
    const extensions_bytes = try cursor.takeU16();
    // Trailing bytes after the extension block are a framing fault, and
    // §6.2 calls that decode_error: the message could not be decoded,
    // rather than arriving at the wrong moment.
    if (extensions_bytes != cursor.remaining()) return error.MalformedMessage;
    // §4.2's duplicate rule is about the block being well formed, so it
    // is answered over the whole block before the question of whether we
    // asked for any of it. The other order collapses decode_error into
    // unsupported_extension — the loop refuses the first unrecognised
    // copy and never reaches the second — which is the same trap the
    // server_name ack below documents, and is what BoGo's
    // `DuplicateExtensionClient-TLS-TLS13` measured.
    try wire.refuseDuplicateExtensions(8, cursor.rest());
    var extensions_seen: u8 = 0;
    while (cursor.remaining() > 0) : (extensions_seen += 1) {
        if (extensions_seen == 8) return error.UnexpectedMessage;
        assert(extensions_seen < 8);
        const extension_type = try cursor.takeU16();
        const data = try cursor.takeSlice(try cursor.takeU16());
        switch (extension_type) {
            0 => { // server_name
                // RFC 6066 §3: the ack is empty. Bytes after it are a
                // framing error, and that verdict has to come *before*
                // the solicitation check below — BoGo wants decode_error
                // for a malformed ack and unsupported_extension for a
                // well-formed one we never asked for, and checking
                // solicitation first would collapse the two.
                if (data.len != 0) return error.MalformedExtension;
                if (self.config.server_name == null) return error.UnsupportedExtension;
            },
            10 => {}, // supported_groups: legal here, always offered, advisory.
            16 => try self.selectAlpn(data), // application_layer_protocol_negotiation
            42 => { // early_data — §4.2.10's acceptance, and the only one
                // §4.2.10 gives it no body here, as in a ClientHello.
                if (data.len != 0) return error.MalformedExtension;
                // §4.2: an extension we did not offer is unsolicited,
                // and this one is worse than merely unasked — a server
                // "accepting" 0-RTT we never sent would have us send an
                // EndOfEarlyData under keys that do not exist.
                if (!self.early_data_offered) return error.UnsupportedExtension;
                // A retry withdraws the offer (§4.1.2), so an
                // acceptance after one answers a hello that never asked.
                if (self.retried) return error.UnsupportedExtension;
                self.early_data_accepted = true;
            },
            else => return error.UnsupportedExtension,
        }
    }
}

/// RFC 7301 §3.2: the server names exactly one protocol, and it must be
/// one of ours. Split out because the order of its two refusals matters:
/// a well-formed selection when we offered no ALPN at all is the whole
/// extension being unsolicited (§4.2), not a bad choice within it.
fn selectAlpn(self: *ClientHandshake, data: []const u8) Error!void {
    var list = wire.Cursor.init(data);
    const list_bytes = try list.takeU16();
    if (list_bytes != list.remaining()) return error.BadAlpn;
    const name = try list.takeSlice(try list.takeByte());
    if (list.remaining() != 0) return error.BadAlpn;
    if (self.config.alpn_protocols.len == 0) return error.UnsupportedExtension;
    self.alpn_selected = for (self.config.alpn_protocols, 0..) |ours, index| {
        if (std.mem.eql(u8, name, ours)) break @intCast(index);
    } else return error.BadAlpn;
}

fn completeHandshake(self: *ClientHandshake, arm: anytype, message: handshake.Message, out: []u8) Error!Event {
    assert(self.inFlight());
    if (!self.resumed) {
        // Policy says who may skip the certificate leg: only a session a
        // PSK already authenticates.
        if (self.config.certificate_policy == .leaf_signature) {
            // A Certificate arrived and no CertificateVerify followed:
            // §4.4 fixes that order, so the Finished is standing where a
            // mandatory message should have been. That is a different
            // fault from a certificate we would not accept, and BoGo's
            // `ServerSkipCertificateVerify` is the case that tells them
            // apart.
            if (self.peer.seen and !self.peer.verified) return error.UnexpectedMessage;
            if (!self.peer.verified) return error.BadCertificate;
        }
    }
    if (!self.assembler.empty()) return error.UnexpectedMessage;
    const send_ccs = self.config.send_change_cipher_spec and !self.ccs_sent;
    // The offer's keys travel only if the server took it. A declined
    // offer leaves them unused, which is the whole cost of 0-RTT going
    // unanswered — the data was sent and nobody read it.
    // A server may accept an offer whose keys we failed to build:
    // `start` writes the extension before `startEarlyKeys` runs and
    // deliberately keeps the offer standing if it fails. §4.5's
    // EndOfEarlyData has to go out under those keys, so there is no
    // flight we can honestly send — and unwrapping here made a
    // *compliant* server's acceptance a panic. The comment in `start`
    // promised this degraded gracefully; it did not.
    if (self.early_data_accepted and self.early_send == null) return error.LibcryptoFailed;
    const early: ?*protect.Protector = if (self.early_data_accepted) &self.early_send.? else null;
    const flight = try arm.finishHandshake(message, send_ccs, self.clientAuthFlight(), early, out);
    if (self.early_send) |*protector| {
        protector.deinit();
        self.early_send = null;
    }
    if (send_ccs) self.ccs_sent = true;
    self.state = .connected;
    // The invariant this function exists to enforce, stated where a
    // reader can check it: nothing reaches `connected` unauthenticated.
    assert(self.resumed or self.peer.verified or
        self.config.certificate_policy == .insecure_no_verification);
    assert(flight.len >= record.header_bytes);
    return .{ .connected = flight };
}

/// The next event from a record already handed to `handleRecord`.
///
/// One record may carry more than one post-handshake message — a
/// NewSessionTicket packed with a KeyUpdate is what Go and OpenSSL emit
/// — so `handleRecord` returns the first and this returns the rest. Call
/// it until it answers null.
///
/// Null means one thing only: the assembler holds no further complete
/// message. It never means "the last message resolved to nothing" —
/// that is `nextPostHandshake`'s job to skip past, and inferring the
/// end from a dispatch result is docs/BOGO.md finding 1.
///
/// Every event borrows `out`, this one included, so consume an event
/// before asking for the next: a ticket's bytes live in the reassembly
/// buffer and a `.send`'s live in `out`, and the next call may reuse
/// either.
pub fn drain(self: *ClientHandshake, out: []u8) Error!?Event {
    assert(out.len >= out_bytes_min);
    // Only the post-handshake stream is drained. The server's flight is
    // assembled by `drainFlight`, which already reads every message a
    // record carried.
    if (self.inFlight()) return null;
    if (!self.readable()) return null;
    if (self.ladder == null) return null;
    errdefer self.state = .failed;
    switch (self.ladder.?) {
        inline else => |*arm| return self.nextPostHandshake(arm, out),
    }
}

/// The next post-handshake message that has something to say, or null
/// once the assembler holds no more complete ones.
///
/// The skipping is the point, and it is where finding 1 was made once
/// already. A KeyUpdate can be consumed and produce nothing —
/// `update_not_requested`, or one arriving after our own close_notify —
/// and handing that back as an event would end a `while (event) |ready|`
/// loop on a message that was not the last, stranding whatever the peer
/// packed behind it. An order the peer chooses, so the strand is
/// reachable from the wire. Null still comes only from
/// `assembler.next()`, and both roles reach it through here.
///
/// Bounded by the flood ceiling rather than by a number chosen here:
/// every silent message is a KeyUpdate, since `dispatchPostHandshake`
/// answers a NewSessionTicket with one and refuses each other type, and
/// `observeKeyUpdate` fails the 33rd in a row.
fn nextPostHandshake(self: *ClientHandshake, arm: anytype, out: []u8) Error!?Event {
    assert(self.readable());
    var silent: u8 = 0;
    while (try self.assembler.next()) |message| : (silent += 1) {
        assert(silent <= flood.key_updates_max);
        if (try self.dispatchPostHandshake(arm, message, out)) |event| return event;
    }
    return null;
}

/// One post-handshake message, already pulled from the assembler. Null
/// is a message consumed in silence, never "no more messages" — see
/// `nextPostHandshake`, which is the only caller and the only place
/// allowed to tell those apart.
fn dispatchPostHandshake(
    self: *ClientHandshake,
    arm: anytype,
    message: handshake.Message,
    out: []u8,
) Error!?Event {
    switch (message.messageType() orelse return error.UnexpectedMessage) {
        .new_session_ticket => {
            var ticket = try parseTicket(message.body());
            ticket.suite = self.ladder.?;
            return .{ .ticket = ticket };
        },
        .key_update => {
            // Counted before the rotation, because deriving the next
            // generation is the work a flood is buying (flood.zig).
            try self.flood_guard.observeKeyUpdate();
            const response = try arm.session.?.processKeyUpdate(message.body(), out);
            // §6.1: nothing goes out after our own close_notify, a
            // requested KeyUpdate included. The receive side still
            // rotated, which is what lets us read on to the peer's
            // close_notify.
            if (self.state == .close_sent) return null;
            if (response) |sealed| return .{ .send = sealed };
            return null;
        },
        else => return error.UnexpectedMessage,
    }
}

/// §4.6.1's `extensions<0..2^16-2>` on a NewSessionTicket. zssl uses
/// none of them — no early data, no resumption_across_names — but a
/// block we ignore is not a block we may leave unread: an extension
/// whose body does not parse is a malformed message whether or not its
/// meaning would have changed anything, and skipping the block was
/// finding 7.
///
/// §4.2's duplicate rule applies to this block like any other, so the
/// same pre-pass finding 9 added runs here first.
fn checkTicketExtensions(block: []const u8) Error!?u32 {
    try wire.refuseDuplicateExtensions(ticket_extensions_max, block);
    var cursor = wire.Cursor.init(block);
    var early_data_bytes_max: ?u32 = null;
    var seen: u16 = 0;
    while (cursor.remaining() > 0) : (seen += 1) {
        if (seen == ticket_extensions_max) return error.ExtensionOverflow;
        assert(seen < ticket_extensions_max);
        const extension_type = try cursor.takeU16();
        const data = try cursor.takeSlice(try cursor.takeU16());
        // Only the ones with a grammar we can hold them to. An unknown
        // extension's body is opaque by definition and there is nothing
        // to check it against.
        if (extension_type == extension_tls_flags) try checkTlsFlags(data);
        if (extension_type == extension_early_data) {
            // §4.6.1 gives it `uint32 max_early_data_size` here, where a
            // ClientHello gives it nothing at all — the one extension in
            // this library whose shape depends on the message carrying
            // it, and the reason reading the block is not optional.
            var body = wire.Cursor.init(data);
            early_data_bytes_max = try body.takeU32();
            if (body.remaining() != 0) return error.MalformedMessage;
        }
    }
    assert(cursor.remaining() == 0);
    return early_data_bytes_max;
}

/// The `tls_flags` extension: `flags<1..255>`, one bit per flag, and the
/// encoding must be minimal — a trailing zero byte carries no flag and
/// so must not be there. From draft-ietf-tls-tlsflags, and cited without
/// a section number on purpose: what this was actually written against
/// is BoringSSL's `flagSet.unmarshalExtensionValue`
/// (`ssl/test/runner/handshake_messages.go`), which is the oracle that
/// checks it and is pinned by digest in bogo/run.zig.
///
/// The two refusals answer differently on purpose, which is what BoGo
/// measures. An empty or over-long list is framing that does not parse:
/// §6.2's decode_error. A list that parses but ends in a zero byte is
/// well-framed and says something the grammar forbids, which is an
/// illegal parameter rather than a decode failure.
fn checkTlsFlags(data: []const u8) Error!void {
    var cursor = wire.Cursor.init(data);
    const flag_bytes = try cursor.takeByte();
    if (flag_bytes == 0) return error.MalformedExtension;
    const flags = try cursor.takeSlice(flag_bytes);
    if (cursor.remaining() != 0) return error.MalformedExtension;
    assert(flags.len >= 1);
    if (flags[flags.len - 1] == 0) return error.NonMinimalEncoding;
}

fn parseTicket(body: []const u8) Error!Ticket {
    var cursor = wire.Cursor.init(body);
    var ticket: Ticket = undefined;
    ticket.lifetime_s = try cursor.takeU32();
    ticket.age_add = try cursor.takeU32();
    const nonce_bytes = try cursor.takeByte();
    // §4.6.1 writes `ticket_nonce<0..255>`, so an empty nonce is inside
    // the grammar and this is zssl's policy rather than the RFC's: a
    // nonce is what a resumption PSK is derived from, and one with no
    // bytes has nothing to distinguish it. The sibling below *is* the
    // grammar — `ticket<1..2^16-1>` has a floor of one.
    if (nonce_bytes == 0) return error.MalformedMessage;
    ticket.nonce = try cursor.takeSlice(nonce_bytes);
    const ticket_bytes = try cursor.takeU16();
    if (ticket_bytes == 0) return error.MalformedMessage;
    // §4.2.11 lets an identity run to 2^16-1 and the size is the issuing
    // server's choice, but a ticket we could never fit back into a
    // ClientHello is one we must not hand the embedder: it stores what
    // we give it, offers it back, and the encoder's bound would then be
    // an abort three flights later. Refused here, where the answer is an
    // alert and the connection simply does not resume.
    if (ticket_bytes > client_messages.psk_identity_bytes_max) return error.MalformedMessage;
    ticket.ticket = try cursor.takeSlice(ticket_bytes);
    const extensions_bytes = try cursor.takeU16();
    const extensions = try cursor.takeSlice(extensions_bytes);
    if (cursor.remaining() != 0) return error.MalformedMessage;
    ticket.early_data_bytes_max = try checkTicketExtensions(extensions);
    assert(ticket.nonce.len >= 1);
    assert(ticket.ticket.len >= 1);
    return ticket;
}

/// §4.6.1: the PSK a captured ticket's nonce stands for — the embedder
/// stores it beside the ticket for the next `Config.resume_session`.
pub fn resumptionPsk(
    self: *const ClientHandshake,
    ticket_nonce: []const u8,
    out: *[cipher_suite.hash_bytes_max]u8,
) []const u8 {
    assert(self.writable());
    assert(ticket_nonce.len >= 1);
    switch (self.ladder.?) {
        inline else => |*arm, comptime_suite| {
            const Schedule = key_schedule.KeySchedule(comptime_suite);
            const psk = Schedule.resumptionPsk(&arm.resumption_master, ticket_nonce);
            @memcpy(out[0..psk.len], &psk);
            return out[0..psk.len];
        },
    }
}

pub fn sendApplicationData(self: *ClientHandshake, bytes: []const u8, out: []u8) Error![]const u8 {
    assert(self.writable());
    assert(bytes.len <= record.plaintext_bytes_max);
    errdefer self.state = .failed;
    switch (self.ladder.?) {
        inline else => |*arm| return arm.session.?.sealApplicationData(bytes, out),
    }
}

pub fn sendClose(self: *ClientHandshake, out: []u8) Error![]const u8 {
    assert(self.writable());
    errdefer self.state = .failed;
    const bytes = alert.encode(.close_notify);
    switch (self.ladder.?) {
        inline else => |*arm| {
            const sealed = try arm.session.?.send.seal(.alert, &bytes, out);
            self.state = self.afterCloseSent();
            return sealed;
        },
    }
}

/// Encode one alert under whatever keys are live — application,
/// handshake, or none yet — and retire the machine. The mirror of
/// `ServerHandshake.sendAlert`, and there for the same reason: a peer we
/// refuse should read a description rather than a reset. zssl still
/// chooses no alerts of its own; it returns errors, and the embedder
/// decides. Answers an empty slice when nothing can be sealed.
pub fn sendAlert(self: *ClientHandshake, description: alert.Description, out: []u8) []const u8 {
    assert(out.len >= alert_bytes_min);
    // Callable in every state, `closed` included: §6.1 lets each side
    // close its own direction, so an embedder answering a peer's
    // close_notify with one of its own is doing the ordinary thing. The
    // send protector outlives the peer's alert, so the seal still works.
    const body = alert.encode(description);
    // A close_notify here closes our write side on the same terms as
    // `sendClose`; anything else retires the machine outright.
    if (description == .close_notify) {
        self.state = self.afterCloseSent();
    } else {
        self.state = .failed;
    }
    if (self.ladder) |*ladder| switch (ladder.*) {
        inline else => |*arm| {
            if (arm.session) |*session| {
                return session.send.seal(.alert, &body, out) catch out[0..0];
            }
            if (arm.send) |*protector| {
                // Mid-handshake: this alert is our first protected record,
                // so D.4's dummy record has to lead it or a peer in
                // compatibility mode reads the alert as the ChangeCipherSpec
                // it was still waiting for.
                var builder = wire.Builder.init(out);
                if (self.config.send_change_cipher_spec and !self.ccs_sent) {
                    builder.putSlice(&server_messages.change_cipher_spec_record);
                    self.ccs_sent = true;
                }
                const sealed = protector.seal(.alert, &body, builder.bytes[builder.index..]) catch
                    return out[0..0];
                builder.index += sealed.len;
                return builder.written();
            }
        },
    };
    // Before the ServerHello there are no keys, so §5.1 plaintext it is.
    var builder = wire.Builder.init(out);
    appendPlaintextRecord(&builder, .alert, &body);
    return builder.written();
}

/// `out` for `sendAlert`: payload, inner content type, and AEAD tag over
/// a record header — plus room for D.4's dummy ChangeCipherSpec, which a
/// mid-handshake alert carries in front of it.
pub const alert_bytes_min: u8 = @intCast(server_messages.change_cipher_spec_record.len +
    record.header_bytes + alert.bytes + 1 + cipher_suite.tag_bytes);

pub fn sendKeyUpdate(self: *ClientHandshake, request_update: bool, out: []u8) Error![]const u8 {
    assert(self.writable());
    assert(out.len >= record.header_bytes + handshake.header_bytes + 1 + 256);
    errdefer self.state = .failed;
    switch (self.ladder.?) {
        inline else => |*arm| return arm.session.?.initiateKeyUpdate(request_update, out),
    }
}

pub const Direction = session_keys.Direction;

/// The kTLS hand-over, current as of the latest §4.6.3 generation.
pub fn exportKeyMaterial(self: *const ClientHandshake, direction: Direction) ktls.KeyMaterial {
    // Not `writable()`: handing a half-closed connection to the kernel
    // would hand it a direction that is already over.
    assert(self.state == .connected);
    switch (self.ladder.?) {
        inline else => |*arm| return arm.session.?.exportMaterial(direction),
    }
}

/// RFC 5705 keying material, through RFC 8446 §7.5's construction. See
/// `ServerHandshake.exporter` for what it is and why the name is close
/// to `exportKeyMaterial`'s without being related to it.
///
/// Available from `connected` and no earlier. A client that is still
/// sending 0-RTT has no exporter: §7.5's secret comes from a transcript
/// that includes the server's Finished, which it has not seen — and the
/// early_exporter_master that *would* answer is a different secret with
/// weaker properties, which this library does not derive.
pub fn exporter(
    self: *const ClientHandshake,
    label: []const u8,
    context: []const u8,
    out: []u8,
) Error!void {
    assert(label.len <= key_schedule.exporter_label_bytes_max);
    assert(out.len >= 1);
    if (self.state != .connected and self.state != .close_sent) return error.HandshakeNotComplete;
    switch (self.ladder.?) {
        inline else => |*arm, tag| {
            const Schedule = key_schedule.KeySchedule(tag);
            Schedule.exporter(&arm.exporter_master, label, context, out);
        },
    }
}

fn appendPlaintextRecord(builder: *wire.Builder, content_type: record.ContentType, payload: []const u8) void {
    assert(payload.len >= 1);
    assert(payload.len <= record.plaintext_bytes_max);
    record.writeHeader(
        .{ .content_type = content_type, .length = @intCast(payload.len) },
        builder.bytes[builder.index..][0..record.header_bytes],
    );
    builder.index += record.header_bytes;
    builder.putSlice(payload);
}

const Ladder = union(CipherSuite) {
    aes_128_gcm_sha256: ArmOf(.aes_128_gcm_sha256),
    aes_256_gcm_sha384: ArmOf(.aes_256_gcm_sha384),
    chacha20_poly1305_sha256: ArmOf(.chacha20_poly1305_sha256),

    fn initFor(suite: CipherSuite) Ladder {
        return switch (suite) {
            .aes_128_gcm_sha256 => .{ .aes_128_gcm_sha256 = .empty },
            .aes_256_gcm_sha384 => .{ .aes_256_gcm_sha384 = .empty },
            .chacha20_poly1305_sha256 => .{ .chacha20_poly1305_sha256 = .empty },
        };
    }
};

/// The suite-typed half, client roles: transmit under the client
/// secrets, receive under the server's.
fn ArmOf(comptime suite: CipherSuite) type {
    const Hash = CipherSuite.HashType(suite);
    const Schedule = key_schedule.KeySchedule(suite);
    const Transcript = transcript.Transcript(Hash);
    const hash_bytes = Hash.digest_length;

    return struct {
        transcript: Transcript,
        schedule: ?Schedule,
        client_handshake_traffic: [hash_bytes]u8,
        server_handshake_traffic: [hash_bytes]u8,
        /// §7.5's exporter base, `Derive-Secret(Master, "exp master",
        /// ClientHello..server Finished)`. Derived with the application
        /// secrets, because that is where the transcript it names is
        /// complete.
        exporter_master: [hash_bytes]u8,
        resumption_master: [hash_bytes]u8,
        recv: ?protect.Protector,
        send: ?protect.Protector,
        session: ?session_keys.SessionKeys(suite),

        const Self = @This();

        pub const empty: Self = .{
            .transcript = .empty,
            .schedule = null,
            .client_handshake_traffic = undefined,
            .server_handshake_traffic = undefined,
            .exporter_master = undefined,
            .resumption_master = undefined,
            .recv = null,
            .send = null,
            .session = null,
        };

        fn deinit(self: *Self) void {
            if (self.recv) |*protector| protector.deinit();
            if (self.send) |*protector| protector.deinit();
            if (self.session) |*session| session.deinit();
            if (self.schedule) |*schedule| schedule.wipe();
            std.crypto.secureZero(u8, &self.client_handshake_traffic);
            std.crypto.secureZero(u8, &self.server_handshake_traffic);
            std.crypto.secureZero(u8, &self.exporter_master);
            std.crypto.secureZero(u8, &self.resumption_master);
            self.* = undefined;
        }

        /// §4.4.1: after a HelloRetryRequest, CH1 is replaced in the
        /// transcript by a synthetic message_hash message. The server
        /// half carries the same routine — the surgery is symmetric,
        /// because both sides have to arrive at one transcript.
        fn absorbRetryClientHello(self: *Self, ch1: []const u8, hrr: []const u8) void {
            assert(self.transcript.messages_seen == 0);
            assert(ch1.len >= handshake.header_bytes);
            var ch1_hash: [hash_bytes]u8 = undefined;
            Hash.hash(ch1, &ch1_hash, .{});
            const synthetic_header = [handshake.header_bytes]u8{
                @intFromEnum(handshake.MessageType.message_hash),
                0,
                0,
                hash_bytes,
            };
            self.transcript.state.update(&synthetic_header);
            self.transcript.state.update(&ch1_hash);
            self.transcript.messages_seen = 1;
            self.transcript.update(hrr);
        }

        fn transcriptHash(self: *const Self) [hash_bytes]u8 {
            return self.transcript.currentHash();
        }

        /// `shared` is a slice, not a `*const [32]u8`: §7.4 makes the
        /// (EC)DHE secret the group's own width, and a retried handshake
        /// can land on secp384r1's 48 bytes. The server half has always
        /// taken a slice here for the same reason.
        fn startHandshakeKeys(self: *Self, shared: []const u8, psk: ?[]const u8) protect.Error!void {
            assert(self.schedule == null);
            assert(self.recv == null);
            // The client offers only resumption PSKs, which §4.6.1
            // derives at exactly a hash length — see
            // `ServerHandshake.startHandshakeKeys` for the accepting
            // half, where an external PSK makes this a range.
            if (psk) |bytes| assert(bytes.len == hash_bytes);
            var schedule = Schedule.initEarly(psk);
            schedule.advanceToHandshake(shared);
            const hello_hash = self.transcriptHash();
            self.client_handshake_traffic = schedule.deriveAt(.handshake, "c hs traffic", &hello_hash);
            self.server_handshake_traffic = schedule.deriveAt(.handshake, "s hs traffic", &hello_hash);
            const receive_keys = Schedule.trafficKeys(&self.server_handshake_traffic);
            const transmit_keys = Schedule.trafficKeys(&self.client_handshake_traffic);
            self.recv = try protect.Protector.init(suite, &receive_keys.key, &receive_keys.iv);
            errdefer {
                self.recv.?.deinit();
                self.recv = null;
            }
            self.send = try protect.Protector.init(suite, &transmit_keys.key, &transmit_keys.iv);
            self.schedule = schedule;
        }

        /// Verify the server Finished, answer with ours, move to the
        /// application keys — the whole §4.4.4 tail in transcript order.
        /// `early` is the 0-RTT protector when the server accepted, and
        /// null otherwise — §4.5's EndOfEarlyData is the last thing it
        /// protects, and it goes out ahead of the Finished that switches
        /// back to the handshake keys.
        /// §4.4.2's Certificate and §4.4.3's CertificateVerify, sealed
        /// into the client flight before its Finished and absorbed into
        /// the transcript that Finished MACs.
        ///
        /// A client that was asked answers even to decline: an empty
        /// certificate_list rather than silence, which is what lets the
        /// server tell "no certificate" from a broken flight.
        ///
        /// Its own function because `finishHandshake` was 96 lines
        /// against TIGER_STYLE's 70-line limit and this was 46 of them —
        /// the same split the checking side already has in
        /// `peer_certificate.zig`.
        fn sendClientAuth(
            self: *Self,
            client_auth: ?ClientAuthFlight,
            builder: *wire.Builder,
        ) Error!void {
            const auth = client_auth orelse return;
            // Declining needs no chain buffer, and must not need one:
            // `client_auth_flight` is empty on every client that
            // never configured mTLS, and those are exactly the
            // clients a server can hand an unsolicited
            // CertificateRequest to. Building the refusal into
            // `auth.flight` panicked them — a remote assertion,
            // found by BoGo's `CertificateRequestInResumption`.
            var empty_storage: [handshake.header_bytes + 4]u8 = undefined;
            const certificate_message = if (auth.credentials) |credentials|
                server_messages.certificateChain(auth.flight, credentials.chain())
            else
                server_messages.certificateChain(&empty_storage, &.{});
            self.transcript.update(certificate_message);
            const sealed_certificate = try self.send.?.seal(
                .handshake,
                certificate_message,
                builder.bytes[builder.index..],
            );
            builder.index += sealed_certificate.len;

            // Only if we sent one. §4.4.3 signs the certificate that
            // was presented, and an empty list presented nothing.
            if (auth.credentials) |credentials| if (auth.scheme) |scheme| {
                var content_buffer: [server_messages.certificate_verify_content_bytes_max]u8 = undefined;
                const to_sign = server_messages.certificateVerifyContent(
                    .client,
                    &self.transcriptHash(),
                    &content_buffer,
                );
                var signature_buffer: [backend.signature_bytes_max]u8 = undefined;
                const signature = try credentials.signer.sign(scheme, to_sign, &signature_buffer);
                const verify_message = server_messages.certificateVerify(
                    auth.flight,
                    @intFromEnum(scheme),
                    signature,
                );
                self.transcript.update(verify_message);
                const sealed_verify = try self.send.?.seal(
                    .handshake,
                    verify_message,
                    builder.bytes[builder.index..],
                );
                builder.index += sealed_verify.len;
            };
        }

        fn finishHandshake(
            self: *Self,
            message: handshake.Message,
            send_ccs: bool,
            client_auth: ?ClientAuthFlight,
            early: ?*protect.Protector,
            out: []u8,
        ) Error![]const u8 {
            assert(self.schedule != null);
            assert(self.schedule.?.stage == .handshake);
            // §4.4.4 gives one verdict to both ways a Finished can be
            // wrong — see `verifyClientFinished` on the server side for
            // why this is decrypt_error and not §6.2's decode_error, and
            // for the two corpora that disagree about it.
            if (message.body().len != hash_bytes) return error.DecryptError;
            const server_key = Schedule.finishedKey(&self.server_handshake_traffic);
            const expected = Schedule.verifyData(&server_key, &self.transcriptHash());
            if (!std.crypto.timing_safe.eql([hash_bytes]u8, message.body()[0..hash_bytes].*, expected)) {
                return error.DecryptError;
            }
            self.transcript.update(message.bytes);
            const finished_hash = self.transcriptHash();
            self.schedule.?.advanceToMaster();
            self.exporter_master = self.schedule.?.deriveAt(.master, "exp master", &finished_hash);
            var client_application = self.schedule.?.deriveAt(.master, "c ap traffic", &finished_hash);
            var server_application = self.schedule.?.deriveAt(.master, "s ap traffic", &finished_hash);
            // `SessionKeys` takes its own copies and owns rotation from
            // here; ours are generation-0 material with no further use.
            defer std.crypto.secureZero(u8, &client_application);
            defer std.crypto.secureZero(u8, &server_application);

            var builder = wire.Builder.init(out);
            if (send_ccs) builder.putSlice(&server_messages.change_cipher_spec_record);
            // §4.5, under the *early* keys — the last thing they protect
            // — and into the transcript, which is why `verify_data`
            // below reads the current hash rather than `finished_hash`.
            // §4.4 puts EndOfEarlyData in the client's handshake context
            // and §7.1 leaves it out of the application secrets derived
            // above, so the two diverge here and nowhere else. With no
            // early data the hashes are equal and this is a no-op.
            if (early) |protector| {
                const end_of_early_data = [_]u8{
                    @intFromEnum(handshake.MessageType.end_of_early_data),
                    0,
                    0,
                    0,
                };
                self.transcript.update(&end_of_early_data);
                const sealed_end = try protector.seal(
                    .handshake,
                    &end_of_early_data,
                    builder.bytes[builder.index..],
                );
                builder.index += sealed_end.len;
            }
            try self.sendClientAuth(client_auth, &builder);
            const client_key = Schedule.finishedKey(&self.client_handshake_traffic);
            const verify_data = Schedule.verifyData(&client_key, &self.transcriptHash());
            var message_buffer: [handshake.header_bytes + cipher_suite.hash_bytes_max]u8 = undefined;
            const finished_message = server_messages.finished(&message_buffer, &verify_data);
            self.transcript.update(finished_message);
            self.resumption_master = self.schedule.?.deriveAt(.master, "res master", &self.transcriptHash());

            const sealed = try self.send.?.seal(.handshake, finished_message, builder.bytes[builder.index..]);
            builder.index += sealed.len;

            // Zero: a client has no 0.5-RTT window. Its own Finished
            // is the last thing it writes under the handshake keys, and
            // nothing goes out on the application ones until the
            // session exists.
            self.session = try session_keys.SessionKeys(suite).init(
                &client_application,
                &server_application,
                0,
            );
            self.recv.?.deinit();
            self.send.?.deinit();
            self.recv = null;
            self.send = null;
            return builder.written();
        }
    };
}

test "§4.6.1: a NewSessionTicket's extension block is checked, not skipped" {
    // Finding 7. zssl acts on none of these extensions, and a block we
    // ignore was a block we left unread — an extension whose body does
    // not parse is a malformed message whether or not its meaning would
    // have changed anything.
    //
    // The two refusals differ on purpose. Framing that does not parse is
    // decode_error; a flag list that parses and then ends in a zero byte
    // is well-framed and says something draft-ietf-tls-tlsflags forbids,
    // which is an illegal parameter.
    const tls_flags: u16 = 62;

    // A NewSessionTicket carrying exactly one extension, built in a
    // fixed buffer — this tree has no allocator and its tests do not
    // get one either.
    const build = struct {
        fn ticket(out: []u8, extension_type: u16, body: []const u8) []const u8 {
            var b = wire.Builder.init(out);
            b.putU32(7200); // lifetime
            b.putU32(0); // age_add
            b.putByte(1); // ticket_nonce<1>
            b.putByte(0);
            b.putU16(1); // ticket<1>
            b.putByte(0xaa);
            b.putU16(@intCast(4 + body.len)); // extensions<>
            b.putU16(extension_type);
            b.putU16(@intCast(body.len));
            b.putSlice(body);
            return b.written();
        }
    };

    var buffer: [64]u8 = undefined;
    const Case = struct { name: []const u8, body: []const u8, want: anyerror };
    for ([_]Case{
        // flags<1..255> with a zero-length list.
        .{ .name = "empty", .body = &.{0}, .want = error.MalformedExtension },
        // A set flag followed by a padding byte that carries none.
        .{ .name = "non-minimal", .body = &.{ 2, 0x02, 0x00 }, .want = error.NonMinimalEncoding },
        // The length prefix disagreeing with what follows it.
        .{ .name = "trailing", .body = &.{ 1, 0x02, 0x99 }, .want = error.MalformedExtension },
        .{ .name = "truncated", .body = &.{ 2, 0x02 }, .want = error.Truncated },
    }) |case| {
        const bytes = build.ticket(&buffer, tls_flags, case.body);
        std.testing.expectError(case.want, parseTicket(bytes)) catch |err| {
            std.debug.print("case '{s}' did not refuse as expected\n", .{case.name});
            return err;
        };
    }

    // A well-formed list is accepted, including bits we do not know: an
    // unknown flag is not a malformed one, which is what BoGo's
    // `UnknownTicketFlags` cases say and what this must not break.
    {
        const bytes = build.ticket(&buffer, tls_flags, &.{ 2, 0x01, 0x80 });
        const parsed = try parseTicket(bytes);
        try std.testing.expectEqual(@as(u32, 7200), parsed.lifetime_s);
    }

    // An extension zssl has no grammar for is opaque by definition, and
    // its body is left alone rather than guessed at.
    {
        const bytes = build.ticket(&buffer, 0xbaad, &.{ 0xde, 0xad, 0xbe, 0xef });
        const parsed = try parseTicket(bytes);
        try std.testing.expectEqual(@as(u32, 7200), parsed.lifetime_s);
    }
}
