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
//!   The PSK does not come along. §4.1.4 wants the second binder
//!   computed over §4.4.1's reconstructed transcript, which is the
//!   surgery the server half also leaves out, so a retried resumption
//!   drops the identity and degrades to a full handshake.
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
const der_bounds = @import("der_bounds.zig");
const cipher_suite = @import("cipher_suite.zig");
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
/// Whether this session came up on our offered PSK.
resumed: bool,
/// True once the leaf's CertificateVerify checked out under the policy.
certificate_verified: bool,
/// True once the peer's Certificate message was seen. Tracked apart from
/// the captured key because `.insecure_no_verification` captures no key
/// and the flight's ordering still has to be checked.
certificate_seen: bool,
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

const ClientHandshake = @This();

/// An RSA-4096 `RSAPublicKey` — two INTEGERs and a SEQUENCE header — is
/// the largest key we accept; the uncompressed P-384 SEC1 point that
/// bounds the EC side is 97.
const leaf_public_key_bytes_max: u16 = 560;

const LeafKeyKind = enum { none, ecdsa, rsa };

/// draft-ietf-tls-tlsflags. Not a flag zssl acts on — the extension is
/// validated and dropped — but §4.6.1's block is checked rather than
/// skipped, so its grammar has to be known.
const extension_tls_flags: u16 = 62;

/// A NewSessionTicket's extension block is short by nature: early data,
/// flags, and whatever a future draft adds. The bound is a refusal, not
/// an invariant.
const ticket_extensions_max: u16 = 16;

pub const State = enum(u8) {
    idle,
    awaiting_server_hello,
    awaiting_flight,
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

pub const CertificatePolicy = enum {
    /// Verify CertificateVerify against the leaf's own public key —
    /// ECDSA P-256/P-384 or RSA-PSS. Chain and name validation remain the
    /// embedder's (DESIGN.md §1); see `Config.chain_verifier`.
    leaf_signature,
    /// No certificate checks at all. For tests and pinned transports.
    insecure_no_verification,
};

pub const CertificateList = certificate_list.CertificateList;
pub const ChainVerifier = certificate_list.ChainVerifier;

pub const Resumption = struct {
    identity: []const u8,
    obfuscated_age: u32,
    psk: [cipher_suite.hash_bytes_max]u8,
    psk_bytes: u8,
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

pub const Error = backend.Error || protect.Error || session_keys.Error ||
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
    /// The certificate could not be read or its key is outside policy.
    BadCertificate,
    /// CertificateVerify did not verify against the leaf.
    BadSignature,
    /// The server's Finished MAC did not verify.
    DecryptError,
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
    if (config.resume_session) |resumption| {
        assert(resumption.psk_bytes == 32 or resumption.psk_bytes == 48);
        assert(resumption.identity.len >= 1);
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
        .resumed = false,
        .certificate_verified = false,
        .certificate_seen = false,
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
    if (self.ladder) |*ladder| switch (ladder.*) {
        inline else => |*arm| arm.deinit(),
    };
    self.* = undefined;
}

const ccs_seen_max: u8 = 2;

/// Build and frame the opening ClientHello. The message is kept whole in
/// `hello_storage`: the transcript can only absorb it once the server
/// has picked a suite.
pub fn start(self: *ClientHandshake, out: []u8) []const u8 {
    assert(self.state == .idle);
    assert(out.len >= record.header_bytes + client_messages.hello_bytes_max);
    var x25519_public: [32]u8 = undefined;
    // The private key was asserted nonzero at init; what remains is a
    // libcrypto fault, which no peer caused and no alert can express.
    backend.x25519Public(&self.config.x25519_private, &x25519_public) catch unreachable;
    const psk: ?client_messages.PskParams = if (self.config.resume_session) |resumption| .{
        .identity = resumption.identity,
        .obfuscated_age = resumption.obfuscated_age,
        .binder_bytes = resumption.psk_bytes,
    } else null;
    const message = client_messages.clientHello(&self.hello_storage, &.{
        .random = &self.config.client_random,
        .session_id = self.config.session_id,
        .share_group = client_hello.group_x25519,
        .share_public = &x25519_public,
        .groups = self.config.groups,
        .server_name = self.config.server_name,
        .alpn_protocols = self.config.alpn_protocols,
        .psk = psk,
    });
    self.hello_bytes = @intCast(message.len);
    if (self.config.resume_session) |resumption| {
        client_messages.patchBinder(
            self.hello_storage[0..self.hello_bytes],
            resumption.psk[0..resumption.psk_bytes],
        );
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
        .peer_fatal => return error.PeerAlert,
    }
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

    var share_storage: [backend.group_public_bytes_max]u8 = undefined;
    const share = backend.keySharePublic(
        group,
        scalar[0..group.privateBytes()],
        &share_storage,
    ) catch return error.HandshakeFailure;

    // The PSK does not come with us. §4.1.4 requires the binder on a
    // second ClientHello to be recomputed over §4.4.1's transcript —
    // message_hash(CH1), the retry, then the truncated CH2 — and
    // `client_messages.patchBinder` hashes the truncated hello alone.
    // Offering the identity with a binder that cannot verify would be a
    // handshake that fails later and blames the key; dropping it is one
    // of the two answers §4.1.4 allows, and it degrades to a full
    // handshake rather than to a lie.
    //
    // The server half declines the same surgery from the other side
    // (DESIGN.md §6 slice 3), so this is one scope cut seen twice, not
    // two.
    const second = client_messages.clientHello(&self.hello_storage, &.{
        .random = &self.config.client_random,
        .session_id = self.config.session_id,
        .share_group = selected,
        .share_public = share,
        .groups = self.config.groups,
        .cookie = retry.cookie,
        .server_name = self.config.server_name,
        .alpn_protocols = self.config.alpn_protocols,
    });
    self.hello_bytes = @intCast(second.len);
    self.share_group = selected;
    self.retried = true;
    self.resumed = false;
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
    // By the *group*, not by whether we retried: a cookie-only retry
    // re-sends the x25519 share it already sent, so `retried` says
    // nothing about which scalar built the share on the wire. Choosing
    // by `retried` there derived the shared secret from the wrong key
    // and surfaced as a bad record MAC on the server's first flight —
    // a transcript-shaped symptom for a key-selection bug.
    const private: []const u8 = if (server_share.group == client_hello.group_x25519)
        &self.config.x25519_private
    else
        self.config.retry_key_share_private.?[0..group.privateBytes()];

    var shared_storage: [backend.group_shared_bytes_max]u8 = undefined;
    const shared = try backend.keyShareShared(
        group,
        private,
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
    self.state = .awaiting_flight;
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
                // dropping the PSK from CH2. Gating on the config alone
                // let a server answer a hello with no identities at all
                // and still set `resumed`, which is the flag
                // `completeHandshake` reads to decide a certificate was
                // not required. An unauthenticated connection reaching
                // `connected` is the one thing that must not happen.
                if (self.retried) return error.BadServerHello;
                if (self.config.resume_session == null) return error.BadServerHello;
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
    switch (self.state) {
        .awaiting_flight, .connected, .close_sent => {},
        else => return error.UnexpectedMessage,
    }
    assert(self.ladder != null);
    switch (self.ladder.?) {
        inline else => |*arm| {
            const opened = switch (self.state) {
                .awaiting_flight => try arm.recv.?.open(wire_record, out),
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
                    if (self.state != .awaiting_flight) return self.nextPostHandshake(arm, out);
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

fn drainFlight(self: *ClientHandshake, arm: anytype, out: []u8) Error!?Event {
    assert(self.state == .awaiting_flight);
    var messages_seen: u8 = 0;
    while (try self.assembler.next()) |message| : (messages_seen += 1) {
        assert(messages_seen < 8); // EE, Certificate, CertificateVerify, Finished.
        switch (message.messageType() orelse return error.UnexpectedMessage) {
            .encrypted_extensions => {
                try self.checkEncryptedExtensions(message.body());
                arm.transcript.update(message.bytes);
            },
            .certificate => {
                if (self.resumed) return error.UnexpectedMessage;
                // §4.4.2 sends exactly one Certificate; a second would
                // otherwise reach `captureLeaf`'s precondition as a panic.
                if (self.certificate_seen) return error.UnexpectedMessage;
                try self.captureLeaf(message.body());
                arm.transcript.update(message.bytes);
            },
            .certificate_verify => {
                if (self.resumed) return error.UnexpectedMessage;
                // §4.4.3 signs what §4.4.2 presented, so the order is
                // fixed: no Certificate yet means the peer inverted the
                // flight, which is a protocol error and not our panic.
                // Tracked by `certificate_seen`, not by the captured key:
                // under `.insecure_no_verification` there is no key, and
                // keying this off one rejected every such handshake that
                // met a server which actually sent a certificate.
                if (!self.certificate_seen) return error.UnexpectedMessage;
                try self.verifyCertificate(arm, message);
                arm.transcript.update(message.bytes);
            },
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

/// Show the chain to the embedder, then pull the leaf's public key out
/// for CertificateVerify. Under `.insecure_no_verification` the message
/// is only length-checked and neither step runs.
fn captureLeaf(self: *ClientHandshake, body: []const u8) Error!void {
    assert(self.leaf_key_kind == .none);
    var cursor = wire.Cursor.init(body);
    // certificate_request_context: empty in a server Certificate (§4.4.2).
    if (try cursor.takeByte() != 0) return error.MalformedMessage;
    const list_bytes = try cursor.takeU24();
    const list_der = try cursor.takeSlice(list_bytes);
    // Bytes after the chain say nothing about the certificates in it.
    if (cursor.remaining() != 0) return error.MalformedMessage;
    self.certificate_seen = true;
    if (self.config.certificate_policy == .insecure_no_verification) return;

    // Identity before possession. The embedder builds the chain and
    // matches the name; we prove the key underneath is held. A chain we
    // would reject is rejected before its leaf's signature is worth
    // checking, and before any of it reaches the transcript.
    if (self.config.chain_verifier) |verifier| {
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
    }) orelse return error.BadCertificate;
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
    if (public_key.len > leaf_public_key_bytes_max) return error.BadCertificate;
    switch (parsed.pub_key_algo) {
        .X9_62_id_ecPublicKey => |curve| switch (curve) {
            .X9_62_prime256v1, .secp384r1 => {
                // Uncompressed P-256 floor; `fromSec1` rejects the rest.
                if (public_key.len < 65) return error.BadCertificate;
                self.leaf_key_kind = .ecdsa;
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
            self.leaf_key_kind = .rsa;
        },
        else => return error.BadCertificate,
    }
    @memcpy(self.leaf_public_key[0..public_key.len], public_key);
    self.leaf_public_key_bytes = @intCast(public_key.len);
}

/// §4.4.3, taken against the *presented* leaf: possession, not identity.
fn verifyCertificate(self: *ClientHandshake, arm: anytype, message: handshake.Message) Error!void {
    if (self.config.certificate_policy == .insecure_no_verification) return;
    // A leaf was captured — the flight ordering in `drainFlight` guarantees
    // it. Deliberately *not* an assertion about the key's length: that is a
    // number the peer chooses, and the previous `>= 65` here was an ECDSA
    // floor left standing when RSA leaves arrived with a floor of 64. A
    // leaf whose `RSAPublicKey` DER is exactly 64 bytes would have reached
    // it and panicked. Each verifier asserts its own precondition instead,
    // where the kind is known.
    assert(self.leaf_key_kind != .none);
    var body = wire.Cursor.init(message.body());
    const scheme = try body.takeU16();
    const signature = try body.takeSlice(try body.takeU16());
    // Bytes after the signature are a framing fault; the signature
    // itself may be perfectly good and has not been checked yet.
    if (body.remaining() != 0) return error.MalformedMessage;
    var content_buffer: [server_messages.certificate_verify_content_bytes_max]u8 = undefined;
    const content = server_messages.certificateVerifyContent(.server, &arm.transcriptHash(), &content_buffer);
    const public_key = self.leaf_public_key[0..self.leaf_public_key_bytes];
    // The scheme must match the key the leaf actually carries: an ECDSA
    // scheme over an RSA key (or the reverse) is a peer error, not a
    // parse to attempt. Checked here so each verifier's precondition is
    // the kind it was written for.
    switch (scheme) {
        0x0403, 0x0503 => if (self.leaf_key_kind != .ecdsa) return error.BadSignature,
        0x0804, 0x0805, 0x0806 => if (self.leaf_key_kind != .rsa) return error.BadSignature,
        else => return error.BadSignature,
    }
    switch (scheme) {
        0x0403 => try verifyEcdsa(std.crypto.sign.ecdsa.EcdsaP256Sha256, public_key, content, signature),
        0x0503 => try verifyEcdsa(std.crypto.sign.ecdsa.EcdsaP384Sha384, public_key, content, signature),
        0x0804 => try verifyRsaPss(std.crypto.hash.sha2.Sha256, public_key, content, signature),
        0x0805 => try verifyRsaPss(std.crypto.hash.sha2.Sha384, public_key, content, signature),
        0x0806 => try verifyRsaPss(std.crypto.hash.sha2.Sha512, public_key, content, signature),
        else => unreachable, // The switch above admitted only these.
    }
    self.certificate_verified = true;
}

fn verifyEcdsa(comptime Ecdsa: type, public_key: []const u8, content: []const u8, signature_der: []const u8) Error!void {
    assert(content.len >= 98); // 64 spaces, the context string, a hash.
    assert(public_key.len >= 65);
    if (signature_der.len < 8) return error.BadSignature;
    const key = Ecdsa.PublicKey.fromSec1(public_key) catch return error.BadCertificate;
    const signature = Ecdsa.Signature.fromDer(signature_der) catch return error.BadSignature;
    signature.verify(content, key) catch return error.BadSignature;
}

/// RSA-PSS (§4.4.3's `rsa_pss_rsae_*`), through `std.crypto`'s
/// implementation rather than libcrypto's — the same choice the ECDSA
/// side makes, and for the same reason: verification of a public-length
/// message is not where the constant-time argument bites.
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

fn completeHandshake(self: *ClientHandshake, arm: anytype, message: handshake.Message, out: []u8) Error!Event {
    assert(self.state == .awaiting_flight);
    if (!self.resumed) {
        // Policy says who may skip the certificate leg: only a session a
        // PSK already authenticates.
        if (self.config.certificate_policy == .leaf_signature) {
            if (!self.certificate_verified) return error.BadCertificate;
        }
    }
    if (!self.assembler.empty()) return error.UnexpectedMessage;
    const send_ccs = self.config.send_change_cipher_spec and !self.ccs_sent;
    const flight = try arm.finishHandshake(message, send_ccs, out);
    if (send_ccs) self.ccs_sent = true;
    self.state = .connected;
    // The invariant this function exists to enforce, stated where a
    // reader can check it: nothing reaches `connected` unauthenticated.
    assert(self.resumed or self.certificate_verified or
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
    if (self.state == .awaiting_flight) return null;
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
        .new_session_ticket => return .{ .ticket = try parseTicket(message.body()) },
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
fn checkTicketExtensions(block: []const u8) Error!void {
    try wire.refuseDuplicateExtensions(ticket_extensions_max, block);
    var cursor = wire.Cursor.init(block);
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
    }
    assert(cursor.remaining() == 0);
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
    ticket.ticket = try cursor.takeSlice(ticket_bytes);
    const extensions_bytes = try cursor.takeU16();
    const extensions = try cursor.takeSlice(extensions_bytes);
    if (cursor.remaining() != 0) return error.MalformedMessage;
    try checkTicketExtensions(extensions);
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
        fn finishHandshake(self: *Self, message: handshake.Message, send_ccs: bool, out: []u8) Error![]const u8 {
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
            var client_application = self.schedule.?.deriveAt(.master, "c ap traffic", &finished_hash);
            var server_application = self.schedule.?.deriveAt(.master, "s ap traffic", &finished_hash);
            // `SessionKeys` takes its own copies and owns rotation from
            // here; ours are generation-0 material with no further use.
            defer std.crypto.secureZero(u8, &client_application);
            defer std.crypto.secureZero(u8, &server_application);

            const client_key = Schedule.finishedKey(&self.client_handshake_traffic);
            const verify_data = Schedule.verifyData(&client_key, &finished_hash);
            var message_buffer: [handshake.header_bytes + cipher_suite.hash_bytes_max]u8 = undefined;
            const finished_message = server_messages.finished(&message_buffer, &verify_data);
            self.transcript.update(finished_message);
            self.resumption_master = self.schedule.?.deriveAt(.master, "res master", &self.transcriptHash());

            var builder = wire.Builder.init(out);
            if (send_ccs) builder.putSlice(&server_messages.change_cipher_spec_record);
            const sealed = try self.send.?.seal(.handshake, finished_message, builder.bytes[builder.index..]);
            builder.index += sealed.len;

            self.session = try session_keys.SessionKeys(suite).init(&client_application, &server_application);
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
