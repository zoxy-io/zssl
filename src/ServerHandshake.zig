//! The server-side TLS 1.3 handshake (RFC 8446 §4), sans-I/O.
//!
//! The embedder feeds whole wire records in and transmits whatever comes
//! back; this machine holds the state. It draws no randomness — the
//! server random and the x25519 ephemeral come in through `Config`, which
//! is what makes a seeded simulation's replay exact and keeps the entropy
//! policy where it belongs, with the embedder.
//!
//! Full 1-RTT with optional HelloRetryRequest, ALPN, PSK resumption
//! (`psk_lookup` + binder verification), NewSessionTicket issuance after
//! the client's Finished, §4.6.3 KeyUpdate in both directions, and kTLS
//! key export current as of the latest generation.

const std = @import("std");
const assert = std.debug.assert;

const Credentials = @import("Credentials.zig");
const alert = @import("alert.zig");
const anti_replay = @import("anti_replay.zig");
const backend = @import("crypto/backend_openssl.zig");
const cipher_suite = @import("cipher_suite.zig");
const flood = @import("flood.zig");
const client_hello = @import("client_hello.zig");
const handshake = @import("handshake.zig");
const key_schedule = @import("key_schedule.zig");
const ktls = @import("ktls.zig");
const protect = @import("protect.zig");
const record = @import("record.zig");
const server_messages = @import("server_messages.zig");
const session_keys = @import("session_keys.zig");
const transcript = @import("transcript.zig");
const CipherSuite = cipher_suite.CipherSuite;

state: State,
config: Config,
/// The key-exchange group this handshake settled on, fixed when the
/// ClientHello's shares are read.
key_share_group: backend.Group,
/// The scheme the CertificateVerify will carry, fixed at negotiation:
/// the first of our key's schemes the client offered. Meaningless on a
/// resumed handshake, which signs nothing.
signature_scheme: backend.SignatureScheme,
assembler: handshake.Assembler,
ladder: ?Ladder,
/// §5.1 and §4.6.3 flood ceilings: consecutive empty records and
/// consecutive KeyUpdates, both bounded so a peer cannot buy unbounded
/// work with records that deliver nothing. See flood.zig.
flood_guard: flood.Guard,
/// Compatibility ChangeCipherSpec records seen; tolerated, but bounded.
ccs_seen: u8,
/// The session id to echo, captured from the (first) ClientHello.
session_echo_bytes: u8,
session_echo: [32]u8,
/// Whether this session came up on an accepted PSK — the fact behind
/// zoxy's `tls_resumed` counter.
resumed: bool,
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
/// §4.2.10's rejected-early-data window: the hello offered 0-RTT, we
/// declined it by saying nothing, and the client is sending it anyway.
/// Records that arrive while this stands are skipped rather than opened
/// — we hold no key that could open them, so reporting a decryption
/// failure would name a fault the peer did not commit.
///
/// It closes at a second ClientHello, because §4.1.2 removes the
/// extension there and §4.2.10 forbids the data: past that point an
/// application_data record is ciphertext we are meant to be able to
/// open, and failing is the right answer.
early_data_offered: bool,
/// What the records skipped under that window have cost, in bytes of
/// the budget below — their payloads, and never less than one each.
early_data_skipped: u32,
/// §4.2.10 accepted for this connection: the flight said so, and the
/// early keys exist to open what follows.
early_data_accepted: bool,
/// Application bytes accepted as early data, against the ticket's own
/// `max_early_data_size`. Counted after decryption, because that is what
/// §4.6.1 measures — the client sized its data against this number.
early_data_bytes: u32,
/// The limit the ticket advertised, copied out because the `Psk` that
/// carried it is gone by the time the records arrive.
early_data_bytes_max: u32,
/// Whether the ClientHello that earned a HelloRetryRequest carried a
/// `pre_shared_key`. §4.1.2 lets the second hello update that extension
/// and not drop it, and CH1's bytes are gone by the time CH2 arrives —
/// so the question is answered while it still can be.
ch1_offered_psk: bool,
/// §4.2.9: whether a NewSessionTicket may be sent. Kept because a ticket
/// is issued long after the hello is gone.
///
/// The rule is narrower than "did the client advertise psk_dhe_ke": the
/// RFC says servers "SHOULD NOT send NewSessionTicket with tickets that
/// are not compatible with the advertised modes", and a hello advertising
/// no modes at all has nothing to be incompatible with. Advertising modes
/// that exclude psk_dhe_ke is the case that forbids a ticket, because
/// then the client has said which modes it will accept and ours is not
/// among them.
ticket_permitted: bool,

const ServerHandshake = @This();

pub const State = enum(u8) {
    awaiting_client_hello,
    awaiting_retry_client_hello,
    /// §4.2.10 accepted: our flight is out and the client's 0-RTT data
    /// is arriving under keys derived from its hello alone. Distinct
    /// from `awaiting_finished` because the records here open with a
    /// different protector, and because the message that ends it —
    /// §4.5's EndOfEarlyData — is the one that moves the transcript the
    /// client's Finished will MAC.
    awaiting_end_of_early_data,
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

/// §6.1's two halves, asked rather than pattern-matched. Every entry
/// point below is gated on one of these instead of on `.connected`,
/// which is what finding 6 was: a single `.closed` state cannot say
/// which direction closed, so it said both and closed neither properly.
pub fn writable(self: *const ServerHandshake) bool {
    return self.state == .connected or self.state == .close_received;
}

/// §2's 0.5-RTT window: our flight is out, the client's Finished has not
/// arrived, and application data may go out anyway. `finishFlight` moved
/// the send side onto application keys, so these records are protected
/// exactly as post-handshake ones are — it is the same key and one
/// continuous nonce sequence.
///
/// What is *weaker* here is not the protection but the knowledge. We
/// have not seen the client's Finished, so we do not yet know the
/// handshake was not tampered with in ways the transcript would catch,
/// and with 0-RTT accepted we do not know the hello was not a replay
/// (§8 bounds that, it does not remove it). Appendix E.5 is the RFC's
/// own account. An embedder that answers here is choosing a round trip
/// over that confirmation, which is exactly the trade 0.5-RTT is.
pub fn halfRttWritable(self: *const ServerHandshake) bool {
    return self.state == .awaiting_finished or self.state == .awaiting_end_of_early_data;
}

pub fn readable(self: *const ServerHandshake) bool {
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
fn afterCloseSent(self: *const ServerHandshake) State {
    return switch (self.state) {
        .connected => .close_sent,
        .close_received => .closed,
        else => .closed,
    };
}

fn afterCloseReceived(self: *const ServerHandshake) State {
    return switch (self.state) {
        .connected => .close_received,
        .close_sent => .closed,
        else => .closed,
    };
}

pub const Config = struct {
    credentials: *const Credentials,
    /// Embedder-supplied entropy; zssl generates none.
    server_random: [32]u8,
    /// The key-exchange scalar. Sized for the largest group zssl offers
    /// (secp384r1); the shorter ones take a prefix, because stretching a
    /// short scalar would quietly take the entropy policy away from the
    /// embedder it belongs to.
    key_share_private: [backend.group_private_bytes_max]u8,
    /// The one protocol this server will negotiate via ALPN, or null to
    /// skip the extension entirely.
    alpn: ?[]const u8 = null,
    /// Our key-exchange group preference, most wanted first. §4.2.8
    /// leaves the choice to the server among what the client offered,
    /// and this is where that choice is made.
    ///
    /// Any subset of `client_hello.groups_supported`, in any order;
    /// `init` asserts each entry is one we can complete, because a group
    /// we cannot complete is a HelloRetryRequest we would send and then
    /// be unable to answer. Narrowing it is how a deployment requires a
    /// curve — and, since a server that accepts x25519 never needs to
    /// send a retry at all, it is also the only way to put a retry under
    /// an in-tree test rather than leaving it to BoGo.
    groups: []const u16 = &client_hello.groups_supported,
    /// §4.4.2's signing set, as wire code points, in the embedder's
    /// preference order. Null leaves the choice to the key, which is
    /// what an embedder that has not thought about it wants.
    ///
    /// Wire values rather than `backend.SignatureScheme` on purpose, the
    /// same way `groups` is: restricting the server to a scheme this
    /// build cannot produce is a legal thing to configure, and the
    /// answer is `HandshakeFailure` — not a type that cannot hold the
    /// request. An embedder pinning ecdsa_secp384r1_sha384 on a P-256
    /// key has misconfigured something, and a handshake that says so is
    /// better than one that quietly signs with the other curve.
    signing_schemes: ?[]const u16 = null,
    /// Caller-owned space for handshake-message reassembly (client side
    /// of the conversation). A ClientHello budget: 8 KiB is generous.
    reassembly: []u8,
    /// Caller-owned space for flight plaintext assembly; must hold the
    /// certificate chain plus ~1 KiB.
    flight: []u8,
    /// The embedder's clock in milliseconds, read once as this
    /// connection began. Null when the embedder keeps none.
    ///
    /// Supplied rather than read, for the reason `server_random` is:
    /// zssl calls nothing and measures nothing, so a replayed simulation
    /// feeds the same number and gets the same run. Time is the
    /// embedder's exactly as entropy is.
    ///
    /// The absence is load-bearing. Everything §8 needs a clock for is
    /// off without one, so a server that never thought about time cannot
    /// accept replayable data by accident — the safe default is the
    /// shape of the type rather than a line in a document.
    now_ms: ?u64 = null,
    /// §8.2's record of ClientHellos already seen, in caller-owned
    /// storage. Null — the default — is one of the three things that
    /// must all be present before any early data is accepted, along with
    /// `now_ms` and the ticket's own `early_data` terms. Three positive
    /// opt-ins, because the failure of any of them is a replay.
    strike_register: ?*anti_replay.StrikeRegister = null,
    /// The PSK seam: given an offered identity, answer the key it stands
    /// for and say which kind it is, or null to fall back to a full
    /// handshake. Both §4.2.11 sources come through here — a ticket this
    /// server issued, and a key agreed out of band — because the wire
    /// tells them apart only by what the embedder recognises. The
    /// embedder owns ticket sealing, lifetime, and age policy; this
    /// machine owns the binder check that follows, and picks its label
    /// from the `kind` this answers with.
    psk_lookup: ?PskLookup = null,
};

pub const PskLookup = struct {
    context: *anyopaque,
    /// Writes the PSK into `psk_out` and answers for it, or null when
    /// the identity is not ours to accept.
    lookup: *const fn (
        context: *anyopaque,
        identity: []const u8,
        obfuscated_age: u32,
        psk_out: *[cipher_suite.hash_bytes_max]u8,
    ) ?Psk,
};

/// What an embedder answers with. The `kind` is not bookkeeping: §4.2.11.2
/// derives `binder_key` under "ext binder" or "res binder" by it, so a
/// PSK described as the wrong kind fails its binder and looks to the peer
/// like a key mismatch. The wire carries an identity and says nothing
/// about provenance, so only the embedder that recognised the identity
/// can say which it is.
/// When the ticket behind an identity was issued, and for how long it
/// was good, in the same milliseconds as `Config.now_ms`. §4.6.1: "The
/// server MUST NOT use the ticket beyond its lifetime" — this is what
/// lets zssl hold to that itself instead of trusting the lookup to have
/// done it.
pub const Issued = struct {
    at_ms: u64,
    /// §4.2.11.1's `ticket_age_add`, which the client adds to the age it
    /// claims. §8.3 cannot be computed without it: what arrives on the
    /// wire is the sum, and only the issuer knows the addend.
    age_add: u32 = 0,
    /// §4.6.1's `ticket_lifetime`, seconds, and the RFC caps it at a
    /// week. A lookup answering more is describing a ticket the server
    /// should never have minted, so the cap is applied rather than
    /// believed.
    lifetime_s: u32,

    pub const lifetime_s_max: u32 = 7 * 24 * 60 * 60;

    /// Whether `now_ms` is past the end of this ticket's life.
    ///
    /// Saturating both ways on purpose. A clock that went backwards, or
    /// an `at_ms` in the future, is the embedder's fault and not the
    /// peer's — answering "expired" to it refuses a resumption that may
    /// be perfectly good, and answering "fresh" honours a ticket that
    /// may be ancient. The first is the one to choose.
    pub fn expired(self: Issued, now_ms: u64) bool {
        const lifetime_ms = @as(u64, @min(self.lifetime_s, lifetime_s_max)) * 1000;
        const age_ms = now_ms -| self.at_ms;
        return age_ms > lifetime_ms;
    }
};

pub const Psk = struct {
    /// How many bytes were written into `psk_out`. A resumption PSK is
    /// exactly the negotiated hash's length, because §4.6.1 derives it
    /// that way; an external one is whatever was agreed out of band,
    /// bounded here by `psk_out` itself.
    ///
    /// Named for the count, not the content: every other `bytes:` field
    /// in this tree holds a slice, and the `_bytes` suffix is what a
    /// length wears — `psk_bytes`, `ticket_bytes`, `nonce_bytes`.
    psk_bytes: u8,
    kind: key_schedule.PskKind,
    /// Null for an external PSK, which has no issuance to speak of, and
    /// for an embedder that keeps no clock. With both this and
    /// `Config.now_ms` present, §4.6.1's lifetime is enforced here
    /// rather than assumed of the lookup.
    issued: ?Issued = null,
    /// What this ticket permits by way of 0-RTT, or null — the default —
    /// for none. §4.2.10 is explicit that early data rides on the
    /// *ticket's* terms, not the connection's: the client was told a
    /// limit and a suite when the ticket was minted and has already
    /// spent bytes against them by the time we read this.
    early_data: ?EarlyData = null,
};

/// The 0-RTT terms a ticket was issued under.
pub const EarlyData = struct {
    /// §4.6.1's `max_early_data_size`, as the ticket advertised it. The
    /// client sized its early data against this number, so it is the
    /// server's to hold to rather than to reconsider.
    bytes_max: u32,
    /// §4.2.10: "the server MUST verify that the ... cipher suite ...
    /// are the same as the ones associated with the ticket". A PSK is
    /// bound to a hash and two of our three suites share one, so the
    /// suite has to be carried rather than inferred from the length.
    suite: CipherSuite,
};

const SelectedPsk = struct {
    psk: [cipher_suite.hash_bytes_max]u8,
    psk_bytes: u8,
    kind: key_schedule.PskKind,
    index: u16,
    /// The binder as the client sent it, kept because §8.2 needs a value
    /// unique to this hello and this already is one: an HMAC over the
    /// truncated ClientHello, so two hellos share it only if they are
    /// the same hello. Copied rather than borrowed — the offer points
    /// into the record buffer and the decision outlives it.
    binder: [cipher_suite.hash_bytes_max]u8,
    binder_bytes: u8,
    /// What the lookup answered about the ticket, carried forward so the
    /// early-data decision can be made after the binder verified rather
    /// than beside it.
    issued: ?Issued,
    early_data: ?EarlyData,
    obfuscated_age: u32,
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
    /// The handshake completed on this record.
    connected,
    /// Decrypted application bytes, sliced from `out`.
    application_data: []const u8,
    /// The peer ended the connection cleanly.
    closed,
};

pub const Error = backend.SignError || protect.Error || handshake.Assembler.Error ||
    client_hello.Error || alert.Error || error{
    /// The record or message is legal TLS arriving at the wrong moment.
    UnexpectedMessage,
    /// `handleRecord` was called while a post-handshake message from the
    /// previous record was still waiting. Not the peer's fault and not a
    /// protocol error: the embedder skipped `drain`. §6 has no alert for
    /// it, and the connection is still intact — drain, then carry on.
    EventsPending,
    /// No common cipher suite, group, or signature scheme (§4.1.1).
    HandshakeFailure,
    /// A ClientHello negotiating TLS 1.3 that omits an extension §9.2
    /// makes mandatory — `supported_groups`, `key_share`, or
    /// `psk_key_exchange_modes` beside a PSK offer. Distinct from
    /// HandshakeFailure, which is an extension that is present and
    /// offers nothing we hold.
    MissingExtension,
    /// `sendNewSessionTicket` on a connection whose ClientHello never
    /// advertised psk_dhe_ke (§4.6.1). The connection is fine; the ticket
    /// is the thing that must not be sent.
    TicketNotPermitted,
    /// The client offered ALPN and nothing on it matched (RFC 7301 §3.2).
    NoApplicationProtocol,
    /// The client's second ClientHello broke an HRR rule (§4.1.4).
    IllegalRetry,
    /// The client's Finished MAC did not verify (§4.4.4).
    DecryptError,
    /// The peer sent a fatal alert; the connection is over.
    PeerAlert,
    /// A KeyUpdate whose body breaks §4.6.3's one-byte grammar.
    IllegalKeyUpdate,
    /// More *accepted* early data than the ticket advertised room for.
    /// §4.6.1's `max_early_data_size` is a promise the client sized its
    /// send against, so a client past it is not one we issued that
    /// ticket to — distinct from `TooMuchSkippedEarlyData`, which is
    /// about data we declined and never keyed.
    TooMuchEarlyData,
    /// More rejected early data than `early_data_skipped_max`. Not the
    /// peer breaking a rule — the records are legal and we asked for
    /// none of them — but discarding is work, and unbounded work a peer
    /// buys for free is the shape flood.zig's three ceilings exist to
    /// refuse.
    TooMuchSkippedEarlyData,
} || session_keys.Error || flood.Error;

/// `out` for `handleRecord` must hold a whole flight or a whole decrypted
/// record, whichever is larger — one wire record's bound covers both.
pub const out_bytes_min: u32 = record.wire_record_bytes_max;

pub fn init(config: *const Config) ServerHandshake {
    assert(config.reassembly.len >= 1024);
    assert(config.flight.len >= Credentials.chain_bytes_max + 1024);
    assert(config.credentials.certificate_count >= 1);
    if (config.alpn) |protocol| assert(protocol.len >= 1);
    assert(config.groups.len >= 1);
    assert(config.groups.len <= client_hello.groups_supported.len);
    // Non-empty, and deliberately unbounded above: unlike `groups`,
    // nothing is ever *written* from this list — it is only read to
    // choose among what the key can already do, so there is no buffer to
    // overrun. Membership is not checked either: naming a scheme the key
    // cannot produce is the misconfiguration described on the field, and
    // it is answered on the wire rather than asserted away.
    if (config.signing_schemes) |schemes| assert(schemes.len >= 1);
    for (config.groups) |group| assert(client_hello.groupShareBytes(group) != null);
    return .{
        .state = .awaiting_client_hello,
        .config = config.*,
        // Overwritten by the first hello, either with what it shared or
        // with what the retry demands. The default matters only if an
        // embedder reads it before then.
        .key_share_group = backend.Group.fromWire(config.groups[0]).?,
        .signature_scheme = config.credentials.signer.supported()[0],
        .ticket_permitted = false,
        .assembler = handshake.Assembler.init(config.reassembly),
        .ladder = null,
        .flood_guard = .{},
        .ccs_seen = 0,
        .session_echo_bytes = 0,
        .session_echo = undefined,
        .resumed = false,
        .ch1_offered_psk = false,
        .peer_alert_description = null,
        .early_data_offered = false,
        .early_data_skipped = 0,
        .early_data_accepted = false,
        .early_data_bytes = 0,
        .early_data_bytes_max = 0,
    };
}

pub fn deinit(self: *ServerHandshake) void {
    assert(self.ccs_seen <= ccs_seen_max);
    if (self.ladder) |*ladder| switch (ladder.*) {
        inline else => |*arm| arm.deinit(),
    };
    self.* = undefined;
}

const ccs_seen_max: u8 = 2;

/// How much rejected early data we will discard before giving up.
///
/// The number is BoringSSL's `kMaxEarlyDataSkipped`
/// (`ssl/tls_record.cc`) and so is the reason: "without this limit an
/// attacker could send records at a faster rate than we can process and
/// cause trial decryption to loop forever". We never accept early data,
/// so this is not a `max_early_data_size` — it is a work ceiling, and
/// the only thing it has to do is bound the discarding.
///
/// What is counted differs from theirs by five bytes a record, and
/// deliberately. BoringSSL adds what it consumed from the stream,
/// header included; this adds the record's payload, which is what
/// §4.2.10 measures early data in ("in units of bytes of application
/// data") — with a floor of one byte a record, so that empty ones are
/// paid for too. Both refuse BoGo's `SkipEarlyData-TooMuchData-TLS13`,
/// which sends 2^14+1 in one record. Only this one admits a client that sends
/// exactly 2^14 — the amount a server advertising the RFC's own example
/// limit would have invited — and tlsfuzzer's `test-tls13-0rtt-garbage`
/// is written around precisely that client.
const early_data_skipped_max: u32 = 16384;

/// Feed one whole wire record; act on what comes back. On any error the
/// machine is `failed` and must not be fed again — the embedder closes.
///
/// Null is "this record produced nothing", and it is the same null
/// `drain` answers, so the two compose into one loop:
///
///     var event = try server.handleRecord(wire_record, &out);
///     while (event) |ready| : (event = try server.drain(&out)) { … }
pub fn handleRecord(self: *ServerHandshake, wire_record: []const u8, out: []u8) Error!?Event {
    assert(out.len >= out_bytes_min);
    assert(self.state != .failed);
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
            // anything about where we are: §5 admits "the single byte
            // value 0x01" and nothing else, so a record that is not
            // that is not the compatibility record at all and its
            // position is beside the point. This used to go unread —
            // `01 01` was accepted as filler, and so was a hundred
            // `01`s in one record, which is tlsfuzzer's finding 8
            // (docs/TLSFUZZER.md).
            if (!record.isCompatibilityCcs(wire_record[record.header_bytes..])) {
                return error.UnexpectedMessage;
            }
            if (self.state == .awaiting_client_hello) return error.UnexpectedMessage;
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
            // wedged into a message being reassembled; §5.1 forbids that
            // for "other record types" without excepting this one.
            try self.refuseInterleavedRecord();
            self.ccs_seen += 1;
            return null;
        },
        .alert => {
            try self.refuseInterleavedRecord();
            return self.handlePlaintextAlert(wire_record[record.header_bytes..]);
        },
        .handshake => return self.handlePlaintextHandshake(wire_record, out),
        .application_data => {
            // Before our flight there is no receive key at all, so
            // every protected record in that window is early data and
            // nothing else could be. After it, the question cannot be
            // answered by content type — see `handleProtectedRecord`.
            if (self.early_data_offered and self.state == .awaiting_retry_client_hello) {
                return self.skipEarlyData(wire_record);
            }
            return self.handleProtectedRecord(wire_record, out);
        },
    }
}

/// Whether a record that would not open is early data rather than a
/// fault. §4.2.10 again, on the far side of our flight: "the server ...
/// must instead use trial decryption ... to find the first non-0-RTT
/// message", and this is the "trial" half — the answer is only early
/// data if opening it failed *and* the client told us some was coming.
fn openFailureIsEarlyData(self: *const ServerHandshake, err: Error) bool {
    assert(self.state != .failed);
    if (!self.early_data_offered) return false;
    if (self.state != .awaiting_finished) return false;
    // Only the two ways a record can fail to be *this* key's ciphertext.
    // A sequence number spent, or a header we refused, is our fault or a
    // framing fault, and neither becomes early data by being adjacent to
    // some.
    return err == error.AuthenticationFailed or err == error.BadInnerPlaintext;
}

/// One rejected early-data record, counted and dropped.
fn skipEarlyData(self: *ServerHandshake, wire_record: []const u8) Error!?Event {
    assert(self.early_data_offered);
    assert(wire_record.len >= record.header_bytes);
    // §5.1 first, and it is not redundant with the skip: early data
    // wedged into a handshake message being reassembled is the
    // interleaving §5.1 forbids whatever the record turns out to hold,
    // and BoGo checks it by name (`SkipEarlyData-Interleaved-TLS13`).
    // A record we discard is still a record that arrived.
    try self.refuseInterleavedRecord();
    // A byte of budget minimum, because a record costs something to
    // look at whether or not it carries anything — and §5.1 lets an
    // application_data record be empty, so a peer paying only for
    // headers would otherwise hold this window open forever at five
    // bytes a turn. That is the same reason flood.zig counts empty
    // records, and the ceiling below is meaningless without it.
    //
    // Saturating, so the ceiling is what refuses rather than a wrap.
    const payload_bytes: u32 = @intCast(wire_record.len - record.header_bytes);
    self.early_data_skipped +|= @max(payload_bytes, 1);
    if (self.early_data_skipped > early_data_skipped_max) {
        return error.TooMuchSkippedEarlyData;
    }
    return null;
}

/// §5.1: "Handshake messages MUST NOT be interleaved with other record
/// types. That is, if a handshake message is split over two or more
/// records, there MUST NOT be any other records between them."
///
/// The assembler holding bytes here means exactly that and nothing
/// else: `handleRecord` has already refused a *complete* undrained
/// message with `EventsPending`, so whatever is left is a message whose
/// length header arrived and whose body did not. A record of any other
/// type on top of it is the interleaving §5.1 forbids.
///
/// It matters beyond tidiness. A peer that can park a half-message and
/// then send freely decides how long we hold a partial reassembly, and
/// tlsfuzzer walks exactly that: a KeyUpdate split in two with a
/// request in the gap (docs/TLSFUZZER.md finding 10).
fn refuseInterleavedRecord(self: *const ServerHandshake) Error!void {
    if (!self.assembler.empty()) return error.UnexpectedMessage;
}

fn handlePlaintextAlert(self: *ServerHandshake, payload: []const u8) Error!?Event {
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

fn handlePlaintextHandshake(self: *ServerHandshake, wire_record: []const u8, out: []u8) Error!?Event {
    // Plaintext handshake records are only ever the ClientHello leg.
    switch (self.state) {
        .awaiting_client_hello, .awaiting_retry_client_hello => {},
        else => return error.UnexpectedMessage,
    }
    assert(self.ladder == null or self.state == .awaiting_retry_client_hello);
    try self.assembler.push(wire_record[record.header_bytes..]);
    const message = (try self.assembler.next()) orelse return null;
    if (message.messageType() != .client_hello) return error.UnexpectedMessage;
    // One message per flight here: bytes after a complete ClientHello are
    // a peer talking past its own handshake.
    if (!self.assembler.empty()) return error.UnexpectedMessage;
    return try self.handleClientHello(message.bytes, out);
}

fn handleClientHello(self: *ServerHandshake, message: []const u8, out: []u8) Error!Event {
    const hello = try client_hello.parse(message);
    if (!hello.supports_tls13) return error.HandshakeFailure;
    const suite = negotiateSuite(&hello) orelse return error.HandshakeFailure;
    assert(hello.offersSuite(suite));
    assert(hello.cipher_suites_wire.len >= 2);
    if (self.state == .awaiting_retry_client_hello) {
        // §4.1.2: after a HelloRetryRequest the client "MUST send the
        // same ClientHello without modification, except as follows",
        // and the list that follows permits *updating* a
        // `pre_shared_key` — recomputing its age and binder — not
        // dropping it. A CH2 that drops one CH1 made is missing an
        // extension it is required to carry, which is the alert §4.1.2
        // earns and the one BoringSSL sends
        // (`Resume-Server-OmitAllPSKsOnSecondClientHello`).
        //
        // Safe here because the suite cannot move across our retry: it
        // is chosen by the same preference walk over the same offer, and
        // a CH2 that changed it is refused two lines down. §4.2.11's
        // "SHOULD NOT offer a PSK whose hash is not the selected
        // suite's" therefore never obliges a client to drop one on us.
        if (self.ch1_offered_psk and hello.pre_shared_key_wire == null) {
            return error.MissingExtension;
        }
        // §4.1.2 again, the other direction: the exception list requires
        // "removing the `early_data` extension ... if one was present.
        // Early data is not permitted after a HelloRetryRequest." One
        // that kept it is a second hello we may not answer.
        if (hello.early_data) return error.IllegalRetry;
        // And the window closes whether or not it was ever open: from
        // here an application_data record is ciphertext we are meant to
        // open, so failing to is the honest answer rather than a discard
        // (BoGo's `SkipEarlyData-SecondClientHelloEarlyData-TLS13`).
        self.early_data_offered = false;
        // §4.1.4: the retry must keep the suite and answer the demand.
        //
        // Ahead of the PSK, and that ordering is load-bearing now that a
        // binder on CH2 is verified: it hashes the transcript this
        // handshake's ladder is holding, and the ladder was built for
        // the suite CH1 settled on. A CH2 that moved the suite must be
        // refused before anything reads that transcript, or the binder
        // would be checked under one hash against a ladder keyed to
        // another.
        const ladder_suite: CipherSuite = self.ladder.?;
        if (suite != ladder_suite) return error.IllegalRetry;
        // The retry must answer the group we asked for, and no other.
        if (hello.keyShareFor(@intFromEnum(self.key_share_group)) == null) {
            return error.IllegalRetry;
        }
    }
    const selected_psk = try self.selectPsk(&hello, message, suite);
    if (selected_psk == null) {
        // A full handshake signs a CertificateVerify; a resumed one
        // authenticates by PSK and needs no common signature scheme.
        // §4.4.2: the scheme we sign under must be one the client offered,
        // and an RSA key admits three digests — so this is an
        // intersection, not an equality.
        self.signature_scheme = selectScheme(
            &hello,
            self.config.credentials,
            self.config.signing_schemes,
        ) orelse
            return error.HandshakeFailure;
    }
    self.captureSessionEcho(&hello);
    // §4.2.10 offers 0-RTT by the extension's presence alone, and this
    // is the only thing zssl does with it: remember that records are
    // coming so they can be skipped rather than mistaken for ciphertext.
    // Accepting is the part §1 defers, and nothing here moves that.
    if (self.state == .awaiting_client_hello) self.early_data_offered = hello.early_data;

    if (self.state == .awaiting_retry_client_hello) {
        return self.acceptClientHello(&hello, message, suite, selected_psk, out);
    }

    assert(self.state == .awaiting_client_hello);
    // §9.2: a ClientHello negotiating TLS 1.3 over (EC)DHE must carry
    // both `supported_groups` and `key_share`, and a server receiving one
    // that does not "MUST abort the handshake with a missing_extension
    // alert". A hello carrying `supported_groups` is attempting (EC)DHE,
    // so one without `key_share` has forgotten half of it.
    //
    // Omission is the error. An *empty* `client_shares`, or one holding
    // only groups we skip, is the legal §4.2.8 way to ask the server to
    // choose, and earns the HelloRetryRequest below — the two are
    // indistinguishable by `key_share_count` alone, which is why the
    // parser records presence separately and why this sits ahead of the
    // retry path.
    //
    // Neither extension present splits in two, which is what the clause
    // just below sorts out: with no PSK offered it is still a §9.2
    // violation, and with one it may be a legitimate attempt at psk_ke,
    // which §9.2 does not reach and which zssl refuses for its own
    // reasons (DESIGN §6) as a handshake_failure further down.
    if (hello.supported_groups_wire != null and !hello.has_key_share) {
        return error.MissingExtension;
    }
    // The other direction, and the reason the rule above is not the whole
    // of §9.2: a hello offering no PSK at all can only be attempting
    // (EC)DHE, so *both* extensions are mandatory and either one missing
    // is the same abort. A hello that does offer a PSK might legitimately
    // be attempting psk_ke, which §9.2 does not reach — zssl refuses that
    // for its own reasons (DESIGN §6), with handshake_failure below.
    if (hello.pre_shared_key_wire == null and hello.supported_groups_wire == null) {
        return error.MissingExtension;
    }
    // §4.2.9 and §9.2 together: "In order to use PSKs, clients MUST also
    // send a psk_key_exchange_modes extension", and a hello missing an
    // extension §9.2 requires is a missing_extension abort. Offering a
    // PSK with no modes at all leaves the server nothing to select, and
    // answering it with a full handshake — which is what zssl did — hides
    // a malformed offer behind a working connection.
    if (hello.pre_shared_key_wire != null and hello.psk_modes_wire == null) {
        return error.MissingExtension;
    }
    self.ticket_permitted = hello.psk_modes_wire == null or hello.offersPskDheKe();
    if (hello.preferredKeyShare(self.config.groups)) |offered| {
        // §4.2.8 leaves the choice to us among what the client sent.
        self.key_share_group = backend.Group.fromWire(offered.group).?;
        return self.acceptClientHello(&hello, message, suite, selected_psk, out);
    }
    // No share we can use. If the client says it supports a group we
    // hold, demand it (§4.1.4); if it does not, there is no handshake.
    const wanted = hello.preferredSupportedGroup(self.config.groups) orelse
        return error.HandshakeFailure;
    self.key_share_group = backend.Group.fromWire(wanted).?;
    // Remembered rather than re-derived: CH1's bytes are gone by the
    // time CH2 arrives, and §4.1.2 asks what *that* hello carried.
    self.ch1_offered_psk = hello.pre_shared_key_wire != null;
    return self.sendHelloRetry(message, suite, out);
}

/// §4.2.11: walk the offered identities through the embedder's lookup;
/// the first one the embedder recognizes must carry a valid binder or
/// the handshake aborts — an attacker replaying a stolen identity does
/// not get downgraded to a full handshake, it gets refused.
///
/// A retry ClientHello may carry an offer like any other. What changes
/// is the transcript the binder covers — §4.4.1's reconstruction rather
/// than the truncation alone — and `binderTranscriptHash` is where that
/// difference lives.
fn selectPsk(
    self: *ServerHandshake,
    hello: *const client_hello.ClientHello,
    message: []const u8,
    suite: CipherSuite,
) Error!?SelectedPsk {
    const lookup = self.config.psk_lookup orelse return null;
    if (hello.preferredKeyShare(self.config.groups) == null) return null; // psk_dhe_ke needs a share.
    if (!hello.offersPskDheKe()) return null;
    const offer = (try client_hello.parsePskOffer(hello)) orelse return null;
    assert(offer.count >= 1);
    assert(offer.binders_section_bytes < message.len);
    const truncated = message[0 .. message.len - offer.binders_section_bytes];
    const transcript_hash = self.binderTranscriptHash(suite, truncated);

    var index: u8 = 0;
    while (index < offer.count) : (index += 1) {
        assert(index < client_hello.psk_identities_max);
        var selected: SelectedPsk = .{
            .psk = undefined,
            .psk_bytes = 0,
            .kind = .resumption,
            .index = index,
            .binder = undefined,
            .binder_bytes = 0,
            .issued = null,
            .early_data = null,
            .obfuscated_age = offer.obfuscated_ages[index],
        };
        const answer = lookup.lookup(
            lookup.context,
            offer.identities[index],
            offer.obfuscated_ages[index],
            &selected.psk,
        ) orelse continue;
        // A resumption PSK is bound to its hash — §4.6.1 derives it at
        // exactly that length, so any other length is an embedder
        // handing back something a ticket cannot have produced. An
        // external PSK carries no such derivation and §4.2.11 sets no
        // length for it, so the only bound is the buffer it arrived in.
        // Zero is refused either way rather than asserted: it would
        // extract a schedule from nothing.
        switch (answer.kind) {
            .resumption => if (answer.psk_bytes != suite.hashBytes()) continue,
            .external => if (answer.psk_bytes == 0 or answer.psk_bytes > selected.psk.len) continue,
        }
        // §4.6.1's lifetime, enforced rather than trusted — but only
        // when the embedder gave us both halves of the question. An
        // expired ticket is our own policy declining, not a peer
        // misbehaving, so it falls through to the next identity and then
        // to a full handshake; `binderMatches` below is where an offer
        // that *is* an attack gets refused outright.
        if (self.config.now_ms) |now_ms| {
            if (answer.issued) |issued| {
                if (issued.expired(now_ms)) continue;
            }
        }
        selected.psk_bytes = answer.psk_bytes;
        selected.kind = answer.kind;
        selected.issued = answer.issued;
        selected.early_data = answer.early_data;
        if (!binderMatches(
            suite,
            answer.kind,
            selected.psk[0..answer.psk_bytes],
            transcript_hash[0..suite.hashBytes()],
            offer.binders[index],
        )) {
            return error.DecryptError;
        }
        // Only now, with the binder verified: an unverified one is a
        // value an attacker chose, and §8.2's register must not be
        // filled with those.
        assert(offer.binders[index].len <= selected.binder.len);
        selected.binder_bytes = @intCast(offer.binders[index].len);
        @memcpy(selected.binder[0..selected.binder_bytes], offer.binders[index]);
        return selected;
    }
    return null;
}

/// §4.2.11.2's `Transcript-Hash(Truncate(ClientHello))`.
///
/// On a first ClientHello the truncation is the whole transcript and
/// this is its plain hash. On a second one it is not: §4.4.1 replaced
/// CH1 with a `message_hash` message and put the HelloRetryRequest
/// behind it, and the binder covers all three. The ladder is standing at
/// exactly that point — `sendHelloRetry` absorbed both and CH2 goes in
/// only once it is accepted — so the prefix is asked for rather than
/// rebuilt here, which is also what stops the two from ever disagreeing
/// about what CH1 hashed to.
fn binderTranscriptHash(
    self: *const ServerHandshake,
    suite: CipherSuite,
    truncated: []const u8,
) [cipher_suite.hash_bytes_max]u8 {
    // Not reachable from the wire: the truncation is a parsed
    // ClientHello minus its binders section, and `selectPsk` has
    // already established that the section is shorter than the message.
    // A hello short enough to fail this could not have parsed.
    assert(truncated.len >= handshake.header_bytes);
    var digest: [cipher_suite.hash_bytes_max]u8 = undefined;
    if (self.state == .awaiting_retry_client_hello) {
        switch (self.ladder.?) {
            inline else => |*arm, tag| {
                // `handleClientHello` refuses a CH2 that moved the suite
                // before this is reached.
                assert(tag == suite);
                const Hash = CipherSuite.HashType(tag);
                digest[0..Hash.digest_length].* = arm.transcript.hashWith(truncated);
            },
        }
        return digest;
    }
    assert(self.state == .awaiting_client_hello);
    switch (suite) {
        inline else => |comptime_suite| {
            const Hash = CipherSuite.HashType(comptime_suite);
            Hash.hash(truncated, digest[0..Hash.digest_length], .{});
        },
    }
    return digest;
}

fn binderMatches(
    suite: CipherSuite,
    kind: key_schedule.PskKind,
    psk: []const u8,
    transcript_hash: []const u8,
    binder: []const u8,
) bool {
    // Not `== suite.hashBytes()`: an external PSK is whatever length the
    // two peers agreed on, and `selectPsk` has already bounded it.
    assert(psk.len >= 1 and psk.len <= cipher_suite.hash_bytes_max);
    assert(transcript_hash.len == suite.hashBytes());
    switch (suite) {
        inline else => |comptime_suite| {
            const Hash = CipherSuite.HashType(comptime_suite);
            const Schedule = key_schedule.KeySchedule(comptime_suite);
            if (binder.len != Hash.digest_length) return false;
            var schedule = Schedule.initEarly(psk);
            defer schedule.wipe();
            const expected = schedule.pskBinder(kind, transcript_hash[0..Hash.digest_length]);
            return std.crypto.timing_safe.eql(
                [Hash.digest_length]u8,
                binder[0..Hash.digest_length].*,
                expected,
            );
        },
    }
}

/// §4.4.2's intersection: our key's schemes against the client's offer,
/// in our preference order so the choice is ours among what it allows.
///
/// `restrict` is the embedder's narrowing, and when present its order
/// wins over the key's — a deployment that lists rsa_pss_rsae_sha512
/// first meant it. A scheme in `restrict` that the key cannot produce
/// simply never matches, which is how naming one we do not hold becomes
/// a `HandshakeFailure` rather than a silent substitution.
fn selectScheme(
    hello: *const client_hello.ClientHello,
    credentials: *const Credentials,
    restrict: ?[]const u16,
) ?backend.SignatureScheme {
    const supported = credentials.signer.supported();
    assert(supported.len >= 1);
    if (restrict) |allowed| {
        for (allowed) |wanted| {
            if (!hello.offersScheme(wanted)) continue;
            for (supported) |scheme| {
                if (@intFromEnum(scheme) == wanted) return scheme;
            }
        }
        return null;
    }
    for (supported) |scheme| {
        if (hello.offersScheme(@intFromEnum(scheme))) return scheme;
    }
    return null;
}

/// Our preference order: AES-128-GCM leads (hardware-everywhere), then
/// ChaCha20 ahead of AES-256 — the §B.4 trio, no more. This sentence
/// had drifted onto `selectScheme` above, where it described neither the
/// parameters nor the return.
fn negotiateSuite(hello: *const client_hello.ClientHello) ?CipherSuite {
    const preference = [_]CipherSuite{
        .aes_128_gcm_sha256,
        .chacha20_poly1305_sha256,
        .aes_256_gcm_sha384,
    };
    for (preference) |suite| {
        if (hello.offersSuite(suite)) return suite;
    }
    return null;
}

fn captureSessionEcho(self: *ServerHandshake, hello: *const client_hello.ClientHello) void {
    assert(hello.legacy_session_id.len <= 32);
    if (self.state == .awaiting_retry_client_hello) return; // Echo what CH1 set.
    self.session_echo_bytes = @intCast(hello.legacy_session_id.len);
    @memcpy(self.session_echo[0..hello.legacy_session_id.len], hello.legacy_session_id);
}

fn sendHelloRetry(self: *ServerHandshake, ch1: []const u8, suite: CipherSuite, out: []u8) Error!Event {
    assert(self.state == .awaiting_client_hello);
    assert(self.ladder == null);
    self.ladder = Ladder.initFor(suite);
    var message_buffer: [server_messages.server_hello_bytes_max]u8 = undefined;
    const echo = self.session_echo[0..self.session_echo_bytes];
    const hrr = server_messages.helloRetryRequest(&message_buffer, echo, suite, @intFromEnum(self.key_share_group));
    switch (self.ladder.?) {
        inline else => |*arm| arm.absorbRetryClientHello(ch1, hrr),
    }
    var builder = @import("wire.zig").Builder.init(out);
    appendPlaintextRecord(&builder, .handshake, hrr);
    builder.putSlice(&server_messages.change_cipher_spec_record);
    self.state = .awaiting_retry_client_hello;
    return .{ .send = builder.written() };
}

/// §4.2.10 and §8, as one question: may this hello's early data be
/// read rather than discarded?
///
/// Every clause is a refusal that costs the client one round trip and
/// nothing else, which is why they are all written as "no unless".
/// Three of them are opt-ins the embedder has to positively supply — a
/// clock, a register, and a ticket that carried 0-RTT terms — because
/// the failure of any one of them is a replay, and defaults that mean
/// "yes" are how that happens.
fn admitEarlyData(
    self: *ServerHandshake,
    hello: *const client_hello.ClientHello,
    selected: *const SelectedPsk,
    suite: CipherSuite,
) bool {
    if (!hello.early_data) return false;
    // §4.1.2/§4.2.10: early data is not permitted after a
    // HelloRetryRequest, and this is the state that says there was one.
    if (self.state != .awaiting_client_hello) return false;
    // §4.2.10: "the server MUST ... only accept early data if the PSK
    // selected is the first one offered". A server that accepted on a
    // later identity would let a client attach 0-RTT to a ticket it
    // listed as a fallback.
    if (selected.index != 0) return false;
    const terms = selected.early_data orelse return false;
    if (terms.bytes_max == 0) return false;
    // §4.2.10 again: the suite must be the ticket's own. Two of our
    // three share a hash, so the PSK's length does not settle this.
    if (terms.suite != suite) return false;
    const now_ms = self.config.now_ms orelse return false;
    const issued = selected.issued orelse return false;
    const register = self.config.strike_register orelse return false;
    // §8.3 before §8.2, and the order is the point: a hello whose age is
    // not plausible must not spend a slot in the register on its way to
    // being refused, or an attacker with a stream of stale hellos
    // evicts nothing and denies everything.
    if (!anti_replay.ageIsPlausible(&.{
        .obfuscated_age = selected.obfuscated_age,
        .age_add = issued.age_add,
        .issued_at_ms = issued.at_ms,
        .now_ms = now_ms,
    })) return false;
    return register.admit(selected.binder[0..selected.binder_bytes], now_ms);
}

fn acceptClientHello(
    self: *ServerHandshake,
    hello: *const client_hello.ClientHello,
    message: []const u8,
    suite: CipherSuite,
    selected_psk: ?SelectedPsk,
    out: []u8,
) Error!Event {
    const group = self.key_share_group;
    const peer_share = hello.keyShareFor(@intFromEnum(group)).?;
    const first_flight = self.state == .awaiting_client_hello;
    if (first_flight) {
        assert(self.ladder == null);
        self.ladder = Ladder.initFor(suite);
    }
    const private_key = self.config.key_share_private[0..group.privateBytes()];
    // One `KeyShare` for both halves of the answer. The pair used to be
    // an agreement and a separate `keySharePublic`, which multiplied by
    // the base point twice — once inside the agreement, discarded, and
    // once for the share on the wire (bench/README.md).
    var key_share = try backend.KeyShare.init(group, private_key);
    defer key_share.deinit();
    var shared_buffer: [backend.group_shared_bytes_max]u8 = undefined;
    defer std.crypto.secureZero(u8, &shared_buffer);
    const shared = try key_share.agree(peer_share, &shared_buffer);
    const public_key = key_share.publicValue();

    var message_buffer: [server_messages.server_hello_bytes_max]u8 = undefined;
    const echo = self.session_echo[0..self.session_echo_bytes];
    const hello_bytes = server_messages.serverHello(
        &message_buffer,
        &self.config.server_random,
        echo,
        suite,
        @intFromEnum(group),
        public_key,
        if (selected_psk) |psk| psk.index else null,
    );
    self.resumed = selected_psk != null;

    const selected_alpn = try self.selectAlpn(hello);
    const accept_early = if (selected_psk) |*psk| self.admitEarlyData(hello, psk, suite) else false;
    if (accept_early) {
        self.early_data_accepted = true;
        self.early_data_bytes_max = selected_psk.?.early_data.?.bytes_max;
        // Nothing left to skip: the records that follow are ours to
        // open, and `skippingEarlyData` must not also claim them.
        self.early_data_offered = false;
    }
    switch (self.ladder.?) {
        inline else => |*arm| {
            arm.absorbMessage(message);
            const psk_slice: ?[]const u8 = if (selected_psk) |*psk| psk.psk[0..psk.psk_bytes] else null;
            // Between the two absorbs, and only here: the early secret
            // is derived over the ClientHello alone.
            if (accept_early) try arm.startEarlyKeys(psk_slice.?);
            arm.absorbMessage(hello_bytes);
            try arm.startHandshakeKeys(shared, psk_slice);
            const flight = try self.buildFlightPlaintext(arm, selected_alpn, accept_early);
            var builder = @import("wire.zig").Builder.init(out);
            appendPlaintextRecord(&builder, .handshake, hello_bytes);
            if (first_flight) builder.putSlice(&server_messages.change_cipher_spec_record);
            const sealed = try arm.send.?.seal(.handshake, flight, builder.bytes[builder.index..]);
            builder.index += sealed.len;
            try arm.finishFlight();
            self.state = if (accept_early) .awaiting_end_of_early_data else .awaiting_finished;
            return .{ .send = builder.written() };
        },
    }
}

/// EncryptedExtensions + Certificate + CertificateVerify + Finished, as
/// one plaintext run in the caller's flight buffer, absorbing each into
/// the transcript at the §4.4.1 points. `arm` is one `LadderOf(suite)`
/// instance, concrete at every call site via the caller's `inline else`.
fn buildFlightPlaintext(
    self: *ServerHandshake,
    arm: anytype,
    selected_alpn: ?[]const u8,
    early_data: bool,
) Error![]const u8 {
    const flight = self.config.flight;
    var builder = @import("wire.zig").Builder.init(flight);

    const extensions = server_messages.encryptedExtensions(
        flight[builder.index..],
        selected_alpn,
        early_data,
    );
    builder.index += extensions.len;
    arm.absorbMessage(extensions);

    // §4.1.1: a PSK authenticates the session, so a resumed flight is
    // EncryptedExtensions and Finished — no certificate, nothing signed.
    var chain_bytes: usize = 0;
    if (!self.resumed) {
        const chain = server_messages.certificateChain(
            flight[builder.index..],
            self.config.credentials.chain(),
        );
        chain_bytes = chain.len;
        builder.index += chain.len;
        arm.absorbMessage(chain);

        var content_buffer: [server_messages.certificate_verify_content_bytes_max]u8 = undefined;
        const to_sign = server_messages.certificateVerifyContent(.server, &arm.transcriptHash(), &content_buffer);
        var signature_buffer: [backend.signature_bytes_max]u8 = undefined;
        const signature = try self.config.credentials.signer.sign(
            self.signature_scheme,
            to_sign,
            &signature_buffer,
        );
        const verify_message = server_messages.certificateVerify(
            flight[builder.index..],
            @intFromEnum(self.signature_scheme),
            signature,
        );
        builder.index += verify_message.len;
        arm.absorbMessage(verify_message);
    }

    const verify_data = arm.serverFinishedVerifyData();
    const finished_message = server_messages.finished(flight[builder.index..], &verify_data);
    builder.index += finished_message.len;
    arm.absorbMessage(finished_message);

    assert(builder.index <= flight.len);
    // A resumed flight is EncryptedExtensions + Finished; a full one adds
    // the chain and the signature. The floor is measured against the
    // chain we just encoded rather than against a guess at how big a
    // certificate ought to be — a constant here once fired on a
    // legitimately small ECDSA leaf, which is the embedder's choice to
    // make and not ours to assert about.
    assert(builder.index >= 40);
    if (self.resumed) assert(chain_bytes == 0);
    // CertificateVerify and Finished both follow the chain, and neither
    // is empty: a header, a scheme, a signature, a MAC.
    if (!self.resumed) assert(builder.index > chain_bytes + 40);
    return flight[0..builder.index];
}

/// RFC 7301 §3.2: if the client offered ALPN and we speak one of its
/// protocols, select it; offered-but-no-overlap is a fatal alert; no
/// offer means no extension.
fn selectAlpn(self: *const ServerHandshake, hello: *const client_hello.ClientHello) Error!?[]const u8 {
    const offered = hello.alpn_wire orelse return null;
    const ours = self.config.alpn orelse return null;
    assert(ours.len >= 1);
    assert(offered.len >= 4); // Validated at extension parse.
    var cursor = @import("wire.zig").Cursor.init(offered);
    const list_bytes = cursor.takeU16() catch return error.MalformedExtension;
    if (list_bytes != cursor.remaining()) return error.MalformedExtension;
    var entries: u8 = 0;
    while (cursor.remaining() > 0) : (entries += 1) {
        if (entries == 16) return error.MalformedExtension;
        assert(entries < 16);
        const name_bytes = cursor.takeByte() catch return error.MalformedExtension;
        if (name_bytes == 0) return error.MalformedExtension;
        const name = cursor.takeSlice(name_bytes) catch return error.MalformedExtension;
        if (std.mem.eql(u8, name, ours)) return ours;
    }
    return error.NoApplicationProtocol;
}

fn handleProtectedRecord(self: *ServerHandshake, wire_record: []const u8, out: []u8) Error!?Event {
    // Readable, not connected: §6.1 leaves the read side open after our
    // own close_notify, and closing it there is what made a truncated
    // shutdown indistinguishable from an orderly one.
    switch (self.state) {
        .awaiting_end_of_early_data, .awaiting_finished, .connected, .close_sent => {},
        else => return error.UnexpectedMessage,
    }
    assert(self.ladder != null);
    // No length assertion here. §5.1 lets an application_data record be
    // empty on the wire — `record.parseHeader` admits exactly that case
    // and refuses it for every other content type — so a record whose
    // length is zero is legal framing a peer can send at will, and
    // asserting it away aborted the process. `Protector.open` already
    // holds the real minimum (a header, a tag, and one inner byte) and
    // answers a short record with `BadInnerPlaintext`, which is what a
    // peer deserves. TLS-Anvil found this.
    switch (self.ladder.?) {
        inline else => |*arm| {
            const opened = (switch (self.state) {
                // §4.2.10's own keys, and their own sequence space: the
                // early data and the Finished that follows it are two
                // different protectors over the same record type.
                .awaiting_end_of_early_data => arm.early_recv.?.open(wire_record, out),
                .awaiting_finished => arm.recv.?.open(wire_record, out),
                .connected, .close_sent => arm.session.?.recv.open(wire_record, out),
                else => unreachable, // The guard above admits only these three.
            }) catch |err| {
                // §4.2.10's trial decryption. A record that will not open
                // under the handshake key, on a connection whose hello
                // offered 0-RTT, is the early data we declined — and it
                // has to be told from the client's Finished *here*,
                // because that travels as an application_data record
                // too. Skipping by content type discards the Finished
                // and wedges the handshake.
                if (self.openFailureIsEarlyData(err)) {
                    return self.skipEarlyData(wire_record);
                }
                return err;
            };
            // §4.2.10's search ends at the first record that opens: that
            // is "the first non-0-RTT message", and everything after it
            // is ours to read. Without this the window stays open and a
            // peer can put early data *behind* the Finished — BoGo's
            // `SkipEarlyData-Interleaved-TLS13` splits one across two
            // records and wedges an early-data record into the gap,
            // which must earn a decryption failure and not a discard.
            self.early_data_offered = false;
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
                    return self.handlePlaintextAlert(plaintext);
                },
                .handshake => return self.handleProtectedHandshake(arm, plaintext, out),
                .application_data => {
                    try self.refuseInterleavedRecord();
                    if (self.state == .awaiting_end_of_early_data) {
                        return self.acceptEarlyData(plaintext);
                    }
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

/// `arm` is one `LadderOf(suite)` instance, always reached through the
/// caller's `inline else` so the type is concrete at every call site.
/// One accepted early-data record, counted against the ticket's own
/// promise. §4.6.1's `max_early_data_size` is what the client sized its
/// send against, so going past it is not a client we issued that ticket
/// to — and the count is of decrypted content, which is what the RFC
/// measures.
fn acceptEarlyData(self: *ServerHandshake, plaintext: []const u8) Error!?Event {
    assert(self.early_data_accepted);
    assert(self.state == .awaiting_end_of_early_data);
    self.early_data_bytes +|= @intCast(plaintext.len);
    if (self.early_data_bytes > self.early_data_bytes_max) return error.TooMuchEarlyData;
    return .{ .application_data = plaintext };
}

fn handleProtectedHandshake(self: *ServerHandshake, arm: anytype, plaintext: []const u8, out: []u8) Error!?Event {
    assert(plaintext.len >= 1);
    try self.assembler.push(plaintext);
    if (self.state == .awaiting_end_of_early_data) {
        // §4.5: `struct {} EndOfEarlyData`, under the early keys, and
        // the only handshake message that may arrive here. It joins the
        // transcript — §4.4 puts it in the client's Finished context and
        // not in §7.1's application secrets, which is why the ladder
        // keeps two hashes.
        const message = (try self.assembler.next()) orelse return null;
        if (message.messageType() != .end_of_early_data) return error.UnexpectedMessage;
        if (message.body().len != 0) return error.MalformedMessage;
        // Nothing may ride behind it: what follows is under other keys.
        if (!self.assembler.empty()) return error.UnexpectedMessage;
        arm.absorbMessage(message.bytes);
        arm.finishEarlyData();
        self.state = .awaiting_finished;
        return null;
    }
    if (self.state != .awaiting_finished) return self.nextPostHandshake(arm, out);
    const message = (try self.assembler.next()) orelse return null;
    if (message.messageType() != .finished) return error.UnexpectedMessage;
    // The Finished is the last thing in its flight; anything packed
    // after it is arriving before the keys that would carry it.
    if (!self.assembler.empty()) return error.UnexpectedMessage;
    if (!arm.verifyClientFinished(message)) return error.DecryptError;
    try arm.startApplicationKeys(message);
    self.state = .connected;
    return .connected;
}

/// One post-handshake message, already pulled from the assembler. Null
/// is a message consumed in silence, never "no more messages" — see
/// `nextPostHandshake`, which is the only caller and the only place
/// allowed to tell those apart.
fn dispatchPostHandshake(
    self: *ServerHandshake,
    arm: anytype,
    message: handshake.Message,
    out: []u8,
) Error!?Event {
    // §4.6.3 is the only post-handshake message a server hears; a client
    // has no tickets to send and no certificates to update.
    if (message.messageType() != .key_update) return error.UnexpectedMessage;
    return self.handleKeyUpdate(arm, message, out);
}

/// The next post-handshake message that has something to say, or null
/// once the assembler holds no more complete ones.
///
/// The skipping is the point. A KeyUpdate can be consumed and produce
/// nothing — `update_not_requested`, or one arriving after our own
/// close_notify — and returning that to the caller as an event would
/// end a `while (event) |ready|` loop on a message that was not the
/// last, stranding whatever the peer packed behind it. Null still comes
/// only from `assembler.next()`, which is what docs/BOGO.md finding 1
/// requires; this loop is how both roles keep that promise while the
/// caller gets an ordinary iterator.
///
/// Bounded by the flood ceiling rather than by a number chosen here:
/// every silent message is a KeyUpdate, since `dispatchPostHandshake`
/// refuses each other type, and `observeKeyUpdate` fails the 33rd in a
/// row.
fn nextPostHandshake(self: *ServerHandshake, arm: anytype, out: []u8) Error!?Event {
    assert(self.readable());
    var silent: u8 = 0;
    while (try self.assembler.next()) |message| : (silent += 1) {
        assert(silent <= flood.key_updates_max);
        if (try self.dispatchPostHandshake(arm, message, out)) |event| return event;
    }
    return null;
}

/// The next event from a record already handed to `handleRecord`.
///
/// One record may carry more than one post-handshake message — §5.1 lets
/// a record hold several, and both Go and OpenSSL pack them — so
/// `handleRecord` returns the first and this returns the rest. Call it
/// until it answers null.
///
/// Null means one thing only: the assembler holds no further complete
/// message. It never means "the last message resolved to nothing" —
/// that is `nextPostHandshake`'s job to skip past, and inferring the
/// end from a dispatch result is docs/BOGO.md finding 1.
///
/// Every event borrows `out`, this one included, so consume an event
/// before asking for the next: the bytes behind the previous one are
/// gone once this writes.
pub fn drain(self: *ServerHandshake, out: []u8) Error!?Event {
    assert(out.len >= out_bytes_min);
    // Only the post-handshake stream is drained. A flight is assembled
    // by `handleRecord` itself, and a Finished admits nothing after it.
    if (self.state == .awaiting_finished) return null;
    if (!self.readable()) return null;
    if (self.ladder == null) return null;
    errdefer self.state = .failed;
    switch (self.ladder.?) {
        inline else => |*arm| return self.nextPostHandshake(arm, out),
    }
}

/// §4.6.3, receive side, delegated to the shared session-keys logic. The
/// decrypted plaintext was already copied into the assembler, so `out`
/// is free to carry any response.
fn handleKeyUpdate(self: *ServerHandshake, arm: anytype, message: handshake.Message, out: []u8) Error!?Event {
    assert(self.readable());
    assert(arm.session != null);
    // Counted before the rotation, because deriving the next generation
    // is the work a flood is buying (flood.zig).
    try self.flood_guard.observeKeyUpdate();
    const response = try arm.session.?.processKeyUpdate(message.body(), out);
    // §6.1: "any data received after a closure alert has been received
    // MUST be ignored" is the peer's rule, and ours is the mirror — we
    // sent close_notify, so nothing further goes out, including a
    // KeyUpdate the peer asked us to send back. Our receive side still
    // rotated, which is what lets us keep reading to its close_notify.
    if (self.state == .close_sent) return null;
    if (response) |sealed| return .{ .send = sealed };
    return null;
}

/// §4.6.3, send side. `request_update` asks the peer to rotate too — the
/// lever for §5.5 sequence-budget hygiene.
pub fn sendKeyUpdate(self: *ServerHandshake, request_update: bool, out: []u8) Error![]const u8 {
    assert(self.writable());
    assert(out.len >= record.header_bytes + handshake.header_bytes + 1 + 256);
    errdefer self.state = .failed;
    switch (self.ladder.?) {
        inline else => |*arm| return arm.session.?.initiateKeyUpdate(request_update, out),
    }
}

/// Seal application bytes for the peer. Legal from `connected`, and also
/// inside §2's 0.5-RTT window — see `halfRttWritable`, which is the
/// question an embedder should ask before writing there.
///
/// The failed-on-error guarantee covers this entry point too: a seal
/// failure (sequence exhaustion included) retires the machine.
pub fn sendApplicationData(self: *ServerHandshake, bytes: []const u8, out: []u8) Error![]const u8 {
    assert(self.writable() or self.halfRttWritable());
    assert(bytes.len <= record.plaintext_bytes_max);
    errdefer self.state = .failed;
    switch (self.ladder.?) {
        inline else => |*arm| {
            if (arm.session) |*session| return session.sealApplicationData(bytes, out);
            // The 0.5-RTT window, where there is no session yet. Same
            // key, same sequence — `startApplicationKeys` carries the
            // count into the session so the two never overlap.
            return arm.send.?.seal(.application_data, bytes, out);
        },
    }
}

/// Seal a close_notify and mark the machine closed (or failed, if even
/// that cannot be sealed).
pub fn sendClose(self: *ServerHandshake, out: []u8) Error![]const u8 {
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
/// handshake, or none yet — and retire the machine. §6 wants a peer told
/// *why* it was refused; every `handleRecord` error above is a refusal,
/// and without this the peer reads a reset instead of a description.
///
/// zssl still does not decide *whether* to alert: it returns errors and
/// the embedder chooses, as it chooses when to close. This is only the
/// encoder that choice needs, and `alert_bytes_min` bounds `out`.
///
/// Answers an empty slice when the alert cannot be sealed at all (a §5.5
/// exhausted sequence space); the embedder closes on either answer.
pub fn sendAlert(self: *ServerHandshake, description: alert.Description, out: []u8) []const u8 {
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
            // Application keys first: once they exist the handshake
            // protectors are gone, and §5's rule is that whatever the
            // record layer is currently protecting, the alert is too.
            if (arm.session) |*session| {
                return session.send.seal(.alert, &body, out) catch out[0..0];
            }
            if (arm.send) |*protector| {
                return protector.seal(.alert, &body, out) catch out[0..0];
            }
        },
    };
    // No keys yet — a ClientHello that never got as far as a suite. §5.1
    // says plaintext, and that is what the peer will be expecting.
    var builder = @import("wire.zig").Builder.init(out);
    appendPlaintextRecord(&builder, .alert, &body);
    return builder.written();
}

/// `out` for `sendAlert`: a two-byte payload, its inner content type,
/// and an AEAD tag, over a record header.
pub const alert_bytes_min: u8 = record.header_bytes + alert.bytes + 1 + cipher_suite.tag_bytes;

/// §4.6.1: derive the PSK a ticket nonce will stand for. Separate from
/// sending, because a stateless embedder needs the PSK *before* the
/// ticket that seals it exists — zoxy's `Tickets.seal` order.
/// §4.2.9: whether a NewSessionTicket may be sent to this peer. False
/// only when the ClientHello advertised key exchange modes and none of
/// them is one zssl can resume under. An embedder should ask before
/// building a ticket — the PSK derivation and sealing either side of
/// `sendNewSessionTicket` are the expensive parts, and this is free.
pub fn ticketPermitted(self: *const ServerHandshake) bool {
    assert(self.state != .awaiting_client_hello or !self.ticket_permitted);
    return self.ticket_permitted;
}

pub fn resumptionPsk(
    self: *const ServerHandshake,
    ticket_nonce: []const u8,
    out: *[cipher_suite.hash_bytes_max]u8,
) []const u8 {
    assert(self.writable());
    assert(ticket_nonce.len >= 1);
    assert(ticket_nonce.len <= 255);
    switch (self.ladder.?) {
        inline else => |*arm, comptime_suite| {
            const Schedule = key_schedule.KeySchedule(comptime_suite);
            const psk = Schedule.resumptionPsk(&arm.resumption_master, ticket_nonce);
            @memcpy(out[0..psk.len], &psk);
            return out[0..psk.len];
        },
    }
}

pub const NewSessionTicketParams = struct {
    lifetime_s: u32,
    age_add: u32,
    ticket_nonce: []const u8,
    /// The sealed ticket, opaque here — sealing is the embedder's.
    ticket: []const u8,
    /// §4.6.1's `max_early_data_size`, or null to advertise none.
    ///
    /// This is a promise, not a preference: a client that takes it up
    /// has already spent the bytes by the time we see them, so whatever
    /// goes here must match what `psk_lookup` will later answer for the
    /// same ticket. zssl cannot check that for you — the two live on
    /// opposite sides of the embedder's ticket store.
    early_data_bytes_max: ?u32 = null,
};

/// Encode and seal one NewSessionTicket onto the application stream. The
/// embedder calls this after `connected` — which is after the client's
/// Finished was processed, the ordering the ~45 ms delayed-ACK stall
/// analysis demands — once per ticket it wants to issue.
pub fn sendNewSessionTicket(
    self: *ServerHandshake,
    params: *const NewSessionTicketParams,
    out: []u8,
) Error![]const u8 {
    assert(self.writable());
    assert(params.ticket.len >= 1);
    assert(params.ticket.len <= server_messages.ticket_bytes_max);
    // §4.2.9: a ticket incompatible with every mode the client advertised
    // is one it must ignore, so sending it is a wasted flight the RFC
    // tells servers not to send. Checked before the `errdefer` below,
    // because an embedder ticketing such a client has made a policy
    // mistake rather than broken the connection — `ticketPermitted` is
    // the question it should have asked.
    if (!self.ticket_permitted) return error.TicketNotPermitted;
    errdefer self.state = .failed;
    var message_buffer: [server_messages.new_session_ticket_bytes_max]u8 = undefined;
    const message = server_messages.newSessionTicket(
        &message_buffer,
        params.lifetime_s,
        params.age_add,
        params.ticket_nonce,
        params.ticket,
        params.early_data_bytes_max,
    );
    switch (self.ladder.?) {
        inline else => |*arm| return arm.session.?.send.seal(.handshake, message, out),
    }
}

/// The suite this handshake negotiated. Available from the moment the
/// ladder exists, which is the ServerHello; an embedder sealing a
/// resumption ticket needs it to record what the PSK is bound to.
/// The suite this connection settled on. An embedder minting a ticket
/// needs it: §4.2.10 only accepts early data on a resumption that
/// negotiates the same suite the ticket was issued under, and the ticket
/// is the embedder's to seal.
pub fn cipherSuite(self: *const ServerHandshake) CipherSuite {
    assert(self.ladder != null);
    return self.ladder.?;
}

pub const Direction = session_keys.Direction;

/// The kTLS hand-over: one direction's application traffic key, IV, and
/// next sequence number, in kernel-ready terms (§4 of docs/DESIGN.md).
/// Reflects the current §4.6.3 generation — export after any KeyUpdate,
/// never before.
pub fn exportKeyMaterial(self: *const ServerHandshake, direction: Direction) ktls.KeyMaterial {
    // Not `writable()`: handing a half-closed connection to the kernel
    // would hand it a direction that is already over.
    assert(self.state == .connected);
    switch (self.ladder.?) {
        inline else => |*arm| return arm.session.?.exportMaterial(direction),
    }
}

fn appendPlaintextRecord(
    builder: *@import("wire.zig").Builder,
    content_type: record.ContentType,
    payload: []const u8,
) void {
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
    aes_128_gcm_sha256: LadderOf(.aes_128_gcm_sha256),
    aes_256_gcm_sha384: LadderOf(.aes_256_gcm_sha384),
    chacha20_poly1305_sha256: LadderOf(.chacha20_poly1305_sha256),

    fn initFor(suite: CipherSuite) Ladder {
        return switch (suite) {
            .aes_128_gcm_sha256 => .{ .aes_128_gcm_sha256 = .empty },
            .aes_256_gcm_sha384 => .{ .aes_256_gcm_sha384 = .empty },
            .chacha20_poly1305_sha256 => .{ .chacha20_poly1305_sha256 = .empty },
        };
    }
};

/// Everything whose size depends on the negotiated suite: transcript,
/// schedule, secrets, protectors. One arm of `Ladder` per suite; the
/// machine dispatches once per record and the arm's body is fully typed.
fn LadderOf(comptime suite: CipherSuite) type {
    const Hash = CipherSuite.HashType(suite);
    const Schedule = key_schedule.KeySchedule(suite);
    const Transcript = transcript.Transcript(Hash);
    const hash_bytes = Hash.digest_length;

    return struct {
        transcript: Transcript,
        schedule: ?Schedule,
        /// Client handshake traffic secret — client Finished verifies
        /// against it after the flight is long gone.
        client_handshake_traffic: [hash_bytes]u8,
        /// Server handshake traffic secret — our own Finished derives
        /// from it mid-flight.
        server_handshake_traffic: [hash_bytes]u8,
        /// Transcript hash through the server Finished: what §7.1's
        /// application secrets derive from.
        finished_hash: [hash_bytes]u8,
        /// What the *client's* Finished MACs, which is not the same
        /// thing once 0-RTT is accepted. §4.4's table gives the client's
        /// handshake context as "ClientHello ... later of server
        /// Finished/EndOfEarlyData", and §7.1 gives the application
        /// secrets "ClientHello...server Finished" — so an EndOfEarlyData
        /// arriving after our flight moves one and not the other. They
        /// are equal until that message exists, and conflating them is a
        /// resumption that verifies fine until the first client that
        /// actually sends early data.
        client_finished_hash: [hash_bytes]u8,
        /// Application traffic secrets, staged at flight end; the live
        /// session keys are built from them at `connected`.
        client_application_traffic: [hash_bytes]u8,
        server_application_traffic: [hash_bytes]u8,
        /// §7.1's last derivation, available from `connected`: what every
        /// ticket's PSK descends from.
        resumption_master: [hash_bytes]u8,
        /// §4.2.10's receive-only protector for accepted early data,
        /// keyed off the ClientHello alone and retired at
        /// EndOfEarlyData. Never a `send` counterpart: 0-RTT is one
        /// direction by construction.
        early_recv: ?protect.Protector,
        /// Handshake-phase protectors; retired at `connected`.
        recv: ?protect.Protector,
        send: ?protect.Protector,
        /// The connection's keys from `connected` on: protectors, §4.6.3
        /// rotation, kTLS export.
        session: ?session_keys.SessionKeys(suite),

        const Self = @This();

        pub const empty: Self = .{
            .transcript = .empty,
            .schedule = null,
            .client_handshake_traffic = undefined,
            .server_handshake_traffic = undefined,
            .finished_hash = undefined,
            .client_finished_hash = undefined,
            .client_application_traffic = undefined,
            .server_application_traffic = undefined,
            .resumption_master = undefined,
            .early_recv = null,
            .recv = null,
            .send = null,
            .session = null,
        };

        fn deinit(self: *Self) void {
            if (self.early_recv) |*protector| protector.deinit();
            if (self.recv) |*protector| protector.deinit();
            if (self.send) |*protector| protector.deinit();
            if (self.session) |*session| session.deinit();
            if (self.schedule) |*schedule| schedule.wipe();
            std.crypto.secureZero(u8, &self.client_finished_hash);
            std.crypto.secureZero(u8, &self.client_handshake_traffic);
            std.crypto.secureZero(u8, &self.server_handshake_traffic);
            std.crypto.secureZero(u8, &self.client_application_traffic);
            std.crypto.secureZero(u8, &self.server_application_traffic);
            std.crypto.secureZero(u8, &self.resumption_master);
            self.* = undefined;
        }

        fn absorbMessage(self: *Self, message: []const u8) void {
            self.transcript.update(message);
        }

        fn transcriptHash(self: *const Self) [hash_bytes]u8 {
            return self.transcript.currentHash();
        }

        /// §4.4.1: after a HelloRetryRequest, CH1 is replaced in the
        /// transcript by a synthetic message_hash message.
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

        /// ClientHello..ServerHello are in the transcript: derive the
        /// handshake secrets and bring up the handshake-key protectors.
        /// `psk` is the accepted pre-shared key — from a ticket or from
        /// out of band, the schedule cannot tell and does not need to —
        /// or null for a full handshake. Either way the (EC)DHE share is
        /// mixed: psk_dhe_ke is the only mode this library speaks.
        /// §7.1's other child of the early secret: the receive keys for
        /// 0-RTT data, derived from `Derive-Secret(early, "c e traffic",
        /// ClientHello)`.
        ///
        /// Called between absorbing the ClientHello and absorbing the
        /// ServerHello, and it cannot be called anywhere else: the
        /// transcript this reads is the hello *alone*, which is the
        /// property that lets these keys exist before a ServerHello does.
        /// A schedule of its own, thrown away here — `startHandshakeKeys`
        /// builds the connection's from the same PSK a moment later, and
        /// sharing one across that boundary would mean advancing a
        /// schedule the early keys still needed.
        fn startEarlyKeys(self: *Self, psk: []const u8) protect.Error!void {
            assert(self.schedule == null);
            assert(self.early_recv == null);
            assert(psk.len >= 1 and psk.len <= cipher_suite.hash_bytes_max);
            assert(self.transcript.messages_seen == 1);
            var schedule = Schedule.initEarly(psk);
            defer schedule.wipe();
            const hello_hash = self.transcriptHash();
            const early_traffic = schedule.deriveAt(.early, "c e traffic", &hello_hash);
            const keys = Schedule.trafficKeys(&early_traffic);
            self.early_recv = try protect.Protector.init(suite, &keys.key, &keys.iv);
        }

        /// EndOfEarlyData (§4.5) has been absorbed: the early keys have
        /// nothing left to open, and the client's Finished now MACs a
        /// transcript one message longer than the server's did.
        fn finishEarlyData(self: *Self) void {
            assert(self.early_recv != null);
            self.early_recv.?.deinit();
            self.early_recv = null;
            self.client_finished_hash = self.transcriptHash();
        }

        fn startHandshakeKeys(self: *Self, shared: []const u8, psk: ?[]const u8) protect.Error!void {
            assert(self.schedule == null);
            assert(self.recv == null);
            // A resumption PSK is a hash long by §4.6.1's derivation; an
            // external one is whatever the peers agreed, and §4.2.11 sets
            // no length for it. The bound is a range because the value
            // arrives from an embedder answering `psk_lookup` about an
            // identity the *peer* chose — an equality here was reachable
            // from the wire the moment external PSKs became acceptable.
            if (psk) |bytes| assert(bytes.len >= 1 and bytes.len <= cipher_suite.hash_bytes_max);
            var schedule = Schedule.initEarly(psk);
            schedule.advanceToHandshake(shared);
            const hello_hash = self.transcriptHash();
            self.client_handshake_traffic = schedule.deriveAt(.handshake, "c hs traffic", &hello_hash);
            self.server_handshake_traffic = schedule.deriveAt(.handshake, "s hs traffic", &hello_hash);
            const receive_keys = Schedule.trafficKeys(&self.client_handshake_traffic);
            const transmit_keys = Schedule.trafficKeys(&self.server_handshake_traffic);
            self.recv = try protect.Protector.init(suite, &receive_keys.key, &receive_keys.iv);
            errdefer {
                self.recv.?.deinit();
                self.recv = null;
            }
            self.send = try protect.Protector.init(suite, &transmit_keys.key, &transmit_keys.iv);
            self.schedule = schedule;
        }

        /// §4.4.4, called with the transcript standing after
        /// CertificateVerify.
        fn serverFinishedVerifyData(self: *const Self) [hash_bytes]u8 {
            assert(self.schedule != null);
            assert(self.schedule.?.stage == .handshake);
            const key = Schedule.finishedKey(&self.server_handshake_traffic);
            const flight_hash = self.transcriptHash();
            return Schedule.verifyData(&key, &flight_hash);
        }

        /// The server flight is fully in the transcript: pin the hash the
        /// client's Finished must MAC, move to master, stage the
        /// application traffic keys (§7.1's derivation point), and put
        /// the send side onto them.
        ///
        /// That last step is §4.4.4: the server's write keys become
        /// application keys the moment its Finished goes out — which is
        /// what makes 0.5-RTT data legal — and the client installs its
        /// application *read* keys as soon as it has verified that
        /// Finished. A server still sealing with the handshake protector
        /// in that window sends records its peer cannot open, and the
        /// record this window exists to send is an alert: the refusal of
        /// a client Finished that does not verify. tlsfuzzer's
        /// `test-tls13-empty-alert` reports it as a bad record MAC.
        ///
        /// The receive side keeps its handshake protector, because the
        /// client's Finished is still sealed with the client's handshake
        /// keys.
        fn finishFlight(self: *Self) protect.Error!void {
            assert(self.schedule != null);
            assert(self.schedule.?.stage == .handshake);
            assert(self.send != null);
            self.finished_hash = self.transcriptHash();
            // Equal here, and they stay equal unless an EndOfEarlyData
            // arrives to move the client's on.
            self.client_finished_hash = self.finished_hash;
            self.schedule.?.advanceToMaster();
            self.client_application_traffic = self.schedule.?.deriveAt(.master, "c ap traffic", &self.finished_hash);
            self.server_application_traffic = self.schedule.?.deriveAt(.master, "s ap traffic", &self.finished_hash);
            const transmit_keys = Schedule.trafficKeys(&self.server_application_traffic);
            const application_send = try protect.Protector.init(suite, &transmit_keys.key, &transmit_keys.iv);
            // Only swapped once the new one exists, so a failure here
            // leaves a machine that can still seal its own alert. The
            // handshake protector has nothing left to write: the flight
            // was its last record.
            self.send.?.deinit();
            self.send = application_send;
        }

        /// §4.4.4, and one verdict for both ways to fail it: "Recipients
        /// of Finished messages MUST verify that the contents are
        /// correct and if incorrect MUST terminate the connection with a
        /// `decrypt_error` alert." A body that is not the negotiated
        /// hash's length is contents that are incorrect — the only field
        /// this message has — so it takes the same answer as one that
        /// decodes and does not match.
        ///
        /// §6.2's decode_error would be the other reading, and tlsfuzzer
        /// and OpenSSL take it. BoringSSL takes this one, and BoGo's
        /// `TrailingMessageData-TLS13-*Finished` is where it says so.
        /// Both corpora run here and they disagree; §4.4.4 is the more
        /// specific rule and this follows it. docs/TLSFUZZER.md finding 7
        /// records the split, and the length that *no* hash could be is
        /// settled earlier, in `handshake.Assembler`, where the two
        /// corpora agree.
        fn verifyClientFinished(self: *const Self, message: handshake.Message) bool {
            assert(self.schedule != null);
            assert(self.schedule.?.stage == .master);
            if (message.body().len != hash_bytes) return false;
            const key = Schedule.finishedKey(&self.client_handshake_traffic);
            const expected = Schedule.verifyData(&key, &self.client_finished_hash);
            return std.crypto.timing_safe.eql(
                [hash_bytes]u8,
                message.body()[0..hash_bytes].*,
                expected,
            );
        }

        /// Client Finished verified: absorb it (the resumption master
        /// derives from it), retire the handshake protectors, bring up
        /// the session keys.
        fn startApplicationKeys(self: *Self, finished_message: handshake.Message) session_keys.Error!void {
            assert(self.schedule != null);
            assert(self.schedule.?.stage == .master);
            assert(self.session == null);
            // The session's send protector is built from the same secret
            // `finishFlight` already keyed `send` with, so its nonce
            // sequence has to continue rather than restart — §2's
            // 0.5-RTT data is written under exactly that key, before
            // this runs. This assertion used to demand a sequence of
            // zero, on the reasoning that `sendAlert` was the only
            // writer in the window and it retires the machine; 0.5-RTT
            // is the second writer, so the count travels instead.
            self.transcript.update(finished_message.bytes);
            // §7.1: resumption_master derives from the transcript through
            // the client Finished — this is the only window it exists in.
            self.resumption_master = self.schedule.?.deriveAt(.master, "res master", &self.transcript.currentHash());
            self.session = try session_keys.SessionKeys(suite).init(
                &self.server_application_traffic,
                &self.client_application_traffic,
                self.send.?.sequence,
            );
            // The session owns rotation from here, so these staged copies
            // are generation-0 material with no further use — wipe them
            // now rather than at teardown.
            std.crypto.secureZero(u8, &self.server_application_traffic);
            std.crypto.secureZero(u8, &self.client_application_traffic);
            self.recv.?.deinit();
            self.send.?.deinit();
            self.recv = null;
            self.send = null;
        }
    };
}
