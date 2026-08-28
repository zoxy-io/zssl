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
    /// Caller-owned space for handshake-message reassembly (client side
    /// of the conversation). A ClientHello budget: 8 KiB is generous.
    reassembly: []u8,
    /// Caller-owned space for flight plaintext assembly; must hold the
    /// certificate chain plus ~1 KiB.
    flight: []u8,
    /// The resumption seam: given an offered ticket identity, answer the
    /// PSK it stands for, or null to fall back to a full handshake. The
    /// embedder owns ticket sealing, lifetime, and age policy — this
    /// machine owns only the binder check that follows.
    psk_lookup: ?PskLookup = null,
};

pub const PskLookup = struct {
    context: *anyopaque,
    /// Writes the PSK into `psk_out` and returns its length (one hash
    /// length), or null when the identity is not ours to accept.
    lookup: *const fn (
        context: *anyopaque,
        identity: []const u8,
        obfuscated_age: u32,
        psk_out: *[cipher_suite.hash_bytes_max]u8,
    ) ?u8,
};

const SelectedPsk = struct {
    psk: [cipher_suite.hash_bytes_max]u8,
    psk_bytes: u8,
    index: u16,
};

pub const Event = union(enum) {
    none,
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
} || session_keys.Error || flood.Error;

/// `out` for `handleRecord` must hold a whole flight or a whole decrypted
/// record, whichever is larger — one wire record's bound covers both.
pub const out_bytes_min: u32 = record.wire_record_bytes_max;

pub fn init(config: *const Config) ServerHandshake {
    assert(config.reassembly.len >= 1024);
    assert(config.flight.len >= Credentials.chain_bytes_max + 1024);
    assert(config.credentials.certificate_count >= 1);
    if (config.alpn) |protocol| assert(protocol.len >= 1);
    return .{
        .state = .awaiting_client_hello,
        .config = config.*,
        .key_share_group = .x25519,
        .signature_scheme = config.credentials.signer.supported()[0],
        .ticket_permitted = false,
        .assembler = handshake.Assembler.init(config.reassembly),
        .ladder = null,
        .flood_guard = .{},
        .ccs_seen = 0,
        .session_echo_bytes = 0,
        .session_echo = undefined,
        .resumed = false,
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

/// Feed one whole wire record; act on what comes back. On any error the
/// machine is `failed` and must not be fed again — the embedder closes.
pub fn handleRecord(self: *ServerHandshake, wire_record: []const u8, out: []u8) Error!Event {
    assert(out.len >= out_bytes_min);
    assert(self.state != .failed);
    errdefer self.state = .failed;
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
            self.ccs_seen += 1;
            return .none;
        },
        .alert => return self.handlePlaintextAlert(wire_record[record.header_bytes..]),
        .handshake => return self.handlePlaintextHandshake(wire_record, out),
        .application_data => return self.handleProtectedRecord(wire_record, out),
    }
}

fn handlePlaintextAlert(self: *ServerHandshake, payload: []const u8) Error!Event {
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
            return .none;
        },
        .refuse => return error.BadAlert,
        .peer_fatal => return error.PeerAlert,
    }
}

fn handlePlaintextHandshake(self: *ServerHandshake, wire_record: []const u8, out: []u8) Error!Event {
    // Plaintext handshake records are only ever the ClientHello leg.
    switch (self.state) {
        .awaiting_client_hello, .awaiting_retry_client_hello => {},
        else => return error.UnexpectedMessage,
    }
    assert(self.ladder == null or self.state == .awaiting_retry_client_hello);
    try self.assembler.push(wire_record[record.header_bytes..]);
    const message = (try self.assembler.next()) orelse return .none;
    if (message.messageType() != .client_hello) return error.UnexpectedMessage;
    // One message per flight here: bytes after a complete ClientHello are
    // a peer talking past its own handshake.
    if (!self.assembler.empty()) return error.UnexpectedMessage;
    return self.handleClientHello(message.bytes, out);
}

fn handleClientHello(self: *ServerHandshake, message: []const u8, out: []u8) Error!Event {
    const hello = try client_hello.parse(message);
    if (!hello.supports_tls13) return error.HandshakeFailure;
    const suite = negotiateSuite(&hello) orelse return error.HandshakeFailure;
    assert(hello.offersSuite(suite));
    assert(hello.cipher_suites_wire.len >= 2);
    const selected_psk = try self.selectPsk(&hello, message, suite);
    if (selected_psk == null) {
        // A full handshake signs a CertificateVerify; a resumed one
        // authenticates by PSK and needs no common signature scheme.
        // §4.4.2: the scheme we sign under must be one the client offered,
        // and an RSA key admits three digests — so this is an
        // intersection, not an equality.
        self.signature_scheme = selectScheme(&hello, self.config.credentials) orelse
            return error.HandshakeFailure;
    }
    self.captureSessionEcho(&hello);

    if (self.state == .awaiting_retry_client_hello) {
        // §4.1.4: the retry must keep the suite and answer the demand.
        const ladder_suite: CipherSuite = self.ladder.?;
        if (suite != ladder_suite) return error.IllegalRetry;
        // The retry must answer the group we asked for, and no other.
        const retried = hello.keyShareFor(@intFromEnum(self.key_share_group)) orelse
            return error.IllegalRetry;
        _ = retried;
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
    if (hello.preferredKeyShare()) |offered| {
        // §4.2.8 leaves the choice to us among what the client sent.
        self.key_share_group = backend.Group.fromWire(offered.group).?;
        return self.acceptClientHello(&hello, message, suite, selected_psk, out);
    }
    // No share we can use. If the client says it supports a group we
    // hold, demand it (§4.1.4); if it does not, there is no handshake.
    const wanted = hello.preferredSupportedGroup() orelse return error.HandshakeFailure;
    self.key_share_group = backend.Group.fromWire(wanted).?;
    return self.sendHelloRetry(message, suite, out);
}

/// §4.2.11: walk the offered identities through the embedder's lookup;
/// the first one the embedder recognizes must carry a valid binder or
/// the handshake aborts — an attacker replaying a stolen identity does
/// not get downgraded to a full handshake, it gets refused.
///
/// PSK offers on a retry ClientHello are deliberately ignored (full
/// handshake instead): the binder there hashes the §4.4.1 surgery
/// transcript, and zssl does not carry that path untested — BoGo in
/// slice 5 is where it earns its way in.
fn selectPsk(
    self: *ServerHandshake,
    hello: *const client_hello.ClientHello,
    message: []const u8,
    suite: CipherSuite,
) Error!?SelectedPsk {
    const lookup = self.config.psk_lookup orelse return null;
    if (self.state != .awaiting_client_hello) return null;
    if (hello.preferredKeyShare() == null) return null; // psk_dhe_ke needs a share.
    if (!hello.offersPskDheKe()) return null;
    const offer = (try client_hello.parsePskOffer(hello)) orelse return null;
    assert(offer.count >= 1);
    assert(offer.binders_section_bytes < message.len);
    const truncated = message[0 .. message.len - offer.binders_section_bytes];

    var index: u8 = 0;
    while (index < offer.count) : (index += 1) {
        assert(index < client_hello.psk_identities_max);
        var selected: SelectedPsk = .{ .psk = undefined, .psk_bytes = 0, .index = index };
        const psk_bytes = lookup.lookup(
            lookup.context,
            offer.identities[index],
            offer.obfuscated_ages[index],
            &selected.psk,
        ) orelse continue;
        if (psk_bytes != suite.hashBytes()) continue; // A PSK is bound to its hash.
        selected.psk_bytes = psk_bytes;
        if (!binderMatches(suite, selected.psk[0..psk_bytes], truncated, offer.binders[index])) {
            return error.DecryptError;
        }
        return selected;
    }
    return null;
}

fn binderMatches(suite: CipherSuite, psk: []const u8, truncated: []const u8, binder: []const u8) bool {
    assert(psk.len == suite.hashBytes());
    assert(truncated.len >= handshake.header_bytes);
    switch (suite) {
        inline else => |comptime_suite| {
            const Hash = CipherSuite.HashType(comptime_suite);
            const Schedule = key_schedule.KeySchedule(comptime_suite);
            if (binder.len != Hash.digest_length) return false;
            var truncated_hash: [Hash.digest_length]u8 = undefined;
            Hash.hash(truncated, &truncated_hash, .{});
            var schedule = Schedule.initEarly(psk);
            defer schedule.wipe();
            const expected = schedule.resumptionBinder(&truncated_hash);
            return std.crypto.timing_safe.eql(
                [Hash.digest_length]u8,
                binder[0..Hash.digest_length].*,
                expected,
            );
        },
    }
}

/// Our preference order: AES-128-GCM leads (hardware-everywhere), then
/// ChaCha20 ahead of AES-256 — the §B.4 trio, no more.
/// §4.4.2's intersection: our key's schemes against the client's offer,
/// in our preference order so the choice is ours among what it allows.
fn selectScheme(
    hello: *const client_hello.ClientHello,
    credentials: *const Credentials,
) ?backend.SignatureScheme {
    const supported = credentials.signer.supported();
    assert(supported.len >= 1);
    for (supported) |scheme| {
        if (hello.offersScheme(@intFromEnum(scheme))) return scheme;
    }
    return null;
}

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
    var shared_buffer: [backend.group_shared_bytes_max]u8 = undefined;
    defer std.crypto.secureZero(u8, &shared_buffer);
    const shared = try backend.keyShareShared(group, private_key, peer_share, &shared_buffer);
    var public_buffer: [backend.group_public_bytes_max]u8 = undefined;
    const public_key = try backend.keySharePublic(group, private_key, &public_buffer);

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
    switch (self.ladder.?) {
        inline else => |*arm| {
            arm.absorbMessage(message);
            arm.absorbMessage(hello_bytes);
            const psk_slice: ?[]const u8 = if (selected_psk) |*psk| psk.psk[0..psk.psk_bytes] else null;
            try arm.startHandshakeKeys(shared, psk_slice);
            const flight = try self.buildFlightPlaintext(arm, selected_alpn);
            var builder = @import("wire.zig").Builder.init(out);
            appendPlaintextRecord(&builder, .handshake, hello_bytes);
            if (first_flight) builder.putSlice(&server_messages.change_cipher_spec_record);
            const sealed = try arm.send.?.seal(.handshake, flight, builder.bytes[builder.index..]);
            builder.index += sealed.len;
            try arm.finishFlight();
            self.state = .awaiting_finished;
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
) Error![]const u8 {
    const flight = self.config.flight;
    var builder = @import("wire.zig").Builder.init(flight);

    const extensions = server_messages.encryptedExtensions(flight[builder.index..], selected_alpn);
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

fn handleProtectedRecord(self: *ServerHandshake, wire_record: []const u8, out: []u8) Error!Event {
    // Readable, not connected: §6.1 leaves the read side open after our
    // own close_notify, and closing it there is what made a truncated
    // shutdown indistinguishable from an orderly one.
    switch (self.state) {
        .awaiting_finished, .connected, .close_sent => {},
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
            const opened = switch (self.state) {
                .awaiting_finished => try arm.recv.?.open(wire_record, out),
                .connected, .close_sent => try arm.session.?.recv.open(wire_record, out),
                else => unreachable, // The guard above admits only these three.
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
                .alert => return self.handlePlaintextAlert(plaintext),
                .handshake => return self.handleProtectedHandshake(arm, plaintext, out),
                .application_data => {
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
fn handleProtectedHandshake(self: *ServerHandshake, arm: anytype, plaintext: []const u8, out: []u8) Error!Event {
    assert(plaintext.len >= 1);
    try self.assembler.push(plaintext);
    const message = (try self.assembler.next()) orelse return .none;
    if (self.state != .awaiting_finished) {
        // §4.6.3 is the only post-handshake message a server hears; a
        // client has no tickets to send and no certificates to update.
        if (message.messageType() != .key_update) return error.UnexpectedMessage;
        if (!self.assembler.empty()) return error.UnexpectedMessage;
        return self.handleKeyUpdate(arm, message, out);
    }
    assert(self.state == .awaiting_finished);
    if (message.messageType() != .finished) return error.UnexpectedMessage;
    if (!self.assembler.empty()) return error.UnexpectedMessage;
    if (!arm.verifyClientFinished(message)) return error.DecryptError;
    try arm.startApplicationKeys(message);
    self.state = .connected;
    return .connected;
}

/// §4.6.3, receive side, delegated to the shared session-keys logic. The
/// decrypted plaintext was already copied into the assembler, so `out`
/// is free to carry any response.
fn handleKeyUpdate(self: *ServerHandshake, arm: anytype, message: handshake.Message, out: []u8) Error!Event {
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
    if (self.state == .close_sent) return .none;
    if (response) |sealed| return .{ .send = sealed };
    return .none;
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

/// Seal application bytes for the peer. Valid only while connected. The
/// failed-on-error guarantee covers this entry point too: a seal failure
/// (sequence exhaustion included) retires the machine.
pub fn sendApplicationData(self: *ServerHandshake, bytes: []const u8, out: []u8) Error![]const u8 {
    assert(self.writable());
    assert(bytes.len <= record.plaintext_bytes_max);
    errdefer self.state = .failed;
    switch (self.ladder.?) {
        inline else => |*arm| return arm.session.?.send.seal(.application_data, bytes, out),
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
    );
    switch (self.ladder.?) {
        inline else => |*arm| return arm.session.?.send.seal(.handshake, message, out),
    }
}

/// The suite this handshake negotiated. Available from the moment the
/// ladder exists, which is the ServerHello; an embedder sealing a
/// resumption ticket needs it to record what the PSK is bound to.
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
        /// Transcript hash through the server Finished: what the client's
        /// Finished MACs, and what the application secrets derive from.
        finished_hash: [hash_bytes]u8,
        /// Application traffic secrets, staged at flight end; the live
        /// session keys are built from them at `connected`.
        client_application_traffic: [hash_bytes]u8,
        server_application_traffic: [hash_bytes]u8,
        /// §7.1's last derivation, available from `connected`: what every
        /// ticket's PSK descends from.
        resumption_master: [hash_bytes]u8,
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
            .client_application_traffic = undefined,
            .server_application_traffic = undefined,
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
        /// `psk` is the accepted resumption secret, or null for a full
        /// handshake — either way the (EC)DHE share is mixed (psk_dhe_ke
        /// is the only mode this library speaks).
        fn startHandshakeKeys(self: *Self, shared: []const u8, psk: ?[]const u8) protect.Error!void {
            assert(self.schedule == null);
            assert(self.recv == null);
            if (psk) |bytes| assert(bytes.len == hash_bytes);
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

        fn verifyClientFinished(self: *const Self, message: handshake.Message) bool {
            assert(self.schedule != null);
            assert(self.schedule.?.stage == .master);
            if (message.body().len != hash_bytes) return false;
            const key = Schedule.finishedKey(&self.client_handshake_traffic);
            const expected = Schedule.verifyData(&key, &self.finished_hash);
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
            // `finishFlight` already keyed `send` with, so reaching here
            // with that protector used would restart its nonce sequence
            // under a key that had seen one. It cannot: the only writer
            // in that window is `sendAlert`, which retires the machine to
            // `failed` or `closed`, and neither state admits the client
            // Finished that calls this. The assertion is what keeps that
            // true as the code moves.
            assert(self.send.?.sequence == 0);
            self.transcript.update(finished_message.bytes);
            // §7.1: resumption_master derives from the transcript through
            // the client Finished — this is the only window it exists in.
            self.resumption_master = self.schedule.?.deriveAt(.master, "res master", &self.transcript.currentHash());
            self.session = try session_keys.SessionKeys(suite).init(
                &self.server_application_traffic,
                &self.client_application_traffic,
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
