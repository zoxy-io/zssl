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
assembler: handshake.Assembler,
ladder: ?Ladder,
/// Compatibility ChangeCipherSpec records seen; tolerated, but bounded.
ccs_seen: u8,
/// The session id to echo, captured from the (first) ClientHello.
session_echo_bytes: u8,
session_echo: [32]u8,
/// Whether this session came up on an accepted PSK — the fact behind
/// zoxy's `tls_resumed` counter.
resumed: bool,

const ServerHandshake = @This();

pub const State = enum(u8) {
    awaiting_client_hello,
    awaiting_retry_client_hello,
    awaiting_finished,
    connected,
    closed,
    failed,
};

pub const Config = struct {
    credentials: *const Credentials,
    /// Embedder-supplied entropy; zssl generates none.
    server_random: [32]u8,
    x25519_private: [32]u8,
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
    client_hello.Error || alert.ParseError || error{
    /// The record or message is legal TLS arriving at the wrong moment.
    UnexpectedMessage,
    /// No common cipher suite, group, or signature scheme (§4.1.1).
    HandshakeFailure,
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
} || session_keys.Error;

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
        .assembler = handshake.Assembler.init(config.reassembly),
        .ladder = null,
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
            // §5, D.4: a compatibility CCS is ignored wherever it lands —
            // but "ignored" is not "unbounded".
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
    if (parsed.isCloseNotify()) {
        self.state = .closed;
        return .closed;
    }
    return error.PeerAlert;
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
        const scheme = self.config.credentials.signer.scheme;
        if (!hello.offersScheme(@intFromEnum(scheme))) return error.HandshakeFailure;
    }
    self.captureSessionEcho(&hello);

    if (self.state == .awaiting_retry_client_hello) {
        // §4.1.4: the retry must keep the suite and answer the demand.
        const ladder_suite: CipherSuite = self.ladder.?;
        if (suite != ladder_suite) return error.IllegalRetry;
        if (hello.key_share_x25519 == null) return error.IllegalRetry;
        return self.acceptClientHello(&hello, message, suite, selected_psk, out);
    }

    assert(self.state == .awaiting_client_hello);
    if (hello.key_share_x25519 == null) {
        // No usable share. If the client can do x25519, demand it (§4.1.4);
        // if it cannot, there is no handshake to have.
        if (!hello.supportsGroup(client_hello.group_x25519)) return error.HandshakeFailure;
        return self.sendHelloRetry(message, suite, out);
    }
    return self.acceptClientHello(&hello, message, suite, selected_psk, out);
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
    if (hello.key_share_x25519 == null) return null; // psk_dhe_ke needs the share.
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
    const hrr = server_messages.helloRetryRequest(&message_buffer, echo, suite);
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
    assert(hello.key_share_x25519 != null);
    const first_flight = self.state == .awaiting_client_hello;
    if (first_flight) {
        assert(self.ladder == null);
        self.ladder = Ladder.initFor(suite);
    }
    var shared: [32]u8 = undefined;
    try backend.x25519Shared(&self.config.x25519_private, hello.key_share_x25519.?, &shared);
    defer std.crypto.secureZero(u8, &shared);
    var x25519_public: [32]u8 = undefined;
    try backend.x25519Public(&self.config.x25519_private, &x25519_public);

    var message_buffer: [server_messages.server_hello_bytes_max]u8 = undefined;
    const echo = self.session_echo[0..self.session_echo_bytes];
    const hello_bytes = server_messages.serverHello(
        &message_buffer,
        &self.config.server_random,
        echo,
        suite,
        &x25519_public,
        if (selected_psk) |psk| psk.index else null,
    );
    self.resumed = selected_psk != null;

    const selected_alpn = try self.selectAlpn(hello);
    switch (self.ladder.?) {
        inline else => |*arm| {
            arm.absorbMessage(message);
            arm.absorbMessage(hello_bytes);
            const psk_slice: ?[]const u8 = if (selected_psk) |*psk| psk.psk[0..psk.psk_bytes] else null;
            try arm.startHandshakeKeys(&shared, psk_slice);
            const flight = try self.buildFlightPlaintext(arm, selected_alpn);
            var builder = @import("wire.zig").Builder.init(out);
            appendPlaintextRecord(&builder, .handshake, hello_bytes);
            if (first_flight) builder.putSlice(&server_messages.change_cipher_spec_record);
            const sealed = try arm.send.?.seal(.handshake, flight, builder.bytes[builder.index..]);
            builder.index += sealed.len;
            arm.finishFlight();
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
    if (!self.resumed) {
        const chain = server_messages.certificateChain(
            flight[builder.index..],
            self.config.credentials.chain(),
        );
        builder.index += chain.len;
        arm.absorbMessage(chain);

        var content_buffer: [server_messages.certificate_verify_content_bytes_max]u8 = undefined;
        const to_sign = server_messages.certificateVerifyContent(.server, &arm.transcriptHash(), &content_buffer);
        var signature_buffer: [backend.signature_bytes_max]u8 = undefined;
        const signature = try self.config.credentials.signer.sign(to_sign, &signature_buffer);
        const verify_message = server_messages.certificateVerify(
            flight[builder.index..],
            @intFromEnum(self.config.credentials.signer.scheme),
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
    // the chain and the signature.
    assert(builder.index >= 40);
    if (!self.resumed) assert(builder.index >= 500);
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
    switch (self.state) {
        .awaiting_finished, .connected => {},
        else => return error.UnexpectedMessage,
    }
    assert(self.ladder != null);
    assert(wire_record.len > record.header_bytes);
    switch (self.ladder.?) {
        inline else => |*arm| {
            const opened = switch (self.state) {
                .awaiting_finished => try arm.recv.?.open(wire_record, out),
                .connected => try arm.session.?.recv.open(wire_record, out),
                else => unreachable, // The guard above admits only these two.
            };
            const plaintext = out[0..opened.plaintext_bytes];
            switch (opened.content_type) {
                .alert => return self.handlePlaintextAlert(plaintext),
                .handshake => return self.handleProtectedHandshake(arm, plaintext, out),
                .application_data => {
                    if (self.state != .connected) return error.UnexpectedMessage;
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
    if (self.state == .connected) {
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
    assert(self.state == .connected);
    assert(arm.session != null);
    const response = try arm.session.?.processKeyUpdate(message.body(), out);
    if (response) |sealed| return .{ .send = sealed };
    return .none;
}

/// §4.6.3, send side. `request_update` asks the peer to rotate too — the
/// lever for §5.5 sequence-budget hygiene.
pub fn sendKeyUpdate(self: *ServerHandshake, request_update: bool, out: []u8) Error![]const u8 {
    assert(self.state == .connected);
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
    assert(self.state == .connected);
    assert(bytes.len <= record.plaintext_bytes_max);
    errdefer self.state = .failed;
    switch (self.ladder.?) {
        inline else => |*arm| return arm.session.?.send.seal(.application_data, bytes, out),
    }
}

/// Seal a close_notify and mark the machine closed (or failed, if even
/// that cannot be sealed).
pub fn sendClose(self: *ServerHandshake, out: []u8) Error![]const u8 {
    assert(self.state == .connected);
    errdefer self.state = .failed;
    const bytes = alert.encode(.close_notify);
    switch (self.ladder.?) {
        inline else => |*arm| {
            const sealed = try arm.session.?.send.seal(.alert, &bytes, out);
            self.state = .closed;
            return sealed;
        },
    }
}

/// §4.6.1: derive the PSK a ticket nonce will stand for. Separate from
/// sending, because a stateless embedder needs the PSK *before* the
/// ticket that seals it exists — zoxy's `Tickets.seal` order.
pub fn resumptionPsk(
    self: *const ServerHandshake,
    ticket_nonce: []const u8,
    out: *[cipher_suite.hash_bytes_max]u8,
) []const u8 {
    assert(self.state == .connected);
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
    assert(self.state == .connected);
    assert(params.ticket.len >= 1);
    assert(params.ticket.len <= server_messages.ticket_bytes_max);
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

pub const Direction = session_keys.Direction;

/// The kTLS hand-over: one direction's application traffic key, IV, and
/// next sequence number, in kernel-ready terms (§4 of docs/DESIGN.md).
/// Reflects the current §4.6.3 generation — export after any KeyUpdate,
/// never before.
pub fn exportKeyMaterial(self: *const ServerHandshake, direction: Direction) ktls.KeyMaterial {
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
        fn startHandshakeKeys(self: *Self, shared: *const [32]u8, psk: ?[]const u8) protect.Error!void {
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
        /// application traffic keys (§7.1's derivation point).
        fn finishFlight(self: *Self) void {
            assert(self.schedule != null);
            assert(self.schedule.?.stage == .handshake);
            self.finished_hash = self.transcriptHash();
            self.schedule.?.advanceToMaster();
            self.client_application_traffic = self.schedule.?.deriveAt(.master, "c ap traffic", &self.finished_hash);
            self.server_application_traffic = self.schedule.?.deriveAt(.master, "s ap traffic", &self.finished_hash);
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
