//! The client-side TLS 1.3 handshake (RFC 8446 §4), sans-I/O — the
//! origination half, for speaking to upstreams. Same contract as
//! `ServerHandshake`: whole wire records in, events out, no randomness of
//! its own (client random and the x25519 ephemeral arrive via `Config`).
//!
//! Two deliberate shapes:
//!
//! - **HelloRetryRequest is refused, structurally.** This client holds
//!   keys for exactly one group (x25519) and always offers its share, so
//!   an HRR is either illegal (demanding what was already offered —
//!   §4.1.4 forbids a retry that changes nothing) or unsatisfiable
//!   (demanding a group we cannot compute). Both are
//!   `error.HandshakeFailure`, not a retry.
//! - **Certificate policy is an explicit seam.** `.ecdsa_leaf_signature`
//!   proves the peer holds the key its leaf names, via `std.crypto`'s
//!   ECDSA over the leaf's own SPKI; chain building and RFC 9525 name
//!   matching are the embedder's, deferred with reasons in DESIGN.md §1.
//!   `.insecure_no_verification` is for pinned-transport tests and says
//!   so in its name.

const std = @import("std");
const assert = std.debug.assert;

const alert = @import("alert.zig");
const backend = @import("crypto/backend_openssl.zig");
const cipher_suite = @import("cipher_suite.zig");
const client_hello = @import("client_hello.zig");
const client_messages = @import("client_messages.zig");
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
ccs_seen: u8,
hello_storage: [client_messages.hello_bytes_max]u8,
hello_bytes: u16,
/// Whether this session came up on our offered PSK.
resumed: bool,
/// True once the leaf's CertificateVerify checked out under the policy.
certificate_verified: bool,
/// True once the server confirmed our ALPN protocol in
/// EncryptedExtensions; the embedder decides whether absence is fatal.
alpn_confirmed: bool,
/// The leaf's SEC1 public key, captured for CertificateVerify.
leaf_public_key: [leaf_public_key_bytes_max]u8,
leaf_public_key_bytes: u8,

const ClientHandshake = @This();

/// An uncompressed P-384 SEC1 point is the largest key we accept.
const leaf_public_key_bytes_max: u8 = 97;

pub const State = enum(u8) {
    idle,
    awaiting_server_hello,
    awaiting_flight,
    connected,
    closed,
    failed,
};

pub const CertificatePolicy = enum {
    /// Verify CertificateVerify against the leaf's own public key. Chain
    /// and name validation remain the embedder's (DESIGN.md §1).
    ecdsa_leaf_signature,
    /// No certificate checks at all. For tests and pinned transports.
    insecure_no_verification,
};

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
    /// Compatibility session id to send and expect echoed (§4.1.3);
    /// embedder-random, may be empty.
    session_id: []const u8 = &.{},
    server_name: ?[]const u8 = null,
    alpn: ?[]const u8 = null,
    certificate_policy: CertificatePolicy,
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

pub const Event = union(enum) {
    none,
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
    handshake.Assembler.Error || alert.ParseError || wire.Error || error{
    UnexpectedMessage,
    /// The ServerHello broke a rule: bad echo, unknown suite, missing or
    /// wrong supported_versions, a PSK we never offered.
    BadServerHello,
    /// HelloRetryRequest — see the file comment for why this is final.
    HandshakeFailure,
    /// The certificate could not be read or its key is outside policy.
    BadCertificate,
    /// CertificateVerify did not verify against the leaf.
    BadSignature,
    /// The server's Finished MAC did not verify.
    DecryptError,
    /// The server selected an ALPN protocol we did not offer (RFC 7301).
    BadAlpn,
    PeerAlert,
};

pub const out_bytes_min: u32 = record.wire_record_bytes_max;

pub fn init(config: *const Config) ClientHandshake {
    assert(config.session_id.len <= 32);
    assert(config.reassembly.len >= 8192);
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
        .ccs_seen = 0,
        .hello_storage = undefined,
        .hello_bytes = 0,
        .resumed = false,
        .certificate_verified = false,
        .alpn_confirmed = false,
        .leaf_public_key = undefined,
        .leaf_public_key_bytes = 0,
    };
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
        .x25519_public = &x25519_public,
        .server_name = self.config.server_name,
        .alpn = self.config.alpn,
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
pub fn handleRecord(self: *ClientHandshake, wire_record: []const u8, out: []u8) Error!Event {
    assert(out.len >= out_bytes_min);
    assert(self.state != .failed);
    assert(self.state != .idle);
    errdefer self.state = .failed;
    const header = try record.parseHeader(wire_record[0..record.header_bytes]);
    if (wire_record.len != @as(usize, record.header_bytes) + header.length) {
        return error.UnexpectedMessage;
    }
    switch (header.content_type) {
        .change_cipher_spec => {
            if (self.ccs_seen == ccs_seen_max) return error.UnexpectedMessage;
            self.ccs_seen += 1;
            return .none;
        },
        .alert => return self.handleAlertPayload(wire_record[record.header_bytes..]),
        .handshake => {
            if (self.state != .awaiting_server_hello) return error.UnexpectedMessage;
            try self.assembler.push(wire_record[record.header_bytes..]);
            const message = (try self.assembler.next()) orelse return .none;
            if (message.messageType() != .server_hello) return error.UnexpectedMessage;
            if (!self.assembler.empty()) return error.UnexpectedMessage;
            return self.handleServerHello(message.bytes);
        },
        .application_data => return self.handleProtectedRecord(wire_record, out),
    }
}

fn handleAlertPayload(self: *ClientHandshake, payload: []const u8) Error!Event {
    assert(self.state != .failed);
    assert(payload.len >= 1);
    const parsed = try alert.parse(payload);
    if (parsed.isCloseNotify()) {
        self.state = .closed;
        return .closed;
    }
    return error.PeerAlert;
}

fn handleServerHello(self: *ClientHandshake, message: []const u8) Error!Event {
    assert(self.state == .awaiting_server_hello);
    assert(self.ladder == null);
    var body = wire.Cursor.init(message[handshake.header_bytes..]);
    if (try body.takeU16() != 0x0303) return error.BadServerHello;
    const random = try body.takeSlice(32);
    if (std.mem.eql(u8, random, &server_messages.hello_retry_magic)) {
        // See the file comment: a single-group client has no second offer.
        return error.HandshakeFailure;
    }
    const echo = try body.takeSlice(try body.takeByte());
    if (!std.mem.eql(u8, echo, self.config.session_id)) return error.BadServerHello;
    const suite = CipherSuite.fromWire(try body.takeU16()) orelse return error.BadServerHello;
    if (try body.takeByte() != 0) return error.BadServerHello;
    const extensions = try self.readServerHelloExtensions(&body);
    // §4.2.1: no supported_versions selecting 1.3 means a 1.2 server —
    // and this library has nothing to say to one.
    if (!extensions.tls13_selected) return error.BadServerHello;
    const server_share = extensions.server_share orelse return error.BadServerHello;
    if (self.resumed) {
        // §4.2.11: the selected PSK's hash and the suite's must agree.
        if (self.config.resume_session.?.psk_bytes != suite.hashBytes()) return error.BadServerHello;
    }

    var shared: [32]u8 = undefined;
    try backend.x25519Shared(&self.config.x25519_private, &server_share, &shared);
    defer std.crypto.secureZero(u8, &shared);
    self.ladder = Ladder.initFor(suite);
    switch (self.ladder.?) {
        inline else => |*arm| {
            arm.transcript.update(self.hello_storage[0..self.hello_bytes]);
            arm.transcript.update(message);
            const psk: ?[]const u8 = if (self.resumed)
                self.config.resume_session.?.psk[0..self.config.resume_session.?.psk_bytes]
            else
                null;
            try arm.startHandshakeKeys(&shared, psk);
        },
    }
    self.state = .awaiting_flight;
    return .none;
}

const ServerHelloExtensions = struct {
    server_share: ?[32]u8,
    tls13_selected: bool,
};

fn readServerHelloExtensions(self: *ClientHandshake, body: *wire.Cursor) Error!ServerHelloExtensions {
    const extensions_bytes = try body.takeU16();
    if (extensions_bytes != body.remaining()) return error.BadServerHello;
    var result: ServerHelloExtensions = .{ .server_share = null, .tls13_selected = false };
    var extensions_seen: u8 = 0;
    while (body.remaining() > 0) : (extensions_seen += 1) {
        if (extensions_seen == 8) return error.BadServerHello;
        assert(extensions_seen < 8);
        const extension_type = try body.takeU16();
        const data = try body.takeSlice(try body.takeU16());
        switch (extension_type) {
            51 => {
                var share = wire.Cursor.init(data);
                if (try share.takeU16() != client_hello.group_x25519) return error.BadServerHello;
                if (try share.takeU16() != 32) return error.BadServerHello;
                result.server_share = (try share.takeSlice(32))[0..32].*;
                if (share.remaining() != 0) return error.BadServerHello;
            },
            43 => {
                var version = wire.Cursor.init(data);
                if (try version.takeU16() != 0x0304) return error.BadServerHello;
                if (version.remaining() != 0) return error.BadServerHello;
                result.tls13_selected = true;
            },
            41 => {
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

fn handleProtectedRecord(self: *ClientHandshake, wire_record: []const u8, out: []u8) Error!Event {
    switch (self.state) {
        .awaiting_flight, .connected => {},
        else => return error.UnexpectedMessage,
    }
    assert(self.ladder != null);
    switch (self.ladder.?) {
        inline else => |*arm| {
            const opened = switch (self.state) {
                .awaiting_flight => try arm.recv.?.open(wire_record, out),
                .connected => try arm.session.?.recv.open(wire_record, out),
                else => unreachable,
            };
            const plaintext = out[0..opened.plaintext_bytes];
            switch (opened.content_type) {
                .alert => return self.handleAlertPayload(plaintext),
                .handshake => {
                    try self.assembler.push(plaintext);
                    if (self.state == .connected) return self.handlePostHandshake(arm, out);
                    return self.drainFlight(arm, out);
                },
                .application_data => {
                    if (self.state != .connected) return error.UnexpectedMessage;
                    return .{ .application_data = plaintext };
                },
                .change_cipher_spec => return error.UnexpectedMessage,
            }
        },
    }
}

fn drainFlight(self: *ClientHandshake, arm: anytype, out: []u8) Error!Event {
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
                if (self.leaf_public_key_bytes != 0) return error.UnexpectedMessage;
                try self.captureLeaf(message.body());
                arm.transcript.update(message.bytes);
            },
            .certificate_verify => {
                if (self.resumed) return error.UnexpectedMessage;
                // §4.4.3 signs what §4.4.2 presented, so the order is
                // fixed: no leaf captured yet means the peer inverted the
                // flight, which is a protocol error and not our panic.
                if (self.leaf_public_key_bytes == 0) return error.UnexpectedMessage;
                try self.verifyCertificate(arm, message);
                arm.transcript.update(message.bytes);
            },
            .finished => return self.completeHandshake(arm, message, out),
            else => return error.UnexpectedMessage,
        }
    }
    return .none;
}

/// RFC 7301 §3.2: the server may select only something we offered.
fn checkEncryptedExtensions(self: *ClientHandshake, body: []const u8) Error!void {
    var cursor = wire.Cursor.init(body);
    const extensions_bytes = try cursor.takeU16();
    if (extensions_bytes != cursor.remaining()) return error.UnexpectedMessage;
    var extensions_seen: u8 = 0;
    while (cursor.remaining() > 0) : (extensions_seen += 1) {
        if (extensions_seen == 8) return error.UnexpectedMessage;
        assert(extensions_seen < 8);
        const extension_type = try cursor.takeU16();
        const data = try cursor.takeSlice(try cursor.takeU16());
        if (extension_type == 16) {
            const ours = self.config.alpn orelse return error.BadAlpn;
            var list = wire.Cursor.init(data);
            const list_bytes = try list.takeU16();
            if (list_bytes != list.remaining()) return error.BadAlpn;
            const name = try list.takeSlice(try list.takeByte());
            if (!std.mem.eql(u8, name, ours)) return error.BadAlpn;
            if (list.remaining() != 0) return error.BadAlpn;
            self.alpn_confirmed = true;
        }
    }
}

/// Pull the leaf's SEC1 public key out of the Certificate message. Under
/// `.insecure_no_verification` the message is only length-checked.
fn captureLeaf(self: *ClientHandshake, body: []const u8) Error!void {
    assert(self.leaf_public_key_bytes == 0);
    var cursor = wire.Cursor.init(body);
    if (try cursor.takeByte() != 0) return error.BadCertificate;
    _ = try cursor.takeU24();
    const leaf_bytes = try cursor.takeU24();
    if (leaf_bytes == 0) return error.BadCertificate;
    const leaf_der = try cursor.takeSlice(leaf_bytes);
    if (self.config.certificate_policy == .insecure_no_verification) return;
    const certificate: std.crypto.Certificate = .{ .buffer = leaf_der, .index = 0 };
    const parsed = certificate.parse() catch return error.BadCertificate;
    switch (parsed.pub_key_algo) {
        .X9_62_id_ecPublicKey => |curve| switch (curve) {
            .X9_62_prime256v1, .secp384r1 => {},
            else => return error.BadCertificate,
        },
        else => return error.BadCertificate,
    }
    const public_key = parsed.pubKey();
    if (public_key.len > leaf_public_key_bytes_max) return error.BadCertificate;
    if (public_key.len < 65) return error.BadCertificate; // Uncompressed P-256 floor.
    @memcpy(self.leaf_public_key[0..public_key.len], public_key);
    self.leaf_public_key_bytes = @intCast(public_key.len);
}

/// §4.4.3, taken against the *presented* leaf: possession, not identity.
fn verifyCertificate(self: *ClientHandshake, arm: anytype, message: handshake.Message) Error!void {
    if (self.config.certificate_policy == .insecure_no_verification) return;
    assert(self.leaf_public_key_bytes >= 65);
    var body = wire.Cursor.init(message.body());
    const scheme = try body.takeU16();
    const signature = try body.takeSlice(try body.takeU16());
    if (body.remaining() != 0) return error.BadSignature;
    var content_buffer: [server_messages.certificate_verify_content_bytes_max]u8 = undefined;
    const content = server_messages.certificateVerifyContent(.server, &arm.transcriptHash(), &content_buffer);
    const public_key = self.leaf_public_key[0..self.leaf_public_key_bytes];
    switch (scheme) {
        0x0403 => try verifyEcdsa(std.crypto.sign.ecdsa.EcdsaP256Sha256, public_key, content, signature),
        0x0503 => try verifyEcdsa(std.crypto.sign.ecdsa.EcdsaP384Sha384, public_key, content, signature),
        else => return error.BadSignature,
    }
    self.certificate_verified = true;
}

fn verifyEcdsa(comptime Ecdsa: type, public_key: []const u8, content: []const u8, signature_der: []const u8) Error!void {
    assert(content.len >= 98); // 64 spaces, the context string, a hash.
    assert(signature_der.len >= 8);
    const key = Ecdsa.PublicKey.fromSec1(public_key) catch return error.BadCertificate;
    const signature = Ecdsa.Signature.fromDer(signature_der) catch return error.BadSignature;
    signature.verify(content, key) catch return error.BadSignature;
}

fn completeHandshake(self: *ClientHandshake, arm: anytype, message: handshake.Message, out: []u8) Error!Event {
    assert(self.state == .awaiting_flight);
    if (!self.resumed) {
        // Policy says who may skip the certificate leg: only a session a
        // PSK already authenticates.
        if (self.config.certificate_policy == .ecdsa_leaf_signature) {
            if (!self.certificate_verified) return error.BadCertificate;
        }
    }
    if (!self.assembler.empty()) return error.UnexpectedMessage;
    const flight = try arm.finishHandshake(message, self.config.send_change_cipher_spec, out);
    self.state = .connected;
    // The invariant this function exists to enforce, stated where a
    // reader can check it: nothing reaches `connected` unauthenticated.
    assert(self.resumed or self.certificate_verified or
        self.config.certificate_policy == .insecure_no_verification);
    assert(flight.len >= record.header_bytes);
    return .{ .connected = flight };
}

fn handlePostHandshake(self: *ClientHandshake, arm: anytype, out: []u8) Error!Event {
    assert(self.state == .connected);
    const message = (try self.assembler.next()) orelse return .none;
    if (!self.assembler.empty()) return error.UnexpectedMessage;
    switch (message.messageType() orelse return error.UnexpectedMessage) {
        .new_session_ticket => return .{ .ticket = try parseTicket(message.body()) },
        .key_update => {
            const response = try arm.session.?.processKeyUpdate(message.body(), out);
            if (response) |sealed| return .{ .send = sealed };
            return .none;
        },
        else => return error.UnexpectedMessage,
    }
}

fn parseTicket(body: []const u8) Error!Ticket {
    var cursor = wire.Cursor.init(body);
    var ticket: Ticket = undefined;
    ticket.lifetime_s = try cursor.takeU32();
    ticket.age_add = try cursor.takeU32();
    const nonce_bytes = try cursor.takeByte();
    if (nonce_bytes == 0) return error.UnexpectedMessage;
    ticket.nonce = try cursor.takeSlice(nonce_bytes);
    const ticket_bytes = try cursor.takeU16();
    if (ticket_bytes == 0) return error.UnexpectedMessage;
    ticket.ticket = try cursor.takeSlice(ticket_bytes);
    const extensions_bytes = try cursor.takeU16();
    _ = try cursor.takeSlice(extensions_bytes);
    if (cursor.remaining() != 0) return error.UnexpectedMessage;
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
    assert(self.state == .connected);
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
    assert(self.state == .connected);
    assert(bytes.len <= record.plaintext_bytes_max);
    errdefer self.state = .failed;
    switch (self.ladder.?) {
        inline else => |*arm| return arm.session.?.send.seal(.application_data, bytes, out),
    }
}

pub fn sendClose(self: *ClientHandshake, out: []u8) Error![]const u8 {
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

pub fn sendKeyUpdate(self: *ClientHandshake, request_update: bool, out: []u8) Error![]const u8 {
    assert(self.state == .connected);
    assert(out.len >= record.header_bytes + handshake.header_bytes + 1 + 256);
    errdefer self.state = .failed;
    switch (self.ladder.?) {
        inline else => |*arm| return arm.session.?.initiateKeyUpdate(request_update, out),
    }
}

pub const Direction = session_keys.Direction;

/// The kTLS hand-over, current as of the latest §4.6.3 generation.
pub fn exportKeyMaterial(self: *const ClientHandshake, direction: Direction) ktls.KeyMaterial {
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

        fn transcriptHash(self: *const Self) [hash_bytes]u8 {
            return self.transcript.currentHash();
        }

        fn startHandshakeKeys(self: *Self, shared: *const [32]u8, psk: ?[]const u8) protect.Error!void {
            assert(self.schedule == null);
            assert(self.recv == null);
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
