//! zssl — a sans-I/O TLS 1.3 protocol layer over libcrypto primitives.
//!
//! The protocol layer is Zig — records, the key schedule, both handshake
//! state machines, resumption, KeyUpdate; libcrypto supplies only the
//! constant-time primitives. Nothing here allocates, and nothing here
//! draws randomness: buffers and entropy arrive from the embedder.
//!
//! `ServerHandshake` and `ClientHandshake` are the entry points, and
//! README.md shows what driving them looks like. Scope and design live
//! in docs/DESIGN.md; the style contract is docs/TIGER_STYLE.md
//! (zoxy's, adopted verbatim).

pub const ClientHandshake = @import("ClientHandshake.zig");
pub const Credentials = @import("Credentials.zig");
pub const ServerHandshake = @import("ServerHandshake.zig");
pub const alert = @import("alert.zig");
pub const cipher_suite = @import("cipher_suite.zig");
pub const client_hello = @import("client_hello.zig");
pub const client_messages = @import("client_messages.zig");
pub const handshake = @import("handshake.zig");
pub const hkdf = @import("hkdf.zig");
pub const key_schedule = @import("key_schedule.zig");
pub const ktls = @import("ktls.zig");
pub const mem_hooks = @import("crypto/mem_hooks.zig");
pub const pem = @import("pem.zig");
pub const protect = @import("protect.zig");
pub const record = @import("record.zig");
pub const record_buffer = @import("record_buffer.zig");
pub const server_messages = @import("server_messages.zig");
pub const session_keys = @import("session_keys.zig");
pub const transcript = @import("transcript.zig");
pub const wire = @import("wire.zig");

/// The libcrypto boundary, exported for embedders that need the raw
/// primitives (zoxy's spike tests do); everything above it is pure Zig.
pub const backend = @import("crypto/backend_openssl.zig");

test {
    @import("std").testing.refAllDecls(@This());
    _ = @import("rfc8448_test.zig");
    _ = @import("handshake_test.zig");
    _ = @import("std_interop_test.zig");
    _ = @import("resumption_test.zig");
    _ = @import("client_server_test.zig");
    _ = @import("fuzz_test.zig");
    _ = @import("readme_test.zig");
}
