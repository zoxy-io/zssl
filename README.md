# zssl

[![ci](https://github.com/zoxy-io/zssl/actions/workflows/ci.yml/badge.svg)](https://github.com/zoxy-io/zssl/actions/workflows/ci.yml)
[![coverage](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fzoxy-io%2Fzssl%2Fbadges%2Fcoverage.json)](https://github.com/zoxy-io/zssl/actions/workflows/ci.yml)

A sans-I/O TLS 1.3 library in Zig, over libcrypto primitives.

zssl implements the protocol — records, the key schedule, both handshake
state machines, resumption, KeyUpdate — in auditable Zig, and calls
libcrypto only for the constant-time primitives (AEAD, X25519, ECDSA and
RSA-PSS signing); checking a *peer's* signature is `std.crypto`'s. It owns no
sockets, no threads, and no memory: you feed it whole TLS records and
transmit whatever it hands back.

```zig
switch (try server.handleRecord(wire_record, &out)) {
    .send => |bytes| try socket.writeAll(bytes),
    .application_data => |plaintext| try onRequest(plaintext),
    .connected, .closed, .none => {},
}
```

That shape is the whole interface, and it is what makes zssl usable from
an `io_uring` event loop, a thread-per-connection server, or a
deterministic simulator with a virtual clock — none of which it needs to
know about.

**Status: prototype.** It is exercised hard (see [Testing](#testing)),
interoperates with OpenSSL and `std.crypto.tls` in both directions, and
both halves run under BoringSSL's adversarial BoGo runner, which has
found real defects — a remote panic on a garbage certificate among them —
and leaves nine findings still on the ledger, all recorded in
[docs/BOGO.md](docs/BOGO.md). The server half also runs under tlsfuzzer,
which has found three ([docs/TLSFUZZER.md](docs/TLSFUZZER.md)). It has had
no external audit. Don't put it in front of anything you care about yet.

## Why

Most TLS libraries hand you a socket-shaped object and own the loop. If
you are writing a proxy, that costs you the two things you needed most:

- **Nothing is hidden from the event loop.** No callbacks into a library
  that might block, no internal buffering you cannot size.
- **kTLS is a first-class hand-off, not a fight.** Traffic keys, IVs and
  record sequence numbers are exportable state
  (`exportKeyMaterial`), so moving the record layer into the kernel is a
  read rather than an excavation.

Two properties fall out of the design and are enforced by the tests:

- **Zero allocation.** Not "after startup" — at all. Every buffer is
  caller-owned or a fixed array. `std.mem.Allocator` appears nowhere in
  the library.
- **Zero randomness.** zssl never calls an RNG. Handshake randoms and
  ephemeral keys arrive through `Config`, which is what lets a seeded
  simulation replay a session byte for byte.

## Install

```sh
zig fetch --save git+https://github.com/zoxy-io/zssl
```

```zig
const zssl_dependency = b.dependency("zssl", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("zssl", zssl_dependency.module("zssl"));
```

libcrypto is built from source by Zig for your target — nothing is
resolved from the host — so cross-compilation works out of the box.

## Usage

### Terminating TLS

Load credentials once; everything after is per-connection.

```zig
const zssl = @import("zssl");

var chain_storage: [zssl.Credentials.chain_bytes_max]u8 = undefined;
var credentials = try zssl.Credentials.load(cert_pem, key_pem, &chain_storage, false);
defer credentials.deinit();
```

Each connection gets a handshake, two caller-owned buffers, and 64 bytes
of entropy you supply:

```zig
var reassembly: [16 * 1024]u8 = undefined;
var flight: [zssl.Credentials.chain_bytes_max + 1024]u8 = undefined;

var entropy: [80]u8 = undefined;
io.random(&entropy); // your `std.Io` — zssl never calls an RNG itself

var server = zssl.ServerHandshake.init(&.{
    .credentials = &credentials,
    .server_random = entropy[0..32].*,
    // 48 bytes: enough scalar for the largest group zssl offers.
    .key_share_private = entropy[32..80].*,
    .alpn = "http/1.1",
    .reassembly = &reassembly,
    .flight = &flight,
});
defer server.deinit();
```

Then drive it with whole records. `zssl.record_buffer.RecordBuffer` turns
a byte stream into those, policing the RFC 8446 §5 length caps as bytes
arrive:

```zig
var out: [zssl.ServerHandshake.out_bytes_min]u8 = undefined;

while (try records.next()) |wire_record| {
    switch (try server.handleRecord(wire_record, &out)) {
        // Handshake bytes to put on the wire.
        .send => |bytes| try socket.writeAll(bytes),
        // The session is up; app data may now flow both ways.
        .connected => {},
        // Decrypted application bytes, valid until the next call.
        .application_data => |plaintext| try onRequest(plaintext),
        // The peer sent close_notify.
        .closed => break,
        // A record that advanced nothing — a fragment, or a CCS.
        .none => {},
    }
}

const reply = try server.sendApplicationData("HTTP/1.1 200 OK\r\n\r\n", &out);
try socket.writeAll(reply);
```

On any error the machine is `failed` and must not be fed again — close
the connection. That is the whole contract.

### Originating TLS

The client half has the same shape; `start` produces the ClientHello, and
the `connected` event carries the flight to send:

```zig
var reassembly: [16 * 1024]u8 = undefined;
var client = zssl.ClientHandshake.init(&.{
    .client_random = entropy[0..32].*,
    .x25519_private = entropy[32..64].*,
    .server_name = "origin.internal",
    .alpn_protocols = &.{ "h2", "http/1.1" },
    .certificate_policy = .leaf_signature,
    .chain_verifier = .{ .context = &trust, .verify = &yourChainCheck },
    .reassembly = &reassembly,
});
defer client.deinit();

try socket.writeAll(client.start(&out));

while (try records.next()) |wire_record| {
    switch (try client.handleRecord(wire_record, &out)) {
        .send, .connected => |bytes| try socket.writeAll(bytes),
        .application_data => |plaintext| try onResponse(plaintext),
        .ticket => |ticket| try store(ticket),
        .closed => break,
        .none => {},
    }
}
```

`alpn_protocols` is offered in preference order; `client.alpnSelected()`
reports what the server took, or null if it took nothing — an answer
rather than an error, because a server that ignores an `h2` offer is
something a client should report, not die on.

Certificate handling is split in two, on purpose.

**Possession** is zssl's: `.leaf_signature` verifies the server's
CertificateVerify against the key its leaf presents — ECDSA P-256/P-384
or RSA-PSS, since an originating client does not choose what its
upstreams present. `.insecure_no_verification` skips it entirely and
says so in its name.

**Identity** is yours: `chain_verifier` is shown the peer's chain, leaf
first, while the bytes are still live, and returning false aborts the
handshake before the leaf's signature is even checked. **Chain building
and RFC 9525 name matching are yours to do**, deliberately, because a
proxy's trust decisions belong to the proxy — `std.crypto.Certificate`
has the pieces. Configure no verifier and zssl proves possession alone,
which authenticates the key and says nothing about who holds it.

### Resumption and kTLS

After `connected`, a server can issue tickets and either side can rotate
keys or hand the connection to the kernel:

```zig
// Derive the PSK first, seal your own ticket around it, then send.
var psk_buffer: [zssl.cipher_suite.hash_bytes_max]u8 = undefined;
const psk = server.resumptionPsk(&nonce, &psk_buffer);
const sealed = try server.sendNewSessionTicket(&.{
    .lifetime_s = 3600,
    .age_add = age_add,
    .ticket_nonce = &nonce,
    .ticket = your_sealed_ticket,
}, &out);

// RFC 8446 §4.6.3 rekey, and the kTLS hand-off.
const update = try server.sendKeyUpdate(true, &out);
const keys = server.exportKeyMaterial(.transmit);
```

Ticket sealing, lifetime and age policy stay with you: zssl takes an
opaque identity through `Config.psk_lookup` and answers with the PSK,
then verifies the binder itself. A recognised identity with a bad binder
aborts the handshake rather than falling back — a replayed ticket is
refused, not downgraded.

## Scope

**In:** TLS 1.3 (RFC 8446), the three standard cipher suites, key
exchange over x25519, secp256r1 and secp384r1 (server side; the client
offers x25519 alone), ECDSA P-256/P-384 and RSA-PSS signing and
verification, SNI, ALPN,
HelloRetryRequest (the server issues it; the client refuses it
structurally, holding keys for one group), PSK resumption with
server-side tickets, KeyUpdate, and kTLS key export.

ECDSA is still the key to *deploy* — an RSA sign is a millisecond where
ECDSA is a few hundred microseconds, and that gap is why zssl needs no
worker pool. RSA is supported because a library should be able to
present a key its embedder already owns, not because it is the one to
choose. RSA keys are bounded at 2048..4096 bits and refused at load
outside it.

**Out, permanently:** TLS 1.2 and earlier, renegotiation, compression,
RSA and DSA *key exchange*, rsa_pkcs1_* signatures (§4.4.3 forbids them
in CertificateVerify). A caller that needs these wants a different
library.

**Out, for now:** 0-RTT (a replay-analysis decision, not a convenience),
X.509 chain validation (the embedder's, through `chain_verifier`),
client certificates, and QUIC.

Everything above is argued in [docs/DESIGN.md](docs/DESIGN.md) §1.

## Testing

`zig build test` runs the unit suite; `zig build interop` runs the
real-OpenSSL gate; `zig build bogo` and `zig build tlsfuzzer` run the two
adversarial ones. Six kinds of evidence, in rough order of how much they
are worth:

| Oracle | Status | Details |
| --- | --- | --- |
| **BoGo** | [![bogo passing](https://img.shields.io/badge/bogo-261%20passing-brightgreen)](docs/BOGO.md)<br>[![bogo declined](https://img.shields.io/badge/bogo-6918%20declined-lightgrey)](docs/BOGO.md#the-three-numbers) | [docs/BOGO.md](docs/BOGO.md) — BoringSSL's hostile-peer runner, pinned; checks *which* alert we send, not just that we refuse. |
| **tlsfuzzer** | [![tlsfuzzer](https://img.shields.io/badge/tlsfuzzer-15%2F57%20scripts-yellow)](docs/TLSFUZZER.md) | [docs/TLSFUZZER.md](docs/TLSFUZZER.md) — Python over tlslite-ng driving our *server*; 1261 conversations, two leaves. |
| **RFC 8448 replay** | — | [`src/rfc8448_test.zig`](src/rfc8448_test.zig) — key schedule, binders and records reproduce the RFC's traced bytes exactly. |
| **OpenSSL interop** | — | [`interop/main.zig`](interop/main.zig) — three legs against a real `openssl`, on an ECDSA leaf and an RSA-2048 one. |
| **`std.crypto.tls`** | — | [`src/std_interop_test.zig`](src/std_interop_test.zig) — a second implementation handshakes both directions and exchanges data. |
| **Fuzzing** | — | [`src/fuzz_test.zig`](src/fuzz_test.zig) — nine targets: arbitrary peer bytes yield a value or an error, never a panic. |

Plus directed tests for the things that only break under adversity —
fragmented ClientHellos, tampered Finished messages, corrupted binders,
inverted flights, sequence exhaustion.

The gaps, stated plainly. Both adversarial gates decline far more than
they run, and both say so in their own badge rather than behind it: BoGo
never ran 6918 of its cases, and tlsfuzzer runs 15 scripts of 57. BoGo's
two badges are a pair on purpose — "261 passing" alone reads as a
coverage claim that 6918 declined cases cannot support.

Of what they did run, nine findings still sit on BoGo's ledger and 18
tlsfuzzer scripts are not yet triaged into a scope decision or a defect.
Every one is named, with a reason, in the two documents above, and a
floor on each passing count is what stops a suppression from being
quiet.

## Development

```sh
zig build test                          # the suite
zig build test -Doptimize=ReleaseSafe   # the mode releases ship
zig build interop                       # against a real openssl binary
zig build bogo                          # against BoringSSL's BoGo runner
zig build tlsfuzzer                     # against tlsfuzzer's scripts
zig build tlsfuzzer-server -- --port 4433   # that server alone, to hand-drive
zig build coverage                      # line coverage, needs kcov (Linux)
zig fmt --check src interop bogo tlsfuzzer scripts build.zig build.zig.zon
```

RFC 8448 vectors are generated, never transcribed:
`scripts/extract_rfc8448.py` parses the RFC text into
`src/rfc8448_vectors.zig`. Regenerate rather than hand-editing.

[docs/TIGER_STYLE.md](docs/TIGER_STYLE.md) is the style contract the tree
is held to.

## License

zssl is [MIT](LICENSE) © 2026 Vsevolod Strukchinsky.

Two things travel with it under other terms:

- **OpenSSL** (Apache-2.0) is compiled into any binary that links zssl,
  so that binary has to carry Apache-2.0's notice and attribution. This
  is an obligation on whoever ships the binary, not on zssl's source.
- **`src/rfc8448_vectors.zig`** is generated from the text of RFC 8448,
  which is IETF Trust material. The generator is in `scripts/`, so the
  provenance of every byte is reproducible rather than asserted.
