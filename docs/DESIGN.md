# zssl design

A sans-I/O TLS 1.3 protocol layer in Zig over libcrypto primitives.
Written to replace the audited `zoxy-io/ztls` fork as zoxy's TLS engine,
on zoxy's terms from the first line: TIGER_STYLE throughout, kTLS as a
design input rather than a bolt-on, and a scope cut to what a terminating
proxy needs instead of what a general TLS library carries.

## §1 Scope

**In**, eventually (slice numbers in §6):

- TLS 1.3 only (RFC 8446). No 1.2, no downgrade dance beyond reading the
  compatibility fields 1.3 froze.
- Server-side handshake first; a client handshake exists for tests and,
  later, for upstream origination.
- The three RFC 8446 suites. ECDSA P-256/P-384 signing only — RSA is
  excluded by the embedder's policy (a ~1–2 ms RSA sign is the number
  that once justified a worker pool; ECDSA's ~100–400 µs is why there
  isn't one).
- x25519 key exchange; PSK resumption with server-side NewSessionTicket
  issuance; ALPN and SNI reads.
- kTLS key export (§4).

**Out, permanently** (a caller that needs these wants a different
library): TLS 1.2, renegotiation, compression, RSA key exchange, DSA,
SSLv3-era anything, post-handshake client auth.

**Out, deliberately deferred**: 0-RTT (a replay-analysis decision, not a
protocol convenience), X.509 chain *validation* (becomes load-bearing
only when the embedder originates TLS to upstreams; RFC 9525 binds then,
not before).

## §2 The trust split

The protocol state machine — where TLS CVEs live — is Zig in this tree.
Constant-time primitives — AEAD, X25519, ECDSA — are libcrypto's, the
most-watched assembly on earth. HKDF, HMAC, and the transcript hash are
pure Zig over `std.crypto`: hashing public-length data is not where the
sharp edges are, and this is the same line ztls drew and zoxy audited.

**One backend, on purpose.** OpenSSL is the only libcrypto family member
with `CRYPTO_set_mem_functions`, and that hook is what makes a
zero-allocation budget over a C library a checkable property instead of
a hope (`src/crypto/mem_hooks.zig`). BoringSSL and AWS-LC removed the
API, so a backend for them could never satisfy §3 — carrying their
bindings anyway is how ztls spent ~660 lines saying "unsupported". The
pin is `zoxy-io/openssl` 3.5.7 (LTS to 2030), the same commit zoxy
links, because the embedder's binary must contain exactly one libcrypto.

The C surface is two files: `src/crypto/c.zig` (the single `@cImport`)
and `src/crypto/backend_openssl.zig` (every call site). Nothing behind
the boundary parses attacker bytes; callers hand in framed slices with
asserted lengths.

## §3 Memory

Zero allocation, full stop — not "after startup", because zssl has no
startup: every buffer is caller-owned and every struct is fixed-size.
The embedder owns startup, installs the `mem_hooks` triple before first
libcrypto use, and sizes the fixed heap that libcrypto's own internals
(EVP contexts, PKEY objects) land in. zoxy's measured budget is ~4.9 KiB
of libcrypto heap per session engine plus a 2 MiB base; zssl's job is to
keep the per-record path free of *any* allocation: AEAD contexts are
created once per traffic key (`AeadKey.init`) and reused per record; the
X25519 `EVP_PKEY` objects live only inside one handshake's key
agreement.

## §4 kTLS is a design input

The reason this library exists rather than a fifth fork commit. Once the
handshake completes, the record layer should be able to move into the
kernel (`setsockopt(SOL_TLS)`), leaving userspace record protection as
the fallback path rather than the only path.

That requires exactly one thing of the library's shape: traffic keys,
static IVs, and sequence numbers must be *first-class, exportable state*
— never hidden inside an opaque session. `src/ktls.zig` defines the
kernel UAPI payloads and packs them from `KeyMaterial`; `Protector`
(`src/protect.zig`) carries `static_iv` and `sequence` as plain fields
so the hand-over is a read, not an excavation. The fiddly parts are
staged, not ignored: session tickets go out *before* the switchover, and
KeyUpdate/post-handshake messages arrive via CMSG once the kernel owns
the stream (slice 4).

## §5 Records

Framing caps are enforced at header parse (`record.parseHeader`), per
content type: §5.1's 2^14 for plaintext records, §5.2's 2^14+256 for
protected ones, §5.4's 2^14+1 for the decrypted inner plaintext. A
record the spec forbids never reaches a buffer. This is a direct lesson
from the ztls defect queue, where the record layer admitted oversized
plaintext and the embedder compensated above the API.

`Protector` is one direction under one traffic key: AEAD contexts,
static IV, sequence. The §5.5 sequence bound (2^24 records, the
AES-GCM-conservative figure applied to every suite) is an error, not a
wrap. zssl never writes padding; it strips peers' padding per §5.4.

## §6 Slices

1. **Foundations** — done: record framing + protection, HKDF/key
   schedule, transcript, ClientHello parse, AEAD/X25519 backend,
   mem-hooks seam, kTLS payloads. Oracle: RFC 8448 §3 byte-for-byte.
2. **ServerHandshake** — done: the state machine (ClientHello through
   client Finished), negotiation, ECDSA CertificateVerify via libcrypto
   with the opt-in RFC 6979 deterministic-nonce mode, ALPN,
   HelloRetryRequest with §4.4.1 transcript surgery,
   fragmented-ClientHello reassembly, compatibility-CCS tolerance
   (bounded), and kTLS key export at `connected`. Oracles: the traced
   ServerHello byte-exact against RFC 8448; a full in-memory handshake
   against **`std.crypto.tls.Client`** — no shared code, std's own X.509
   and ECDSA judging our Certificate/CertificateVerify — plus the
   in-tree test client covering fragmentation, HRR, and every failure
   path. Known-refused, on purpose: KeyUpdate and post-handshake
   messages error loudly (`KeyUpdateUnsupported`) until slice 4.
3. **Resumption** — done: `psk_lookup` is the embedder seam (opaque
   identity in, PSK out; ticket sealing, lifetime, and age policy stay
   the embedder's), binder verification aborts on a recognized identity
   with a bad binder (a replayed identity is refused, never downgraded),
   an unknown identity falls back to a full handshake, and the resumed
   flight drops Certificate/CertificateVerify. `resumptionPsk` derives
   before `sendNewSessionTicket` seals — the stateless-server ordering —
   and issuance happens strictly after `connected`, i.e. after the
   client's Finished (the delayed-ACK lesson). Oracles: RFC 8448 §4's
   binder chain, truncation arithmetic, PSK ServerHello, and PSK-mixed
   ladder, all byte-exact; end-to-end ticket → resumed session with the
   client deriving every PSK from its own resumption_master. Deliberate
   scope cuts: PSK offers on a retry ClientHello are ignored (the §4.4.1
   surgery binder stays out until BoGo can pressure it), and psk_ke
   without (EC)DHE is never accepted.
4. **KeyUpdate, the kTLS switchover contract, and the client handshake**
   — done. §4.6.3 lives once, in `session_keys.zig`, shared by both
   machines: rotation resets the sequence space, a rotation ceiling turns
   a request loop into an error, and `exportKeyMaterial` reflects the
   current generation — the switchover contract is *tickets first, then
   export both directions after any KeyUpdate, then stop feeding the
   machine*. `ClientHandshake` is the origination half: SNI, ALPN with
   RFC 7301 selection checks, the certificate-policy seam
   (`.ecdsa_leaf_signature` proves key possession via std.crypto against
   the presented leaf; chain/name stay deferred per §1), ticket capture
   through the event surface, resumption, and a *structural* refusal of
   HelloRetryRequest — a single-group client has no second offer to
   make, so both HRR shapes (illegal repeat, unsatisfiable demand) abort.
   Oracle: both production machines end to end — handshake, resume,
   KeyUpdate both directions with kTLS exports agreeing across machines
   at every generation.
5. **The assurance ladder**: BoGo shim, parser fuzz targets (record
   header, ClientHello, extensions), differential against ztls, interop
   against openssl s_client and s_server.

## §7 Testing stance

Slice 1 already carries the three kinds of test every later slice must:
RFC 8448 replay (agreement with an implementation sharing no code),
differential against `std.crypto` AEAD (a second no-shared-code oracle,
covering inputs the trace doesn't), and negative-space tests (tampered
tags, skewed sequences, truncation at every prefix, forbidden grammar).
The RFC vectors are *generated* from the RFC text by
`scripts/extract_rfc8448.py` — hand-copied hex is how vector tests rot.
