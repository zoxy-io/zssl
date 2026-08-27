# zssl

A sans-I/O TLS 1.3 protocol layer in Zig 0.16 over libcrypto primitives
(`zoxy-io/openssl`, the pin zoxy links). Prototype for zoxy's TLS
engine, with kTLS key export as a design input and TIGER_STYLE from the
first line.

Read before writing code:

- [docs/DESIGN.md](docs/DESIGN.md) — scope, the trust split, the slice
  plan, and the testing stance.
- [docs/TIGER_STYLE.md](docs/TIGER_STYLE.md) — the enforced style
  contract, a verbatim copy of zoxy's.

## Gates

- `zig build test` — 52 tests across three oracle classes:
  - **RFC 8448 replayed byte for byte** — §3's key ladder, every
    protected record opened, the server flight and ServerHello re-encoded
    to identical wire bytes; §4's binder chain, truncated-transcript
    arithmetic, PSK ServerHello, and PSK-mixed ladder.
  - **Interop with `std.crypto.tls.Client`** — an implementation sharing
    no code with zssl completes a full in-memory handshake against
    `ServerHandshake` (std's own X.509 and ECDSA verify our Certificate
    and CertificateVerify), exchanges data both ways, and takes a clean
    close_notify.
  - **State-machine scenarios** — fragmented ClientHello, coalesced
    flights, HelloRetryRequest with §4.4.1 transcript surgery, ALPN,
    kTLS key-export agreement, RFC 6979 signature determinism,
    resumption end-to-end (tickets issued after client Finished, PSK
    session up with no certificate, client-side PSK derivation agreeing
    with the server's), the production `ClientHandshake` against the
    production server (leaf verification, ticket capture, resumption,
    §4.6.3 KeyUpdate both ways with kTLS exports agreeing at every
    generation, structural HelloRetryRequest refusal), and the failure
    paths (tampering, corrupted binders, unknown tickets, no common
    suite, ALPN mismatch, talking past the handshake) — plus AEAD
    differentials against `std.crypto` for all three suites.
- `zig build test -Doptimize=ReleaseSafe` — the same suite in the mode
  release builds ship (assertions stay on; libcrypto builds with
  `sanitize_c = .off` in every mode — zoxy's #283).
- `zig fmt --check src build.zig build.zig.zon` — format gate.

Test vectors are generated, not transcribed: `scripts/extract_rfc8448.py`
parses the RFC text into `src/rfc8448_vectors.zig`.

## Status

Slices 1 (foundations), 2 (ServerHandshake), 3 (resumption), and 4
(KeyUpdate, the kTLS switchover contract, ClientHandshake) — see
DESIGN.md §6 for what each proved. Remaining: the BoGo/fuzz assurance
ladder (5).
