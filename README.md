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

- `zig build test` — 40 tests across three oracle classes:
  - **RFC 8448 §3 replayed byte for byte** — the key ladder, every
    protected record opened, the server flight and ServerHello re-encoded
    to identical wire bytes.
  - **Interop with `std.crypto.tls.Client`** — an implementation sharing
    no code with zssl completes a full in-memory handshake against
    `ServerHandshake` (std's own X.509 and ECDSA verify our Certificate
    and CertificateVerify), exchanges data both ways, and takes a clean
    close_notify.
  - **State-machine scenarios** — fragmented ClientHello, coalesced
    flights, HelloRetryRequest with §4.4.1 transcript surgery, ALPN,
    kTLS key-export agreement, RFC 6979 signature determinism, and the
    failure paths (tampering, no common suite, ALPN mismatch, talking
    past the handshake) — plus AEAD differentials against `std.crypto`
    for all three suites.
- `zig build test -Doptimize=ReleaseSafe` — the same suite in the mode
  release builds ship (assertions stay on; libcrypto builds with
  `sanitize_c = .off` in every mode — zoxy's #283).
- `zig fmt --check src build.zig build.zig.zon` — format gate.

Test vectors are generated, not transcribed: `scripts/extract_rfc8448.py`
parses the RFC text into `src/rfc8448_vectors.zig`.

## Status

Slices 1 (foundations) and 2 (ServerHandshake) — see DESIGN.md §6 for
what each proved and the ladder ahead: resumption (3), kTLS switchover +
KeyUpdate + client handshake (4), BoGo and fuzzing (5).
