# zssl

A sans-I/O TLS 1.3 protocol layer in Zig 0.16 over libcrypto primitives
(`zoxy-io/openssl`, the pin zoxy links). Prototype for zoxy's TLS
engine, with kTLS key export as a design input and TIGER_STYLE from the
first line.

Read before writing code:

- [docs/DESIGN.md](docs/DESIGN.md) — scope, the trust split, the slice
  ladder and what each slice's oracle proved, and the testing stance.
- [docs/TIGER_STYLE.md](docs/TIGER_STYLE.md) — the enforced style
  contract, a verbatim copy of zoxy's.
- [docs/BOGO.md](docs/BOGO.md) — the one gate still outstanding, and why
  it is staged rather than half-built. Everything below tests what zssl
  *accepts*; BoGo is what tests the refusals.

## Gates

- `zig build test` — 62 tests across four oracle classes:
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
  - **Fuzz targets** — nine of them, over every parser (record header,
    alert, ClientHello, PEM, the handshake assembler, the record
    buffer) and both state machines, asserting that arbitrary peer
    bytes yield a value or an error and never a panic. `zig build test`
    runs each once over its corpus; the coverage-guided `--fuzz` search
    is blocked on a 0.16.0 toolchain bug (see DESIGN.md §6).
- `zig build interop` — the real-OpenSSL gate, over loopback sockets:
  `openssl s_client` against our `ServerHandshake`, with openssl's own
  X.509 verifying our certificate, and our `ClientHandshake` against
  `openssl s_server -rev`, opening the reversed echo openssl sealed
  back. Exits 2 with a readable SKIP when no TLS 1.3-capable `openssl`
  is on PATH, rather than failing.
- `zig build test -Doptimize=ReleaseSafe` — the same suite in the mode
  release builds ship (assertions stay on; libcrypto builds with
  `sanitize_c = .off` in every mode — zoxy's #283).
- `zig fmt --check src interop build.zig build.zig.zon` — format gate.

Test vectors are generated, not transcribed: `scripts/extract_rfc8448.py`
parses the RFC text into `src/rfc8448_vectors.zig`.
