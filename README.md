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

- `zig build test` — 22 tests: the RFC 8448 §3 handshake replayed byte
  for byte (key ladder, every protected record opened, the server flight
  re-sealed to identical wire bytes), an AEAD differential against
  `std.crypto` for all three suites, x25519 agreement, ClientHello
  parsing with truncation at every prefix, and the kTLS payload layouts.
- `zig build test -Doptimize=ReleaseSafe` — the same suite in the mode
  release builds ship (assertions stay on; libcrypto builds with
  `sanitize_c = .off` in every mode — zoxy's #283).
- `zig fmt --check src build.zig build.zig.zon` — format gate.

Test vectors are generated, not transcribed: `scripts/extract_rfc8448.py`
parses the RFC text into `src/rfc8448_vectors.zig`.

## Status

Slice 1 (foundations) — see DESIGN.md §6 for the ladder to a working
ServerHandshake, resumption, and the kTLS switchover.
