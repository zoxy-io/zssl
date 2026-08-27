# zssl

Sans-I/O TLS 1.3 protocol layer in Zig 0.16 over libcrypto primitives
(`zoxy-io/openssl`). Prototype engine for zoxy. Read before writing code:

- [docs/DESIGN.md](docs/DESIGN.md) — scope, the trust split, the slice
  ladder and what each slice's oracle proved. Bare § references point
  here or to RFC 8446 (context makes it obvious which).
- [docs/TIGER_STYLE.md](docs/TIGER_STYLE.md) — the enforced style
  contract, a verbatim copy of zoxy's; zoxy's copy is the source of
  truth when they drift.

## Gates — run before every commit

- `zig build test` — the full suite, three oracle classes (RFC 8448
  byte-exact replay, `std.crypto.tls.Client` interop, state-machine
  scenarios). Run it in **both** modes: plain and
  `-Doptimize=ReleaseSafe` — ReleaseSafe is what release builds ship,
  and assertions stay on there.
- `zig build interop` — the real-OpenSSL gate (spawns `openssl
  s_client`/`s_server` over loopback). Exits 2 as a readable SKIP when
  no TLS 1.3-capable `openssl` is on PATH; macOS's `/usr/bin/openssl` is
  LibreSSL and does not qualify, so Homebrew's `openssl@3` is what the
  probe finds first.
- `zig build bogo` — the adversarial gate: BoringSSL's BoGo runner, at
  the commit pinned in `bogo/run.zig`, against `bogo/shim.zig`. Exits 2
  as a readable SKIP with no Go toolchain (or no network on a cold run,
  which fetches the checkout into `zig-out/bogo/`). It fails on any
  case the runner ran and we did not satisfy, *and* on a passing count
  below the floor in `bogo/run.zig` — that floor is what stops a
  `config.json` suppression from being silent. See docs/BOGO.md.
- `zig fmt --check src interop bogo scripts build.zig build.zig.zon` —
  format gate.
- Run the `tiger-style-reviewer` agent on the working diff before
  committing a slice (same rule as zoxy). Point it at the
  security-critical paths of the diff by name; reachable assertions on
  attacker-controlled input are must-fix findings.

## Invariants (grep-checkable; a reviewer failure if broken)

- **Exactly one `@cImport`**, in `src/crypto/c.zig`; C symbols are
  called only from `src/crypto/backend_openssl.zig` and
  `src/crypto/mem_hooks.zig`. Everything above that boundary is Zig.
- **No allocators.** `std.mem.Allocator` appears nowhere; every buffer
  is caller-owned or a fixed array. libcrypto's internal allocations are
  the embedder's to redirect via `mem_hooks.install`.
- **No randomness.** zssl draws no entropy: client/server randoms and
  x25519 ephemerals arrive through `Config`. Seeded-simulation replay
  depends on this; do not add an RNG call.
- **Record caps are enforced at header parse** (`record.zig`), never
  compensated for downstream.

## Policies

- `src/rfc8448_vectors.zig` is **generated** by
  `scripts/extract_rfc8448.py` from the RFC text — regenerate, never
  hand-edit. Hand-copied hex is how vector tests rot.
- The `openssl` pin in build.zig.zon must move together with zoxy's:
  one libcrypto per binary (zrk/profile-harness link both trees).
- OpenSSL is the only backend, deliberately: `CRYPTO_set_mem_functions`
  is load-bearing for the zero-allocation budget and the BoringSSL
  family removed it. Do not add backends.
- Test fixtures in `src/testdata/` are throwaway self-signed material
  shared with zoxy's `src/tls/testdata/`; never real credentials.
- `bogo/config.json` is a **ledger**: every `DisabledTests` entry carries
  a one-line reason, and one that reads "OPEN GAP" points at a numbered
  finding in docs/BOGO.md. Never add an entry without a reason, and never
  lower `passing_floor` to make a run green.
- Workflow: one slice per commit, descriptive commit messages recording
  what the oracles proved. Push only when asked.
