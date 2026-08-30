# zssl

Sans-I/O TLS 1.3 protocol layer in Zig 0.16 over libcrypto primitives
(`zoxy-io/openssl`). Prototype engine for zoxy. Read before writing code:

- [docs/DESIGN.md](docs/DESIGN.md) — §1 is what is built, not built,
  and never; §2–§5 are the decisions everything follows from; §6 is
  what proved it. Bare § references point here or to RFC 8446 (context
  makes it obvious which).
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
- `zig build tlsfuzzer` — the second adversarial gate: tlsfuzzer's
  scripts against `tlsfuzzer/server.zig`, at the commit pinned in
  `tlsfuzzer/run.zig`. Exits 2 as a readable SKIP with no python3 (or no
  network on a cold run). Fails on any script it ran and did not satisfy,
  and on a passing count below the floor. See docs/TLSFUZZER.md.
- `zig build tlsanvil` — the third adversarial gate: TLS-Anvil's
  RFC-derived corpus against the same `tlsfuzzer/server.zig` harness, at
  the image digest pinned in `tlsanvil/run.zig`. Exits 2 as a readable
  SKIP with no reachable Docker daemon. Fails on any test it ran and did
  not satisfy, on a passing count below the floor, and — distinctly, and
  before the counts — when the harness died mid-run, because a corpus
  that ran against a corpse reports a low number that looks exactly like
  a corpus that refused us. See docs/TLSANVIL.md.
- `zig fmt --check src interop bench bogo fuzz tlsanvil tlsfuzzer
  scripts build.zig build.zig.zon` — format gate. `fuzz/` is in the list
  even though its one file is vendored from the compiler: it is
  zig-fmt-clean upstream, so keeping it under the gate costs nothing and
  a re-sync that is not costs a one-line `zig fmt`.
- Run the `tiger-style-reviewer` agent on the working diff before
  committing a slice (same rule as zoxy). Its definition lives in
  `.claude/agents/tiger-style-reviewer.md`; zoxy's copy remains the
  source of truth for TIGER_STYLE itself, and this one adds zssl's
  invariants. Point it at the security-critical paths of the diff by
  name; reachable assertions on attacker-controlled input are must-fix
  findings.

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
- **No clock reads.** Time arrives through `Config.now_ms` the same way
  entropy does — supplied per connection, never measured. Seeded replay
  depends on this exactly as it depends on the rule above:
  `grep -rnE '\.now\(|clock_gettime|milliTimestamp|nanoTimestamp' src/`
  must stay empty. In Zig 0.16 a clock is `Io.Clock.Timestamp.now(io,
  …)`, so `.now(` is the pattern that matters and the `std.time.*`
  spellings are there for a future that brings them back. Unit constants
  (`std.time.ns_per_ms`) are arithmetic, not a clock.
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
- `tlsanvil/tests.json` is the third ledger, and keys on `<class>.<method>`
  rather than on TLS-Anvil's own test ids. Those ids are **not stable**:
  the same corpus produced different ids for the same failures across two
  runs of a changed tree, so a ledger keyed on them would silently stop
  matching. Class and method are Java identifiers and do not move.
  Separately, 321 of the 437 tests disable *themselves* against a
  TLS 1.3-only server, so that count comes from the tool and is not ours
  to maintain.
- `bogo/config.json` is a **ledger**: every `DisabledTests` entry carries
  a one-line reason. Most are by-design exclusions — a version we do not
  speak, a feature DESIGN.md §1 puts out of scope — and those are plain
  prose. An entry that cites a numbered finding in docs/BOGO.md opens
  with a marker saying which kind of thing it is:

  - **OPEN GAP** — a defect we intend to fix.
  - **SCOPE** — the case needs a capability we have decided not to
    carry, so it is waiting on that decision rather than on a fix.
  - **KEEP** — we refuse the input exactly as BoGo wants and differ only
    in which alert we send, having argued ours is the better answer.
  - **Not a defect** — the case encodes the runner's own policy rather
    than a requirement.

  Only the first is a gap, so `grep 'OPEN GAP'` is the count of what is
  actually open. Keep it that way: a case that turns out to be a scope
  decision or a divergence gets re-marked rather than left overstating
  itself. Never add an entry without a reason, and never lower
  `passing_floor` to make a run green.
- The coverage badge is served from this repository, not a third party:
  the `coverage` job writes `coverage.json` to an orphan `badges` branch
  and shields.io reads it through its endpoint API, so the only
  credential involved is the `GITHUB_TOKEN` the job already has. Note
  that this only renders while the repository is public — a private repo
  needs `raw.githubusercontent.com` auth, and the badge would have to go
  static like the BoGo pair.
- `tlsfuzzer/scripts.json` is the same kind of ledger as
  `bogo/config.json`, with one difference that matters: 18 of its entries
  say "not yet triaged", and the gate counts and prints them. That number
  should go *down*. Never add a new untriaged entry when the cause is
  known, and never let the count grow to make a pin bump green. Triage a
  script against **both** leaves the gate serves (ECDSA and RSA) before
  recording a reason: a dozen scripts advertise RSA-PSS alone, and over
  the wrong leaf they fail their own `sanity` conversation.
- The BoGo and tlsfuzzer badges in README.md are static and carry the same numbers
  as `passing_floor` and the decline count. They move in the same commit
  the floor does; a badge that disagrees with the gate is worse than no
  badge. They are a pair on purpose — the passing figure alone reads as
  a coverage claim it cannot support.
- Workflow: one slice per commit, descriptive commit messages recording
  what the oracles proved. Push only when asked.
