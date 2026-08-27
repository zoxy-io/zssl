# BoGo — staged, not yet wired

BoGo is BoringSSL's adversarial TLS test runner: a Go program that plays
a deliberately hostile peer and drives an implementation through some
thousands of cases, most of which are things a correct stack must
*refuse*. It is the single highest-value item left on zssl's assurance
ladder, and it is deliberately **not** claimed as done — a half-wired
BoGo that runs forty cases and reports green is worse than none, because
it reads like coverage.

## What it needs

BoGo talks to a **shim**: a binary it spawns per test case, which takes
the case's flags on argv, speaks TLS over an inherited socket, and exits
zero on success. The work is:

1. `bogo/shim.zig` — a `ClientHandshake`/`ServerHandshake` driver over a
   socket handed in on fd 3 (or `-port`), implementing the flag subset
   below.
2. A pinned BoringSSL checkout for `ssl/test/runner`, run as
   `go test -run TestRunnerZssl -shim-path ...`.
3. `config.json` — the expected-failure list. Every entry needs a reason
   in one line; an unexplained suppression is how a runner rots.

## The flags a first cut must honour

`-server`, `-port`, `-shim-id`, `-key-file`, `-cert-file`,
`-max-version`/`-min-version` (we answer only 0x0304 and must decline
the rest), `-expect-version`, `-curves`, `-cipher`,
`-resume-count`/`-on-resume-*` (slice 3's ticket path),
`-expect-session-miss`, `-shim-writes-first`, `-expect-alert`.

## Why the suppression list will be long at first, and legitimately so

zssl is 1.3-only by design (DESIGN.md §1), so the entire TLS 1.0–1.2
corpus is out of scope rather than failing — those cases must be
declined by version negotiation, and BoGo has flags that assert exactly
that. Other known-absent surfaces, each already a written decision:
client certificates, 0-RTT/early data, DTLS, renegotiation, RSA,
Ed25519, compressed certificates, and PSK offered on a retry
ClientHello. Each becomes a `config.json` entry citing the design
section, not a silent skip.

## Order of work

BoGo before the ztls differential. A differential against ztls proves
we agree with one other implementation that shares our *assumptions*;
BoGo proves we refuse what the protocol says to refuse, which is the
question a proxy's TLS terminator actually gets asked by the internet.
The ztls differential belongs with zoxy's engine swap anyway — that is
where the two run side by side and disagreement is diagnosable against
a live proxy.

## What exists today instead

The interop gate (`zig build interop`) runs both directions against the
real `openssl` binary — genuine libssl, no shared code, real sockets —
and the unit suite carries an in-process `std.crypto.tls.Client` leg.
Neither is adversarial. That is the gap BoGo closes, and until it is
wired this file is the honest statement of where the ladder stops.
