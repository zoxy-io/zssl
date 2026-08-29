# bench — zssl against rustls

Not a gate. Nothing here asserts, nothing here fails a build, and no
number below is a threshold. It exists to answer one question with
measurements instead of intuition: where is zssl slow, and is it slow
because of the protocol layer this tree writes or because of what sits
under it.

The short answer is that the protocol layer is not the problem. zssl's
own code is *faster* than rustls's on both sides of a handshake and by a
wide margin on bulk data. Every microsecond of the handshake gap is in
the primitives.

The harness has found two things and both have been fixed. It opened at
a 3.9× full-handshake gap; it now reads 1.38×, and resumption 1.13×,
with `handshake_full` down from 495 µs to 175 µs. Neither fix touched
the protocol layer:

| | `handshake_full` | vs rustls |
|---|---|---|
| as measured | 495.14 µs | 3.90× slower |
| ECDSA verification through libcrypto | 208.38 µs | 1.64× slower |
| one key-exchange multiplication instead of two | **175.26 µs** | **1.38× slower** |

Both predictions were made from the primitive rows before the code was
touched — 207 µs and ~35 µs saved — and both landed within 2%. The
before-and-after is kept below because the point of this directory is
the method, and a report that only shows the answer does not let anyone
check the method that found it.

```
./bench/run.sh
```

Builds both harnesses, pins them to one core, writes
`bench/results/{zssl,rustls}.jsonl` (git-ignored — the table below is the
record meant to last), and prints the comparison.
`BENCH_CORE=5 ./bench/run.sh` picks a different core.

## What is measured

Four classes, with the same scenario names on both sides:

- **`handshake_full`, `handshake_resume`** — a client and a server driven
  to `connected` in one process. Full handshake over an ECDSA P-256 leaf;
  resumption over a ticket the previous session issued.
- **`phase_*`** — the same handshake with the clock read between each of
  the four flights, so a gap can be located rather than just noted.
- **`transfer_*`** — one 16 KiB record sealed by one peer and opened by
  the other, through each library's public API.
- **primitives** — the AEAD, the signature and the key exchange
  underneath all of the above, so the protocol cost can be separated from
  the crypto cost by subtraction.

## The comparison is meant to be fair, and here is where it had to work at it

- **No I/O anywhere.** Both harnesses run both peers in one process and
  move bytes through a buffer. zssl is sans-I/O by design; rustls's
  `write_tls`/`read_tls` pair is the same shape, and it is the shape
  rustls's own test suite uses.
- **The same certificate.** Both load `src/testdata/cert.pem` — one
  self-signed P-256 leaf — from the tree rather than from a copy.
- **The same verification policy.** zssl's `.leaf_signature` checks
  CertificateVerify against the leaf's public key and leaves chain
  building and name matching to the embedder (DESIGN.md §1). rustls is
  given a custom `ServerCertVerifier` that does exactly that and no more.
  Handing rustls its real webpki verifier would have compared a handshake
  that builds a chain against one that does not.
- **The same negotiated parameters.** rustls's provider is narrowed to
  one cipher suite and to X25519, because zssl's client offers one key
  share and its server has a fixed preference order. TLS 1.3 only on both
  sides. ALPN `http/1.1` and SNI on both sides.
- **The same release settings.** The Rust half is `--release` with LTO
  and one codegen unit. The Zig half pins `ReleaseFast` for the harness
  *and* rebuilds zssl and libcrypto at `ReleaseFast` underneath it — a
  module's optimize mode is its own in Zig, so a fast harness importing
  the default-Debug library would have reported a number about a binary
  nobody ships. `cargo --release` has no such trap, which is why the
  correction lives in `build.zig`.
- **The same statistics.** Fifteen rounds, a warmup of a quarter round,
  best and median reported. The tables quote the best round, because this
  is a laptop and the median carries thermal history the best round does
  not. Median and best agree to under 1% on every line, which is the only
  reason quoting the best is defensible.

Two differences could not be equalised, and both are noted where they
matter: rustls's ECDSA signer draws a random nonce, so zssl's signer is
configured for random nonces too rather than RFC 6979; and zssl draws no
entropy at all for randoms or ephemerals (DESIGN.md's no-randomness
rule), which saves it a CSPRNG call per handshake that rustls pays.

`transfer_aes256` and `transfer_chacha20` are the one place the names had
to be bent. zssl's handshake always lands on AES-128-GCM — the client's
offer list and the server's preference order are both fixed in the
library — so the other two suites are unreachable through a connected
pair. What is measured for those two is `protect.Protector` directly, one
seal and one open, against rustls's full connection path. That comparison
is only honest because zssl's `transfer_aes128` and `record_aes128` agree
to within 0.1%: the state machine over the record layer is free, so
nothing is being quietly dropped from zssl's side of the row.

## Results

Intel Core Ultra 7 258V (4 P-cores at 4.8 GHz, 4 LP E-cores at 3.7 GHz),
Linux 6.18, `intel_pstate` with turbo enabled and
`energy_performance_preference=performance`. Pinned to core 2, a P-core.
zssl at `8e90551` plus this branch's two moves, over
`zoxy-io/openssl` 3.5.7; rustls 0.23.43 over
aws-lc-rs 1.18.0; Zig 0.16.0, rustc 1.97.1. Best of fifteen rounds.

```
Handshake
  handshake_full               175.26 us       127.28 us     1.38x slower
  handshake_resume             107.22 us        95.22 us     1.13x slower

Handshake, by flight
  phase_client_hello            18.21 us        15.33 us     1.19x slower
  phase_server_flight           68.09 us        47.86 us     1.42x slower
  phase_client_finish           85.02 us        61.76 us     1.38x slower
  phase_server_finish            2.96 us         1.93 us     1.53x slower

Bulk data (16 KiB record, sealed and opened)
  transfer_aes128     3.43 us  4.78 GB/s   4.39 us  3.73 GB/s  1.28x faster
  transfer_aes256     3.99 us  4.10 GB/s   4.95 us  3.31 GB/s  1.24x faster
  transfer_chacha20  10.56 us  1.55 GB/s  10.73 us  1.53 GB/s  1.02x faster

Primitives
  aead_seal_aes128     1.62 us 10.11 GB/s  1.68 us  9.77 GB/s  1.03x faster
  aead_seal_aes256     1.88 us  8.70 GB/s  1.95 us  8.42 GB/s  1.03x faster
  aead_seal_chacha20   5.07 us  3.23 GB/s  4.94 us  3.32 GB/s  1.03x slower
  aead_key_init                 747.8 ns         71.4 ns    10.47x slower
  ecdsa_p256_sign                16.49 us        14.74 us     1.12x slower
  ecdsa_p256_verify              44.59 us        34.63 us     1.29x slower
  x25519_keygen_agree            44.31 us        23.16 us     1.91x slower
  x25519_public                  17.88 us              —
  x25519_shared                  25.93 us              —
  x25519_shared_rederive         43.51 us              —
  p256_verify_stdcrypto         333.82 us              —
```

Two rows measure code no path reaches any more, and both are kept
deliberately. `p256_verify_stdcrypto` is what the `verifyEcdsa` move
rests on; `x25519_shared_rederive` is what the `KeyShare` bundle rests
on. The day someone proposes undoing either is the day they should have
to re-run the row that argued for it.

### The two moves, before and after

Nothing else changed between these columns — same harness, same machine,
same rustls build:

| | as measured | after `verifyEcdsa` | after `KeyShare` |
|---|---|---|---|
| `handshake_full` | 495.14 µs | 208.38 µs | **175.26 µs** |
| `handshake_resume` | 141.29 µs | 140.97 µs | **107.22 µs** |
| `phase_server_flight` | 86.63 µs | 84.51 µs | **68.09 µs** |
| `phase_client_finish` | 386.01 µs | 101.34 µs | **85.02 µs** |
| ratio against rustls | 3.90× | 1.64× | **1.38×** |

Each column is its own run, so the last one carries this page's rustls
figures and the first two do not; run-to-run spread on this machine is
about 1.5%, which is smaller than every difference the table is about.

Predicted 206.7 µs and then a further ~35 µs; measured 208.38 and 35.58.
The arithmetic in the section below held twice to under 2%, which is the
reason to trust the rest of it. All six gates pass unchanged across both
moves, BoGo at the same 311 with no case flipping in either direction.

The second move is the one visible in `handshake_resume`: a resumed
handshake does no signing and no verification, so the first move could
not touch it and the second took a third off it.

## What the numbers say

**The protocol layer is the fast part.** Subtracting the primitives each
phase calls from the phase itself leaves the library's own work:

| | zssl | rustls |
|---|---|---|
| crypto in a full handshake | 148.7 µs | 95.7 µs |
| everything else | **26.6 µs** | **31.6 µs** |
| crypto's share | 85% | 75% |

zssl's state machine, parsing, key schedule and transcript hashing cost
about 27 µs per handshake against rustls's 32 — and zssl's figure is the
more pessimistic of the two, because it also carries the `EVP_PKEY`
import `ecFromPublic` does per verification, which the standalone
`ecdsa_p256_verify` row does not pay. The same ordering holds on the
resumed path — 20 µs against 49 — and on bulk data, where zssl's record
layer adds 6% over the raw AEAD and rustls's connection path adds 31%,
which is what the extra buffer copies between `writer()`, `sendable_tls`,
`write_tls`, `read_tls` and `reader()` cost. Nothing in this tree needs
to get faster for zssl to win those rows; it already does.

**The remaining 48 µs gap is almost all one thing, and it is no longer
ours.** It decomposes to within about 11%, the residue being the four
clock reads the phase split adds:

1. **X25519 — 41 µs, 86% of what is left.** zssl does four scalar
   multiplications per handshake (each peer builds a share and agrees
   against the other's) for 88 µs; rustls does the same four for 46 µs.
   What is left is OpenSSL being about twice aws-lc-rs's cost per
   multiplication — partly because OpenSSL routes the fixed-base one
   through the C `ge_scalarmult_base` while only the variable-base one
   reaches `x25519-x86_64.s`, partly EVP object construction around each
   call. Neither is something this tree can act on without either
   reaching for OpenSSL's internal `ossl_x25519` (an `ossl_`-prefixed
   symbol, not public API, and a pin bump away from renaming) or adding
   the second backend DESIGN.md §2 rules out. **This row is done.**

   What *was* ours is now fixed, and the `x25519_shared_rederive` row is
   what it cost. `EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, …)`
   reaches `ossl_ecx_key_fromdata` → `ossl_ecx_public_from_private`
   (`crypto/ec/ecx_backend.c:99`, and a callgrind trace confirms it), so
   constructing a private-key object from a scalar alone **eagerly
   derives the public key**. An agreement handed only a scalar therefore
   paid for a fixed-base multiplication it discarded: 43.51 µs against
   the 25.93 µs the same agreement costs when the public half comes with
   it. The server paid it twice over — once inside the agreement, once
   again in a separate `keySharePublic` for the share on the wire.
   `backend.KeyShare` now bundles the two halves so `init` multiplies
   once and `agree` is handed the answer.

2. **ECDSA verification — 10 µs.** 44.59 µs against aws-lc-rs's 34.63.
   Both are assembly (`ecp_nistz256` against aws-lc's own); a 28%
   difference between two hand-written P-256 implementations is not
   something this tree can act on.

3. **`aead_key_init` — 5.4 µs.** 747.8 ns against 71.4 ns, and a
   handshake stands up eight traffic keys across both peers. Small, and
   listed only so it is not mistaken for the cause: an early guess that
   OpenSSL 3's implicit provider fetch in `EVP_EncryptInit_ex` was driving
   the handshake gap is what this row was added to test, and it refuted it.

4. **ECDSA signing — 1.8 µs.** libcrypto's `ecp_nistz256` and aws-lc-rs
   are within 12% of each other. Nothing to do here.

The call that used to head this list — `ClientHandshake.verifyEcdsa` on
`std.crypto`, at 298 µs of the original 368 µs gap — is gone. What it cost to remove
is that a peer's public key and signature now cross into C. They are
bounded before they get there (`captureLeaf` caps the key and
floors it at 65 bytes; the signature is a §4.4.3-framed slice) and the
point is validated at import by `ecFromPublic` rather than trusted, which
is the same treatment a KeyShareEntry already gets. `verifyRsaPss` has
not moved: nobody has measured it, and moving it on the strength of the
ECDSA number would be guessing.

The three AEADs are a wash — libcrypto and aws-lc-rs are within 3% on all
of AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305 — which is worth
recording because it means the bulk-data rows are measuring the two
*libraries*, not the two crypto backends.

## Caveats

- A laptop is not a benchmarking machine, whatever its governor says. The
  runs are pinned to one core and best-of-fifteen, and the two harnesses
  are interleaved on the same core in the same script, so the *ratios* are
  sound. The absolute microsecond figures are not portable to a server.
- The governor is `powersave`, and that is *not* the throttle the name
  suggests: under `intel_pstate` it is the default dynamic governor and it
  scales to full turbo under load — `performance` is the only alternative
  the driver offers, and it merely pins the P-state rather than raising
  the ceiling. With `energy_performance_preference=performance` and turbo
  enabled, the ceiling here is already the hardware's. What the runs do
  guard against is the other thing this CPU has: core heterogeneity.
- Wall-clock, not instruction counts. rustls's own `ci-bench` prefers
  callgrind for exactly this reason; callgrind could not be used here
  because valgrind 3.27 cannot decode the GFNI instructions LLVM emits
  for this CPU when compiling the vendored OpenSSL C.
- One handshake shape: TLS 1.3, P-256 leaf, X25519, no client auth, no
  HelloRetryRequest, no chain to build. Every one of those is a
  deliberate narrowing to the case both libraries can be made to run
  identically, and every one of them is a case a real deployment also
  meets.
- rustls numbers are for 0.23.43 over aws-lc-rs 1.18.0, pinned in
  `bench/rustls-bench/Cargo.lock`. A version bump invalidates the table
  above and not the harness.

## Layout

| | |
|---|---|
| `zssl_bench.zig` | the Zig harness; `zig build bench` runs it |
| `rustls-bench/` | the Rust harness, a normal cargo crate |
| `cargo.sh` | cargo from nixpkgs, plus the cmake `aws-lc-sys` wants |
| `run.sh` | builds both, pins both, prints the table |
| `compare.py` | pairs the two JSON-lines files |
| `results/` | the last run's output; generated, and git-ignored |

`ZSSL_BENCH_ONLY=handshake_full,x25519_shared` runs a subset of the Zig
harness and `ZSSL_BENCH_SCALE=100` divides the iteration counts, which is
what makes it usable under a profiler.

devenv.nix deliberately carries no Rust toolchain: nothing zssl ships
needs one, and none of the six gates in CLAUDE.md would be improved by
1.1 GiB in every developer's shell. `cargo.sh` fetches its own.
