# bench — zssl against rustls

Not a gate. Nothing here asserts, nothing here fails a build, and no
number below is a threshold. It exists to answer one question with
measurements instead of intuition: where is zssl slow, and is it slow
because of the protocol layer this tree writes or because of what sits
under it.

The short answer is that the protocol layer is not the problem. zssl's
own code is *faster* than rustls's on both sides of a handshake and by a
wide margin on bulk data. Every microsecond of the 3.9× full-handshake
gap is in the primitives, and 81% of it is one call.

Two things came out of it that are worth acting on, both in the
primitives and neither in the state machine. They are numbered in the
analysis below and are not fixed here: this commit is the measurement.

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
zssl at `8e90551` over `zoxy-io/openssl` 3.5.7; rustls 0.23.43 over
aws-lc-rs 1.18.0; Zig 0.16.0, rustc 1.97.1. Best of fifteen rounds.

```
Handshake
  handshake_full               495.14 us       126.92 us     3.90x slower
  handshake_resume             141.29 us        94.74 us     1.49x slower

Handshake, by flight
  phase_client_hello            18.39 us        15.26 us     1.20x slower
  phase_server_flight           86.63 us        47.71 us     1.82x slower
  phase_client_finish          386.01 us        61.46 us     6.28x slower
  phase_server_finish            2.99 us         1.98 us     1.51x slower

Bulk data (16 KiB record, sealed and opened)
  transfer_aes128     3.43 us  4.77 GB/s   4.37 us  3.75 GB/s  1.27x faster
  transfer_aes256     3.97 us  4.12 GB/s   4.93 us  3.32 GB/s  1.24x faster
  transfer_chacha20  10.47 us  1.57 GB/s  10.71 us  1.53 GB/s  1.02x faster

Primitives
  aead_seal_aes128     1.62 us 10.13 GB/s  1.67 us  9.81 GB/s  1.03x faster
  aead_seal_aes256     1.88 us  8.71 GB/s  1.94 us  8.43 GB/s  1.03x faster
  aead_seal_chacha20   5.05 us  3.25 GB/s  4.93 us  3.32 GB/s  1.02x slower
  aead_key_init                 733.6 ns         69.3 ns    10.58x slower
  ecdsa_p256_sign                16.49 us        14.72 us     1.12x slower
  ecdsa_p256_verify              44.25 us        34.48 us     1.28x slower
  x25519_keygen_agree            61.06 us        23.01 us     2.65x slower
  x25519_public                  17.75 us              -
  x25519_shared                  43.23 us              -
  p256_verify_stdcrypto         332.68 us              -
```

`p256_verify_stdcrypto` and the `x25519_public`/`x25519_shared` split are
diagnostic rows with no rustls counterpart: they exist to attribute the
handshake gap, and the analysis below is what they are for.

## What the numbers say

**The protocol layer is the fast part.** Subtracting the primitives each
phase calls from the phase itself leaves the library's own work:

| | zssl | rustls |
|---|---|---|
| crypto in a full handshake | 471.1 µs | 95.2 µs |
| everything else | **24.0 µs** | **31.7 µs** |
| crypto's share | 95% | 75% |

zssl's state machine, parsing, key schedule and transcript hashing cost
about 24 µs per handshake against rustls's 32. The same ordering holds
on the resumed path — 19 µs against 49 — and on bulk data, where zssl's record
layer adds 6% over the raw AEAD and rustls's connection path adds 31%,
which is what the extra buffer copies between `writer()`, `sendable_tls`,
`write_tls`, `read_tls` and `reader()` cost. Nothing in this tree needs
to get faster for zssl to win those rows; it already does.

**The 368 µs handshake gap is four things, and one of them is 81% of it.**

1. **`p256_verify_stdcrypto` — 298 µs.** `ClientHandshake.verifyEcdsa`
   runs on `std.crypto.sign.ecdsa.EcdsaP256Sha256`, not on libcrypto. That
   is deliberate — DESIGN.md §2 puts constant-time primitives behind the C
   boundary but exempts *verification*, on the argument that a
   public-length message is not where the timing argument bites, and
   `verifyRsaPss` says so in as many words. The argument is sound. What
   was never priced is that Zig's P-256 verifier costs **332.68 µs**
   against libcrypto's own **44.25 µs** — 7.5× — and that this one call is
   two thirds of a full zssl handshake. The `ecdsa_p256_verify` row above
   measures a libcrypto verifier that no code path in the library reaches.

   This is a decision to re-take with a number in hand, not a bug. Routing
   `verifyEcdsa` to libcrypto would take `handshake_full` from 495 µs to
   roughly 207 µs — a 2.4× improvement from one call site — at the cost of
   moving verification of attacker-supplied bytes from memory-safe Zig
   into C. The same question applies to `verifyRsaPss`, which was not
   measured here.

2. **X25519 — 76 µs.** zssl does four scalar multiplications per
   handshake (each peer derives a public and agrees a shared) for 122 µs;
   rustls does the same four for 46 µs. Part is that OpenSSL routes the
   fixed-base multiplication through the C `ge_scalarmult_base` while only
   the variable-base one reaches `x25519-x86_64.s`. But the split rows
   show something more specific: `x25519_public` is 17.75 µs and
   `x25519_shared` is 43.23 µs, when an agreement should be the *cheaper*
   of the two. A callgrind trace says why —
   `EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, …)` reaches
   `ossl_ecx_key_fromdata` → `ossl_ecx_public_from_private`
   (`crypto/ec/ecx_backend.c:99`), so constructing the private-key object
   **eagerly derives the public key**. Every agreement therefore pays for
   a fixed-base scalar multiplication it immediately throws away, roughly
   17.75 µs of the 43.23, twice per handshake — and the server pays it a
   third time, because it follows the agreement with a separate
   `keySharePublic` for the share on the wire. Building the key object
   with the public half supplied recovers ~35 µs per handshake without
   leaving libcrypto, and unlike the first item it costs nothing but code.

3. **`aead_key_init` — 5.3 µs.** 733.6 ns against 69.3 ns, and a
   handshake stands up eight traffic keys across both peers. Small, and
   listed only so it is not mistaken for the cause: an early guess that
   OpenSSL 3's implicit provider fetch in `EVP_EncryptInit_ex` was driving
   the handshake gap is what this row was added to test, and it refuted it.

4. **ECDSA signing — 1.8 µs.** libcrypto's `ecp_nistz256` and aws-lc-rs
   are within 12% of each other. Nothing to do here.

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
