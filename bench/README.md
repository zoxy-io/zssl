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
a 3.9× full-handshake gap; it now reads 1.36×, and resumption 1.11×,
with `handshake_full` down from 495 µs to 172 µs. Neither fix touched
the protocol layer:

| | `handshake_full` | vs rustls |
|---|---|---|
| as measured | 495.14 µs | 3.90× slower |
| ECDSA verification through libcrypto | 208.38 µs | 1.64× slower |
| one key-exchange multiplication instead of two | **171.86 µs** | **1.36× slower** |

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
  handshake_full               171.86 us       126.76 us     1.36x slower
  handshake_resume             105.12 us        94.86 us     1.11x slower

Handshake, by flight
  phase_client_hello            17.97 us        15.25 us     1.18x slower
  phase_server_flight           66.92 us        47.83 us     1.40x slower
  phase_client_finish           83.18 us        61.34 us     1.36x slower
  phase_server_finish            2.92 us         1.88 us     1.55x slower

Bulk data (16 KiB record, sealed and opened)
  transfer_aes128     3.43 us  4.78 GB/s   4.39 us  3.73 GB/s  1.28x faster
  transfer_aes256     3.99 us  4.10 GB/s   4.95 us  3.31 GB/s  1.24x faster
  transfer_chacha20  10.56 us  1.55 GB/s  10.73 us  1.53 GB/s  1.02x faster

Primitives
  aead_seal_aes128     1.63 us 10.08 GB/s  1.67 us  9.80 GB/s  1.03x faster
  aead_seal_aes256     1.89 us  8.69 GB/s  1.94 us  8.44 GB/s  1.03x faster
  aead_seal_chacha20   4.97 us  3.29 GB/s  4.92 us  3.33 GB/s  1.01x slower
  aead_key_init                 737.3 ns         69.4 ns    10.63x slower
  ecdsa_p256_sign                16.47 us        14.67 us     1.12x slower
  ecdsa_p256_verify              43.80 us        34.53 us     1.27x slower
  x25519_keygen_agree            44.04 us        23.01 us     1.91x slower
  x25519_public                  17.85 us         4.57 us     3.91x slower
  x25519_shared                  25.96 us        16.22 us     1.60x slower
  x25519_shared_rederive         43.27 us              —
  p256_verify_stdcrypto         333.15 us              —
```

`x25519_keygen_agree` and the `x25519_public`/`x25519_shared` pair answer
different questions and do not sum to each other. The split is
per-*operation*, and it is what the analysis below reasons about: an
import plus a fixed-base multiplication, then a variable-base one.
`x25519_keygen_agree` is per-*handshake-side*, and for rustls that
includes generating the ephemeral — ~2.2 µs of CSPRNG that zssl does not
pay, because DESIGN.md's no-randomness rule has the scalar arrive through
`Config`. Handshake arithmetic below uses the per-side row for rustls,
because generating is what its handshake actually does.

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
| `handshake_full` | 495.14 µs | 208.38 µs | **171.86 µs** |
| `handshake_resume` | 141.29 µs | 140.97 µs | **105.12 µs** |
| `phase_server_flight` | 86.63 µs | 84.51 µs | **66.92 µs** |
| `phase_client_finish` | 386.01 µs | 101.34 µs | **83.18 µs** |
| ratio against rustls | 3.90× | 1.64× | **1.36×** |

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
| crypto in a full handshake | 147.9 µs | 95.2 µs |
| everything else | **24.0 µs** | **31.5 µs** |
| crypto's share | 86% | 75% |

zssl's state machine, parsing, key schedule and transcript hashing cost
about 24 µs per handshake against rustls's 32 — and zssl's figure is the
more pessimistic of the two, because it also carries the `EVP_PKEY`
import `ecFromPublic` does per verification, which the standalone
`ecdsa_p256_verify` row does not pay. The same ordering holds on the
resumed path — 20 µs against 49 — and on bulk data, where zssl's record
layer adds 6% over the raw AEAD and rustls's connection path adds 31%,
which is what the extra buffer copies between `writer()`, `sendable_tls`,
`write_tls`, `read_tls` and `reader()` cost. Nothing in this tree needs
to get faster for zssl to win those rows; it already does.

**The remaining 45 µs gap is almost all one thing, and it is no longer
ours.** It decomposes to within about 10%, the residue being the four
clock reads the phase split adds:

1. **X25519 — 42 µs, 92% of what is left, and none of it ours.** The
   split rows say where: a fixed-base multiplication to build a share
   costs 17.85 µs against aws-lc-rs's 4.57 (**3.91×**), and a
   variable-base one to agree costs 25.96 against 16.22 (**1.60×**). A
   handshake does two of each.

   This was checked for "are we holding it wrong?" before being written
   off, and the answer is no:

   - **It is not EVP bookkeeping.** Importing a 32-byte public value and
     freeing it — a full `EVP_PKEY` round trip with no scalar
     multiplication anywhere in it — costs **667 ns**, and the
     `OSSL_PARAM_BLD` + `EVP_PKEY_CTX_new_from_name` route `agree` takes
     costs 732 ns. Against 17–26 µs of work that is 3–5%.
   - **Caching the `EVP_PKEY` across `init` and `agree` buys 1.25 µs**
     (26.04 → 24.79), about 5% of one agreement and 1.4% of a handshake.
     Not taken: it would turn `KeyShare` from plain data into a type that
     owns a libcrypto handle and therefore cannot be copied, and that is
     a bad trade against a state machine for 1.4%.
   - **The build is not missing assembly.** `X25519_ASM` is defined,
     `x25519-x86_64.s` is compiled in, and `OPENSSL_ia32cap` has the ADX
     bit, so `x25519_scalar_mulx` is the path taken. The external check
     agrees: `openssl speed ecdhx25519` on the system's stock OpenSSL
     3.6.3 reports 45,318 op/s — **22.06 µs**, against our 24.79 for the
     same operation on the vendored 3.5.7.
   - **The routing is already the right way round.** OpenSSL sends the
     variable-base multiplication to the ADX assembly and the fixed-base
     one to `ge_scalarmult_base`; going the other way and computing a
     public value as X25519(scalar, 9) reaches the assembly but costs
     23 µs against the 17 µs the C tables take. Slower, not faster.

   What is left is upstream implementation quality, in two different
   places. `ossl_x25519` uses OpenSSL's own fe64/ADX assembly, where
   AWS-LC uses s2n-bignum's — a straight 1.6×. And
   `ossl_x25519_public_from_private` has no assembly at all: it runs
   `ge_scalarmult_base`, the ref10 Ed25519 code with base-2^25.5 `int32`
   limbs, which is the portable representation OpenSSL never wired to the
   2^51/2^64 field arithmetic it ships for the other direction. That one
   is the 3.91×, and it is why the fixed-base row is the *larger* half of
   the remaining gap even though the operation is cheaper.

   Nothing in this tree can close either without reaching for OpenSSL's
   internal `ossl_x25519` (an `ossl_`-prefixed symbol, not public API and
   one pin bump from renaming) or a second backend, which DESIGN.md §2
   rules out. **This row is done.**

   ### Is the vendored libcrypto built right?

   Asked separately, because "upstream is slower" is a convenient answer
   and the build is the thing we control. It is built at `ReleaseFast`
   (`zig build --summary all` says `compile lib crypto ReleaseFast
   native`), and `build.zig` gives the bench its *own* ReleaseFast
   libcrypto rather than inheriting `-Doptimize`. C is compiled by clang
   either way — Zig has no self-hosted C backend, so the `use_llvm`
   question only ever applies to Zig code, and ReleaseFast uses LLVM for
   that too.

   Linking one C program against different libcryptos, same machine, same
   core, `EVP` calls identical to the ones the backend makes:

   | libcrypto | fixed-base | variable-base |
   |---|---|---|
   | ours, 3.5.7, Zig/clang ReleaseFast | 17,590 ns | 24,065 ns |
   | stock 3.5.7, gcc -O3 (nixpkgs) | 15,695 ns | 22,488 ns |
   | stock 3.6.3, gcc -O3 (nixpkgs) | 15,175 ns | 22,376 ns |

   Stock 3.5.7 is the control that matters: same source version as our
   pin, so the ~12% and ~7% are the *build*, not the release. Chasing
   that down to flags, by compiling `crypto/ec/curve25519.c` alone and
   timing `ossl_x25519_public_from_private` — pure C, none of the X25519
   assembly — with everything else held fixed:

   | compiler and flags | ns |
   |---|---|
   | `zig cc -O2`, sanitizers off — the ReleaseFast default | 16,451 |
   | `zig cc -O3`, sanitizers off | 16,465 |
   | `zig cc -O2 -fsanitize=undefined -fsanitize-trap=undefined` — the ReleaseSafe default | 18,598 |
   | `gcc -O2` | 18,630 |
   | `gcc -O3` | 14,894 |

   Two plausible diagnoses died here, which is most of the value:

   - **`-O2` is not a bug to fix.** Zig's ReleaseFast really does hand
     clang `-O2` rather than the `-O3` a distro uses, and that looked like
     the answer until it was measured: clang emits the same speed either
     way. Adding `-O3` to the openssl package's `base_flags` would buy
     **nothing**. Only gcc cares, by 1.25x.
   - **Frame pointers are not it either.** Zig passes
     `-fno-omit-frame-pointer`; removing it changes nothing measurable on
     either compiler.

   `-DNDEBUG` is set — checked with a C file that `#error`s under
   `#ifndef NDEBUG`, not assumed.

   So the residual against a distro build is gcc-versus-clang codegen on
   ref10's `int32` limb arithmetic, worth ~2% of a handshake, and there is
   no flag that recovers it. The build is right.

   ### What `sanitize_c = .off` is actually worth

   Both libcryptos in `build.zig` set it — the gate's at line 18 and the
   bench's — and it is worth being precise about where that matters,
   because it is easy to credit it with more than it does. Zig turns
   `-fsanitize=undefined -fsanitize-trap=undefined` on for C at **Debug
   and ReleaseSafe**, and off at **ReleaseFast**:

   - At ReleaseFast, where the numbers on this page are taken, the setting
     is a **no-op**. The sanitizers were never on.
   - At ReleaseSafe — which CLAUDE.md says is what release builds ship —
     it is worth **1.13x** on this routine, on top of the correctness
     reason it was added for (zoxy's #283, where `-fsanitize=function`
     turned `OPENSSL_sk_pop_free` into a `ud1` trap at key load).

   An earlier version of this section claimed 1.77x. That number was real
   but described something else: `zig cc -O2` defaults to *non-trapping*
   UBSan, with a runtime handler, which no zssl build uses. Measuring the
   driver instead of the build is exactly the mistake this section exists
   to catch.

   ### ReleaseFast is measured; ReleaseSafe is what ships

   CLAUDE.md ships release builds at `-Doptimize=ReleaseSafe`, so a page
   quoting only ReleaseFast would describe a configuration nobody runs.
   `zig build bench -Dbench-optimize=ReleaseSafe` builds the harness, zssl
   and libcrypto that way instead. It costs less than the run-to-run
   spread on the rows that matter:

   | | ReleaseFast | ReleaseSafe |
   |---|---|---|
   | `handshake_full` | 171.86 µs | 174.23 µs (+1.4%) |
   | `handshake_resume` | 105.12 µs | 107.85 µs (+2.6%) |
   | `transfer_aes128` | 3.43 µs | 3.54 µs (+3.2%) |
   | `record_aes128` | 3.44 µs | 3.47 µs (+0.9%) |
   | `aead_seal_aes128` | 1.63 µs | 1.63 µs (—) |
   | `x25519_shared` | 25.96 µs | 26.05 µs (—) |
   | `ecdsa_p256_verify` | 43.80 µs | 44.24 µs (+1.0%) |

   The primitive rows do not move at all, which is the check that the two
   builds differ only where they should: libcrypto is compiled the same
   both times, and what ReleaseSafe adds is Zig's bounds and overflow
   checks over zssl's own ~24 µs. Paying 1.4% of a handshake for them is
   the trade this tree would make every time.

   What *was* ours is fixed, and `x25519_shared_rederive` is what it
   cost. `EVP_PKEY_new_raw_private_key` reaches `ossl_ecx_key_fromdata` →
   `ossl_ecx_public_from_private` (`crypto/ec/ecx_backend.c:99`, and a
   callgrind trace confirms it), so building a key object from a scalar
   alone **eagerly derives the public key**. An agreement handed only a
   scalar therefore paid a fixed-base multiplication it discarded: 43.27
   µs against the 25.96 the same agreement costs when the public half
   comes with it. The server paid it twice over — once inside the
   agreement, once again in a separate `keySharePublic` for the share on
   the wire. `backend.KeyShare` bundles the two halves so `init`
   multiplies once and `agree` is handed the answer.

2. **ECDSA verification — 9 µs.** 43.80 µs against aws-lc-rs's 34.53.
   Both are assembly (`ecp_nistz256` against aws-lc's own); a 28%
   difference between two hand-written P-256 implementations is not
   something this tree can act on.

3. **`aead_key_init` — 5.3 µs.** 737.3 ns against 69.4 ns, and a
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
`zig build bench -Dbench-optimize=ReleaseSafe` measures the mode release
builds actually ship, rather than the one that compares against rustls's
`--release`; both are in the results above.

devenv.nix deliberately carries no Rust toolchain: nothing zssl ships
needs one, and none of the six gates in CLAUDE.md would be improved by
1.1 GiB in every developer's shell. `cargo.sh` fetches its own.
