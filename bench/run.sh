#!/usr/bin/env bash
# Run both halves of the rustls comparison and print the table.
#
# Both binaries are pinned to one core, and the default is a *P*-core.
#
# The machine this was written on is a Lunar Lake laptop: four P-cores at
# 4.7-4.8 GHz and four low-power E-cores at 3.7 GHz. An unpinned run
# migrates between the two mid-round and reports a spread wider than most
# of the differences being measured — a ~30% frequency step is larger than
# every result in the table. Pinning does not make the numbers absolute,
# nothing on a laptop does, but it makes the two sides comparable, which is
# the only claim this harness makes.
#
# Override with BENCH_CORE, and check what you are picking:
# `cat /sys/devices/system/cpu/cpuN/cpufreq/cpuinfo_max_freq` separates the
# two kinds. The governor is not the thing to worry about here — under
# `intel_pstate`, `powersave` is the default dynamic governor and still
# reaches full turbo.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(dirname "$here")"
results="$here/results"
core="${BENCH_CORE:-2}"
mkdir -p "$results"

echo "bench: building zssl harness (ReleaseFast, own libcrypto)" >&2
zig build --build-file "$root/build.zig" >&2

echo "bench: building rustls harness (release, lto)" >&2
"$here/cargo.sh" build --release --manifest-path "$here/rustls-bench/Cargo.toml" >&2

echo "bench: running on core $core" >&2
taskset -c "$core" "$root/zig-out/bin/zssl-bench" > "$results/zssl.jsonl"
taskset -c "$core" "$here/rustls-bench/target/release/rustls-bench" > "$results/rustls.jsonl"

python3 "$here/compare.py" --zssl "$results/zssl.jsonl" --rustls "$results/rustls.jsonl" \
  | tee "$results/comparison.txt"
