#!/usr/bin/env bash
# Cargo, from the same nixpkgs the dev shell pins, plus the two things
# `aws-lc-sys` needs to build its C and assembly: cmake and a compiler.
#
# devenv.nix deliberately carries no Rust — nothing zssl ships needs one,
# and the six gates in CLAUDE.md would not be improved by a 1.1 GiB
# toolchain in every developer's shell. The comparison harness is the only
# thing here that wants a `cargo`, so it brings its own.
set -euo pipefail
exec nix shell nixpkgs#cargo nixpkgs#rustc nixpkgs#cmake --command cargo "$@"
