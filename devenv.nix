# Dev environment (https://devenv.sh): the pinned toolchain.
#
# This is a list of gate dependencies — what it takes to run CLAUDE.md's
# six gates, plus `zig build coverage`, from a bare checkout. Two notes
# below on what is not here: a package no gate runs, and a gate no
# package can satisfy.
#
#   zig       every gate; 0.16.0 exactly, the other half of the
#             `minimum_zig_version` pin in build.zig.zon
#   openssl   `zig build interop` spawns the real `openssl s_client` /
#             `s_server`. This is `.bin`, not zoxy's `.dev`: zssl builds
#             libcrypto from the build.zig.zon dependency rather than
#             linking a system one, so it needs the *binary* to talk to
#             and no headers at all
#   go        `zig build bogo` — BoGo's runner is a Go program
#   python3   `zig build tlsfuzzer` — tlsfuzzer is a Python program, and
#             the gate builds its own virtualenv over this interpreter
#   git       the bogo and tlsfuzzer gates fetch their pinned checkout
#             with it
#   kcov      `zig build coverage`, Linux only (it is the DWARF
#             instrumentation the coverage badge is computed from)
#
# `zig build tlsanvil` is the one gate with no row here, and deliberately
# so. TLS-Anvil ships as a container, so what it needs is a reachable
# Docker *daemon* — and a daemon is not a package. Shipping `pkgs.docker`
# would put a client on PATH without the thing it talks to, which reads
# as "this shell covers tlsanvil" while the SKIP still fires; worse, on a
# host that does have a daemon it would shadow the matching client with a
# nix-pinned one. A machine with a daemon already has its client.
#
# So: for every gate that needs a *binary*, the shell supplies it, and
# the SKIP paths those gates carry — exit 2 for "no openssl / no Go / no
# python3" — cannot fire in here. None of the scripts below swallow exit
# 2 anyway. Inside this shell a 2 means no Docker daemon, or no network
# on a cold adversarial run; both are infrastructure failures rather than
# passes. That is the same reasoning .github/workflows/tlsfuzzer.yml
# records for not tolerating it either.
#
# zls is the exception, and the only reason there is no CI/dev split like
# zoxy's: zssl's workflows install their toolchain with mlugg/setup-zig
# and actions/setup-go, so no CI job ever enters this shell and there is
# no CI closure worth gating one editor LSP out of.
#
# Activated automatically by `.envrc` via direnv, or manually with
# `devenv shell`.
{ pkgs, lib, ... }:
{
  packages =
    [
      pkgs.zig_0_16
      pkgs.openssl.bin
      pkgs.go
      pkgs.python3
      pkgs.git
      # Editor LSP — the one package no gate runs.
      pkgs.zls
    ]
    ++ lib.optionals pkgs.stdenv.hostPlatform.isLinux [
      pkgs.kcov
    ];

  # Named to avoid shadowing the `test` and `build` shell builtins,
  # matching the sibling zurl and hparse checkouts so muscle memory
  # carries across.
  scripts.zb.exec = ''zig build "$@"'';
  scripts.zt.exec = ''zig build test --summary all "$@"'';
  scripts.zc.exec = ''
    zig fmt --check src interop bench bogo tlsanvil tlsfuzzer scripts build.zig build.zig.zon \
      && zig build test --summary all \
      && zig build test -Doptimize=ReleaseSafe --summary all \
      && zig build interop
  '';
  scripts.za.exec = ''
    zig build bogo && zig build tlsfuzzer && zig build tlsanvil
  '';

  enterShell = ''
    echo "zssl dev shell — zig $(zig version), $(openssl version | cut -d' ' -f1-2), go $(go version | cut -d' ' -f3 | sed s/^go//), python $(python3 --version | cut -d' ' -f2)"
    echo "  zb  → zig build"
    echo "  zt  → zig build test --summary all"
    echo "  zc  → the commit gate: fmt, test, test ReleaseSafe, interop"
    echo "  za  → the adversarial trio: bogo, tlsfuzzer, tlsanvil (needs network on a cold run, and Docker for tlsanvil)"
  '';

  # `devenv test` runs the commit gate from CLAUDE.md. The adversarial
  # trio is left to `za` on purpose: a cold run pulls a BoringSSL
  # checkout, a tlsfuzzer checkout and a container image, and minutes of
  # network do not belong in the thing you reach for to check a shell
  # still works. tlsanvil also wants a daemon this shell cannot promise.
  enterTest = ''
    zig fmt --check src interop bench bogo tlsanvil tlsfuzzer scripts build.zig build.zig.zon
    zig build test --summary all
    zig build test -Doptimize=ReleaseSafe --summary all
    zig build interop
  '';
}
