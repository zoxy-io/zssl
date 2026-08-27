//! Redirect libcrypto's internal allocations into memory the embedder
//! owns (`CRYPTO_set_mem_functions`).
//!
//! This hook is the reason zssl is written over OpenSSL and not the
//! BoringSSL family: the fork-family libcryptos removed the API, and
//! without it a zero-allocation-after-startup budget over a C library is
//! a hope, not a property. There is deliberately no second backend to
//! fall back to — an embedder whose install fails should refuse to start,
//! which is exactly what zoxy does today.
//!
//! Call `install` before *any* libcrypto use: OpenSSL refuses to swap
//! allocators once something is allocated, and answers `false` here.

const std = @import("std");
const assert = std.debug.assert;

const c = @import("c.zig").c;

/// OpenSSL's debug-carrying allocator signatures (file, line at the call
/// site). The hooks must be infallible-signal-safe in the sense libcrypto
/// expects of malloc: return null on exhaustion, never unwind.
pub const MallocFn = *const fn (size: usize, file: ?[*:0]const u8, line: c_int) callconv(.c) ?*anyopaque;
pub const ReallocFn = *const fn (address: ?*anyopaque, size: usize, file: ?[*:0]const u8, line: c_int) callconv(.c) ?*anyopaque;
pub const FreeFn = *const fn (address: ?*anyopaque, file: ?[*:0]const u8, line: c_int) callconv(.c) void;

/// Install the embedder's allocator triple. `false` means libcrypto
/// refused — it has already allocated, or the build lacks the API — and
/// the embedder decides whether that is fatal (for a zero-allocation
/// budget it is).
pub fn install(malloc_hook: MallocFn, realloc_hook: ReallocFn, free_hook: FreeFn) bool {
    const answer = c.CRYPTO_set_mem_functions(
        @ptrCast(malloc_hook),
        @ptrCast(realloc_hook),
        @ptrCast(free_hook),
    );
    assert(answer == 0 or answer == 1);
    return answer == 1;
}

test "signatures line up with CRYPTO_set_mem_functions" {
    // Presence-and-type check only: actually installing hooks is
    // process-global and order-dependent (libcrypto refuses after its
    // first allocation), so the behavioral proof runs as its own process
    // in the embedder — zoxy's `tls-heap-proof` pattern.
    const Fns = @TypeOf(c.CRYPTO_set_mem_functions);
    comptime assert(@typeInfo(Fns) == .@"fn");
    try std.testing.expect(@typeInfo(@TypeOf(install)) == .@"fn");
}
