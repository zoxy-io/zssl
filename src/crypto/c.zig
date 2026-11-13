//! The single C import in zssl. Every libcrypto symbol enters through this
//! file, so "what does the C surface consist of" is answered by one import
//! list rather than a grep — and a second C import anywhere else in the
//! tree is a review failure, not a style preference.
//!
//! The list is `c.h`, beside this file. Zig 0.17 removed `@cImport`, so
//! the headers can no longer be named here: build.zig's
//! `addLibcryptoImport` translates `c.h` per target and mode, against
//! the headers the `crypto` artifact installs for that target, and hands
//! the result to every module that compiles this file as `libcrypto`.
//! The invariant keeps its shape — one `#include` list in `c.h`, one
//! `addTranslateC` in build.zig, and this file the only one that imports
//! what it produces.

pub const c = @import("libcrypto");
