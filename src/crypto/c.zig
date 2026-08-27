//! The single C import in zssl. Every libcrypto symbol enters through this
//! file, so "what does the C surface consist of" is answered by one import
//! list rather than a grep — and a second `@cImport` anywhere else in the
//! tree is a review failure, not a style preference.

pub const c = @cImport({
    @cInclude("openssl/crypto.h");
    @cInclude("openssl/evp.h");
    @cInclude("openssl/err.h");
});
