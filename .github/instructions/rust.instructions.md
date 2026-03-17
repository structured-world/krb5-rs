---
applyTo: "**/*.rs"
---

# Rust Code Review Instructions

## Review Priority (HIGH -> LOW)

Focus review effort on real bugs, not cosmetics. Stop after finding issues in higher tiers -- do not pad reviews with low-priority nitpicks.

### Tier 1 -- Logic Bugs and Correctness (MUST flag)
- Wrong key usage: encrypting with the wrong key type or key usage number (RFC 4120 section 7.5.1)
- Wrong encryption order: encrypt-then-MAC vs MAC-then-encrypt mismatch for the cipher suite
- ASN.1 validation: accepting malformed DER, skipping tag/length checks, wrong IMPLICIT/EXPLICIT tagging
- Replay counter issues: nonce reuse, sequence number wrapping without re-keying, stale timestamp acceptance
- Off-by-one in boundaries, index lookups, or range operations
- TOCTOU: checking state then acting on it without holding a lock or atomic operation
- Missing validation: unchecked index, unvalidated input from network/KDC/keytab/credential cache
- Resource leaks: unclosed file handles, missing cleanup on error paths
- Concurrency: data races, lock ordering violations, missing synchronization
- Error swallowing: `let _ = fallible_call()` silently dropping errors that affect correctness
- Integer overflow/truncation on sizes, offsets, lengths, or security-critical values

### Tier 2 -- Safety and Crash Recovery (MUST flag)
- `unsafe` without `// SAFETY:` invariant explanation
- `unwrap()`/`expect()` on I/O, network, or deserialization paths (must use `Result` propagation)
- Sensitive data (PMK, session keys, passwords, pre-authentication data) not wrapped in `Zeroize`/`Zeroizing`
- Constant-time comparison not used for MAC verification, checksum validation, or password-derived key checks
- fsync ordering for credential caches: write temp file, fsync, rename -- not write-in-place without sync
- Hardcoded secrets, credentials, or private URLs

### Tier 3 -- API Design and Robustness (flag if clear improvement)
- Public API missing `#[must_use]` on builder-style methods or non-`Result` types callers might discard
- `pub` visibility where `pub(crate)` suffices
- Missing `Send + Sync` bounds on types used across threads
- `Clone` on large types where a reference would work
- Fallible operations returning `()` instead of `Result`

### Tier 4 -- Style (ONLY flag if misleading or confusing)
- Variable/function names that actively mislead about behavior
- Dead code (unused functions, unreachable branches)

## DO NOT Flag (Explicit Exclusions)

These are not actionable review findings. Do not raise them:

- **Kerberos bit numbering**: Bit positions in `KerberosFlags` use MSB-first numbering in a 32-bit field per RFC 4120 section 5.2.8. Bit 0 is the most significant bit. Do not flag this as "reversed" or "off-by-one" -- it is correct per the RFC.
- **RFC compliance comments as documentation**: Comments referencing RFC 4120, RFC 4121, RFC 3961, RFC 3962, RFC 6113, or other Kerberos/crypto RFCs are specification traceability, not noise. Do not suggest removing or shortening them.
- **Comment wording vs code behavior**: If a comment says "decrypt the ticket" but the function also validates the checksum, the intent is clear. Do not suggest rewording comments to match exact implementation steps. Comments describe intent, not repeat the code.
- **Comment precision**: "returns the session key" when it technically returns `Result<SessionKey>` -- the comment conveys meaning, not type signature.
- **Magic numbers with context**: `12` in `assert_eq!(nonce.len(), 12, "expected 96-bit nonce")` -- the assertion message provides context. Do not suggest a named constant when the value is used once in a test with an explanatory message.
- **Domain constants**: Specific numeric values for key sizes (e.g., `16`, `32`), encryption type numbers (e.g., `17` for aes128-cts-hmac-sha1-96), protocol version numbers, port `88`, or ticket lifetimes are domain constants, not magic numbers, when used with surrounding context.
- **Minor naming preferences**: `enc_part` vs `encrypted_part`, `tgt` vs `ticket_granting_ticket`, `kvno` vs `key_version_number` -- these are team style, not bugs.
- **Import ordering**: Import grouping or ordering style. Unused imports are NOT cosmetic -- they cause `clippy -D warnings` failures and must be removed.
- **Test code style**: Tests prioritize readability and explicitness over DRY. Repeated setup code in tests is acceptable.
- **`#[allow(clippy::...)]` in existing code**: Existing `#[allow]` suppressions with justification comments are legacy -- do not flag in unchanged code. New code in PRs should use `#[expect(clippy::...)]`.

## Scope Rules

- **Review ONLY code within the PR's diff.** Do not suggest inline fixes for unchanged lines.
- For issues **outside the diff**, suggest opening a separate issue.
- **Read the PR description.** If it lists known limitations or deferred items, do not re-flag them.

## Rust-Specific Standards

- Prefer `#[expect(lint)]` over `#[allow(lint)]` -- `#[expect]` warns when suppression becomes unnecessary
- `TryFrom`/`TryInto` for fallible conversions; `as` casts need justification
- No `unwrap()` / `expect()` on I/O paths -- use `?` propagation
- `expect()` is acceptable for programmer invariants (e.g., lock poisoning, `const` construction) with reason
- Code must pass `cargo clippy --all-features -- -D warnings`
- RFC compliance comments (e.g., "RFC 4120 section 7.5.1", "RFC 3961 section 5.3") are documentation -- preserve them

## Testing Standards

- Test naming: `fn <what>_<condition>_<expected>()` or `fn test_<scenario>()`
- Use `tempfile::tempdir()` for test directories (e.g., credential cache files) -- ensures cleanup even on panic
- Integration tests that require a KDC use `#[ignore = "reason"]`
- Prefer `assert_eq!` with message over bare `assert!` for better failure output
- Hardcoded values in tests are fine when accompanied by explanatory comments or assertion messages
- Corruption/validation tests: tamper the relevant field (e.g., ciphertext byte, checksum, ASN.1 tag) and assert the error
