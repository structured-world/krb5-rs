# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0](https://github.com/structured-world/krb5-rs/compare/v0.1.0...v0.2.0) - 2026-03-16

### Added

- *(protocol)* fall back to PA-ETYPE-INFO (type 11) for legacy KDCs
- *(protocol)* add AS exchange state machine
- *(crypto)* add AES-CTS-HMAC-SHA1-96 encryption module
- *(types)* implement all RFC 4120 + RFC 6113 ASN.1 types
- initial scaffold — Cargo.toml, src/lib.rs, CI workflows, README

### Fixed

- *(protocol)* pin chrono >= 0.4.38 for const east_opt, rename FieldTooLong
- *(protocol)* validate KRB-ERROR pvno/msg_type before processing
- *(test)* pipe master key twice for kdb5_util create -W (enter + verify)
- *(protocol)* use server realm field for WRONG_REALM redirect target
- *(protocol)* mark ErrorCode non_exhaustive, avoid abs() panic in time_diff
- *(protocol)* pipe passwords via stdin in KDC setup, add RetryTcp to doc example
- *(protocol)* reset loop_count on realm redirect, use env vars for KDC secrets
- *(protocol)* distinct rtime overflow message, validate TCP frame length
- *(protocol)* use ReplyValidation for lifetime overflow, typed error codes in tests
- *(protocol)* validate AS-REP pvno/msg_type, return error on till overflow
- *(protocol)* remove expect() panics, use Duration::MAX for skew overflow
- *(protocol)* use checked_add for till/rtime, precise error for missing e-data
- *(protocol)* realign RFC 4120 error codes 26-36, use preauth salt fallback
- *(protocol)* use Option salt, extract reply s2kparams, guard resp_len
- *(protocol)* clear cached preauth state on realm redirect
- *(protocol)* add realm validation, clamp duration cast, scope preauth loop
- *(protocol)* wire request_pac to include_pac, fix healthcheck and timestamps
- *(protocol)* mask nonce to 31 bits for MIT KDC compat
- *(protocol)* persist s2kparams, add RetryTcp, truncate timestamps
- *(crypto)* enforce per-profile key length validation
- *(crypto)* pre-allocate zeroized plaintext buffer, return error on negative key_usage
- *(crypto)* validate key length, reject zero s2kparams, add MIT KAT vectors
- *(crypto)* add UnsupportedEtype error, zeroize plaintext buffer
- *(build)* remove no-op default features, move test import to top-level
- *(types)* secure EncryptionKey storage, enforce RFC 4120 till field, validate principal parsing
- *(types)* secure EncryptionKey zeroize and correct FromStr name_type

### Other

- *(protocol)* scope module doc to AS exchange, clarify ErrorCode as typed source
- *(protocol)* note chrono const fn dependency for UTC_OFFSET
- *(test)* clarify default credentials are test-only, note tcp_send duplication
- *(protocol)* allow large_enum_variant on StepResult with justification
- *(protocol)* match on reference for Option salt fields
- *(protocol)* derive error constants from ErrorCode, prefer client etype order
- *(protocol)* clarify PreauthPlugin is an extension point, not wired
- *(protocol)* remove dead padata emptiness branch, renumber validation steps
- *(examples)* apply cargo fmt
- Merge remote-tracking branch 'origin/main' into feat/#14-crypto-aes-cts
- *(release)* add concurrency group to release job to prevent publish races
- *(release)* revert SHA pinning to version tags for dependabot compatibility
- *(release)* pin actions to SHA, scope permissions per job, add concurrency
- *(release)* add job ordering and remove unused token from release-pr
- *(release)* split into explicit release-pr and release jobs
- *(release)* replace manual tag workflow with release-plz automation
- *(types)* strengthen Debug redaction check with hex format assertion
- *(error)* remove duplicate fields from KdcError variant
- *(types)* tighten zeroize assertions and add semantic equality checks
- Initial commit
