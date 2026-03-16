# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0](https://github.com/structured-world/krb5-rs/compare/v0.1.0...v0.2.0) - 2026-03-16

### Added

- *(crypto)* add AES-CTS-HMAC-SHA1-96 encryption module
- *(types)* implement all RFC 4120 + RFC 6113 ASN.1 types
- initial scaffold — Cargo.toml, src/lib.rs, CI workflows, README

### Fixed

- *(crypto)* enforce per-profile key length validation
- *(crypto)* pre-allocate zeroized plaintext buffer, return error on negative key_usage
- *(crypto)* validate key length, reject zero s2kparams, add MIT KAT vectors
- *(crypto)* add UnsupportedEtype error, zeroize plaintext buffer
- *(build)* remove no-op default features, move test import to top-level
- *(types)* secure EncryptionKey storage, enforce RFC 4120 till field, validate principal parsing
- *(types)* secure EncryptionKey zeroize and correct FromStr name_type

### Other

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
