# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0](https://github.com/structured-world/krb5-rs/compare/v0.1.0...v0.2.0) - 2026-03-15

### Added

- *(types)* implement all RFC 4120 + RFC 6113 ASN.1 types
- initial scaffold — Cargo.toml, src/lib.rs, CI workflows, README

### Fixed

- *(build)* remove no-op default features, move test import to top-level
- *(types)* secure EncryptionKey storage, enforce RFC 4120 till field, validate principal parsing
- *(types)* secure EncryptionKey zeroize and correct FromStr name_type

### Other

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
