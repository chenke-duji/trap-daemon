# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added

- **CHANGELOG.md**: this file, to track notable changes going forward.

---

## [0.1.0] - 2026-09-13

### Added

- Initial release: multi-threaded SNMP Trap Daemon (v1/v2c/v3) receiving traps
  over UDP 162, mapping varbind OIDs to field names via the oid-database, and
  batch-forwarding `RawEvent` payloads to cep-engine.
- Prometheus metrics: uptime, cumulative trap count, last-5min throughput.
- `-v` flag printing build version/date.
- Active-Active stateless deployment (dedup left to cep-engine).

### Fixed

- Code review remediation (P0–P3) and SNMP v3 support.
- golangci-lint gosec/gocritic findings; CI Go version pinned to 1.22.
- Renamed `com.raysdata` → `com.dujitech` in docs and comments.
