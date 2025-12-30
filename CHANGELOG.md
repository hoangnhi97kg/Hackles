# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- 7 new security queries (128 -> 135 total):
  - **RODC Security**: Allowed RODC Password Replication Group members, Tier Zero missing from Denied RODC Replication
  - **Domain Config**: Domain functional level check, Single point of failure DCs
  - **AdminSDHolder**: Non-Tier Zero principals with AdminSDHolder control
  - **Hygiene**: Logon scripts in trusted domains, Unresolved SIDs with outbound control
- Comprehensive test suite for config singleton and utils module (77 tests total)

### Fixed

- README examples now include correct `-u neo4j` flag and default password
- Test files use correct function names from abuse loader module

### Changed

- Removed internal development files from repository (CODE_REVIEW.md, QUERY_GAP_ANALYSIS.md, debug files)

## [0.1.0] - 2024-12-29

### Added

- Initial release of Hackles
- 128 security queries across 13 categories:
  - ACL Abuse
  - ADCS (ESC1-ESC15)
  - Attack Paths
  - Azure/Hybrid
  - Basic Info
  - Credentials/Privilege Escalation
  - Dangerous Groups
  - Delegation
  - Exchange
  - Lateral Movement
  - Miscellaneous
  - Owned Principal Analysis
  - Security Hygiene
- Multiple output formats: table, JSON, CSV, HTML reports
- Severity-based filtering (CRITICAL, HIGH, MEDIUM, LOW, INFO)
- Abuse command templates with 58 YAML-based attack guides
- Owned principal management and highlighting
- Tier Zero asset management
- Path finding (shortest path, path to DA, path to DC)
- Node exploration and search
- Group membership analysis
- Admin rights enumeration
- Edge exploration
- Quick filters (Kerberoastable, AS-REP, Unconstrained, No LAPS)
- Custom Cypher query support
- Domain filtering
- Quiet mode for scripting
- Progress bar for long-running queries
- Debug mode for troubleshooting

### Security

- Environment variable support for credentials
- No hardcoded sensitive values

[Unreleased]: https://github.com/Real-Fruit-Snacks/hackles/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Real-Fruit-Snacks/hackles/releases/tag/v0.1.0
