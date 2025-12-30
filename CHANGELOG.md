# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **`--investigate` command**: Comprehensive one-command investigation of any node (user/computer/group):
  - Auto-detects node type and shows relevant information
  - **User investigation**: Properties, group memberships, outbound/inbound attack edges, admin rights, active sessions, path to DA
  - **Computer investigation**: Properties, active sessions, local admins, group memberships, attack edges
  - **Group investigation**: Properties, members (with Admin column), parent groups, inbound control edges
  - Supports wildcards for triage: `--investigate '*.DOMAIN.COM'` shows summary table sorted by attack relevance
  - Critical attack edges (GenericAll, WriteDacl, etc.) highlighted in red
  - Works with `--abuse` flag to show exploitation commands for each outbound attack edge

- **Wildcard support for node operations**: All node operation commands now support `*` wildcards for pattern matching:
  - `--info '*.DOMAIN.COM'` - Get info for multiple nodes matching pattern
  - `--sessions '*.DOMAIN.COM'` - Sessions across multiple computers
  - `--adminto '*.DOMAIN.COM'` - Admins to multiple computers
  - `--adminof 'SVC_*'` - Admin rights for multiple principals
  - `--members 'DOMAIN *'` - Members of multiple groups (with Admin column)
  - `--memberof 'SVC_*'` - Group memberships for multiple principals
  - `--edges-from '*.DOMAIN.COM'` - Outbound edges from multiple nodes
  - `--edges-to 'DOMAIN ADMINS*'` - Inbound edges to multiple nodes
  - Results include source/target context column when wildcards are used

- **Quick enumeration flags**: New standalone commands for rapid domain enumeration:
  - `--computers` - List all domain computers with OS, LAPS, and delegation status
  - `--users` - List all domain users with admin, SPN, AS-REP, and password flags
  - `--spns` - List all Service Principal Names for Kerberoasting targeting

- **`--quick-wins` command**: Consolidated view of lowest-effort/highest-impact attack paths:
  - Direct paths to Domain Admins (1-2 hops)
  - Kerberoastable admin accounts with password age
  - AS-REP roastable accounts
  - Direct ACL abuse to high-value targets (GenericAll, WriteDacl, etc. to DA/DC/Tier Zero)

- **2 new coercion queries** (150 → 152 total):
  - **Coercion Targets**: Lists all DCs and unconstrained delegation systems as potential coercion targets
  - **Coercion to Unconstrained Chain**: Shows DC → Unconstrained attack chains for TGT capture (domain compromise path)

### Improved

- **`--members` output**: Now includes Admin column showing `admincount` status, with results sorted by admin status first (admins at top)

## [0.2.0] - 2025-12-30

### Added

- **22 new security queries** (128 → 150 total):
  - **ACL Abuse** (7 new):
    - GenericAll, WriteDacl, ForceChangePassword, GenericWrite, AddMember - dedicated queries with target admin/enabled status
    - AllExtendedRights abuse detection - finds non-admin principals with full extended rights (password reset, DCSync, LAPS read)
    - Schema/Configuration partition control - detects WriteDACL/WriteOwner over critical AD partitions (forest-wide risk)
  - **Delegation** (4 new):
    - Multi-hop delegation chains to DCs
    - Computer accounts with dangerous delegation
    - S4U2Self + Unconstrained Delegation - Protocol Transition attack detection (impersonate ANY user)
    - Unconstrained Delegation → DC paths - Golden Ticket risk assessment
  - **Service Account Security** (3 new): Admin rights, dangerous delegation, interactive logon detection
  - **ADCS**: ESC3 dedicated enrollment agent abuse query with template detection
  - **RODC Security** (2 new): Allowed replication group members, Tier Zero missing from denied replication
  - **Domain Config** (2 new): Functional level check, single point of failure DCs
  - **Hygiene** (2 new): Logon scripts in trusted domains, unresolved SIDs with outbound control
  - **ACL** (1 new): AdminSDHolder control by non-Tier Zero principals

- **User Input Enhancement Features**:
  - `--from-owned PRINCIPAL`: Filter owned queries to analyze paths from a specific owned principal only (11 owned queries updated)
  - `--abuse-var KEY=VALUE`: Pre-fill abuse template placeholders (e.g., `--abuse-var DC_IP=192.168.1.10`)
  - `--abuse-config FILE`: Load abuse variables from config file (KEY=VALUE format)
  - Auto-loads `~/.hackles/abuse.conf` if it exists
  - `--stale-days N`: Customize stale account threshold (default: 90 days) - affects stale accounts and computer stale password queries
  - `--max-path-depth N`: Maximum hops in path queries (default: 5) - affects 15 path-finding queries
  - `--max-paths N`: Maximum paths to return from queries (default: 25) - affects 15 path-finding queries

- **9 abuse template wirings** added to previously uncovered queries:
  - ESC8, ESC11, ESC15 ADCS queries now call their abuse templates
  - ESC2/ESC3 any_purpose_templates.py now calls ADCSESC2
  - manage_ca.py now calls ADCSESC7
  - WriteAccountRestrictions, GPO Interesting Names, Plaintext userPassword queries

- Comprehensive test suite for config singleton and utils module (77 tests total)

### Fixed

- README examples now include correct `-u neo4j` flag and default password
- Test files use correct function names from abuse loader module
- **Domain Functional Level query**: Fixed type comparison error when BloodHound returns level as string (e.g., "2016") instead of integer
- **RODC Allowed Replication query**: Fixed Cypher syntax error with ORDER BY after RETURN DISTINCT
- **Delegation Chains query**: Fixed Cypher syntax error - ORDER BY now uses aliased column names after RETURN DISTINCT
- **Abuse template "Ready-to-Paste" section**: No longer shows empty header when context cannot fill command placeholders
- **Abuse template placeholder substitution** - Enhanced Ready-to-Paste command generation:
  - `<GROUP>` placeholder now correctly fills when target is a Group (e.g., `net rpc group addmem 'DOMAIN ADMINS'`)
  - `<TARGET$>` placeholder now adds `$` suffix for computer account targets (RBCD attacks)
  - `<TARGET>` placeholder now fills for lateral movement commands (WinRM, RDP, PSRemote) from computer field
  - `<PASSWORD>` and `<YOUR_PASSWORD>` are now synced as aliases - providing either via `--abuse-var` fills both

### Improved

- **Query Output Completeness**: Enhanced 27 queries to return actionable information:
  - **Kerberoasting queries** (3): Now show Service Principal Names (SPNs) AND password age for crack likelihood
  - **Constrained Delegation**: Now shows if targets are DC/high-value services with warning
  - **GPOs on DC OU**: Now shows "X of Y" totals instead of truncating controllers
  - **Path queries** (8): Now display full attack paths with node types and relationships instead of just start/end
  - **ADCS queries** (4): Now include Certificate Authority (CA) name for targeting
  - **Count-only queries** (3): Now show sample targets alongside counts
  - **ACL queries** (2): Now show permission type and GPO controllers
  - **ESC6 query**: Now shows usable templates on vulnerable CAs
  - **Circular groups query**: Now shows full cycle path for remediation

- **Path Display Formatting**: Completely redesigned path output to use table format (9 queries updated):
  - Paths now display in proper tables with columns: Hops, Attack Path
  - Full path shown with nodes and relationships inline (no truncation)
  - Maximum 10 paths displayed with "... and X more" summary for additional paths
  - Owned principals marked with `[!]` prefix
  - Example output:
    ```
    +------+---------------------------------------------------------------------------------+
    | Hops | Attack Path                                                                     |
    +------+---------------------------------------------------------------------------------+
    | 3    | [!]J.SMITH -[MemberOf]-> DOMAIN USERS -[MemberOf]-> USERS -[LocalToComputer]-> DC01 |
    | 6    | [!]J.SMITH -[MemberOf]-> DOMAIN USERS -[MemberOf]-> USERS -[LocalToComputer]-> DC01 -[DCFor]-> CORP.LOCAL -[Contains]-> DOMAIN ADMINS |
    +------+---------------------------------------------------------------------------------+
    ```
  - Affected queries: Owned->High Value, Owned->DA, Owned->ADCS, Owned->Unconstrained, Owned->Kerberoastable, Owned->DCSync, Kerberoastable->DA, AS-REP->DA, Domain Users->High Value

- **Abuse Templates Enhanced** with BloodHound.py and OPSEC notes:
  - Kerberoasting: Added bloodhound.py collection, `/nowrap` flag for Rubeus, OPSEC for TGS requests (event 4769)
  - DCSync: Added bloodhound.py DCOnly, OPSEC for replication events (4662)
  - ASREPRoasting: Added bloodhound.py, OPSEC for AS-REP (event 4768)
  - GoldenCert: Added Certipy backup, OPSEC for CA compromise
  - GenericAll: Added shadow credentials, PowerView, OPSEC for modifications
  - GenericWrite: Added PowerView `Set-DomainObject` method, cleanup commands to remove fake SPNs, OPSEC notes
  - ReadLAPSPassword: Updated to use NetExec (nxc) as primary tool, added usage example with retrieved password
  - ADCSESC8: Added `certipy relay` as simpler alternative to ntlmrelayx

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

[Unreleased]: https://github.com/Real-Fruit-Snacks/hackles/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/Real-Fruit-Snacks/hackles/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Real-Fruit-Snacks/hackles/releases/tag/v0.1.0
