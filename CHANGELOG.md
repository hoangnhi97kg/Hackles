# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.5.0] - 2026-01-07

### Added

- **Comprehensive Abuse Command System Expansion**: Extended `--abuse` flag with 4 new template files and 50+ new attack techniques:

  **New Template Files:**
  - `groups.yaml` - Dangerous group membership abuse (DNSAdmins, Backup Operators, Server Operators, Print Operators, Account Operators, GPO Creators, Schema Admins, Enterprise Admins)
  - `coercion.yaml` - Authentication coercion attacks (PrintSpooler/PrinterBug, PetitPotam, DFSCoerce, ShadowCoerce, WebDAV, CoerceToRelay chains)
  - `gpo.yaml` - GPO abuse commands (GPLink, GPO modification, ownership takeover)
  - `azure.yaml` - Azure/Entra ID attacks (AZAddMembers, AZAddOwner, AZAddSecret, AZGlobalAdmin, AZPrivilegedRoleAdmin, AADConnect, AZVMContributor, AZKeyVaultReader, AZResetPassword, AZUserAccessAdministrator, AZOwner)

  **Enhanced Existing Templates:**
  - `acl.yaml` - Added OU/Container targets for GenericAll, GenericWrite, WriteDacl, WriteOwner, AllExtendedRights, Owns; New edge types: AddSelf, WriteSPN, AddKeyCredentialLink, WriteAccountRestrictions
  - `credentials.yaml` - Added PasswdNotReqd, ShadowCredentials, ReadLAPSPassword, ReadGMSAPassword, WriteSPN, GetChanges, GetChangesAll
  - `adcs.yaml` - Added ESC5, ESC13, ESC14, ESC15 (CVE-2024-49019)
  - `lateral.yaml` - Added SQLAdmin edge type with xp_cmdshell exploitation

  **New Edge Type Mappings (41 total):**
  - ACL: AddKeyCredentialLink, WriteSPN, AddSelf, WriteAccountRestrictions
  - Credentials: ReadLAPSPassword, ReadGMSAPassword, DCSync, GetChanges, GetChangesAll
  - Azure: 15 edge types (AZAddMembers, AZGlobalAdmin, SyncedToEntraUser, etc.)
  - Lateral: SQLAdmin
  - GPO: GPLink

  **Queries Now Display Abuse Commands (29 total, up from 9):**
  - Groups: dnsadmins_members, backup_operators_members, server_operators_members, print_operators_members, account_operators_members, gpo_creator_owners
  - Credentials: passwd_notreqd, shadow_credentials, gmsa_readers
  - Hygiene: computers_without_laps, spooler_on_dcs
  - Delegation: unconstrained_delegation, constrained_delegation, constrained_delegation_dangerous, rbcd, rbcd_targets
  - ACL: write_owner, owns_relationships, addself_privileged, write_spn_paths, non_admin_owners

### Fixed

- **Admin Group False Positives in Non-Admin Queries**: Added RID-based exclusions (`-512`, `-519`, `-544`) to 30 queries that previously only checked the `admincount` property. This prevents built-in admin groups (Domain Admins, Enterprise Admins, Administrators) from appearing in "non-admin" findings when their `admincount` field is NULL or false in BloodHound data. Affected queries include:
  - ACL: `acl_abuse`, `generic_all`, `generic_write`, `write_dacl`, `write_owner`, `force_change_password`, `all_extended_rights`, `add_member`, `chained_acl_abuse`, `gpo_control_privileged`, `non_admin_owners`, `add_allowed_to_act`, `schema_config_control`, `write_spn_paths`, `addself_privileged`, `container_acl_abuse`
  - Credentials: `dcsync`, `gmsa_readers`, `shadow_credentials`, `getchangesall_only`
  - ADCS: `manage_ca`, `manage_certificates`, `vulnerable_enrollment`, `adcs_escalation_paths`, `esc3_enrollment_agent`
  - Delegation: `rbcd_targets`
  - Lateral: `local_admin_rights`, `rdp_access`, `dcom_access`, `psremote_access`, `sql_admin`

- **Operator Group False Positives in ACL Queries**: Extended RID-based exclusions to include built-in operator groups (`-548` Account Operators, `-549` Server Operators, `-550` Print Operators, `-551` Backup Operators) in all 14 ACL queries. These groups have elevated privileges by design and were appearing as false positives in "non-admin" ACL findings. Affected queries: `acl_abuse`, `generic_all`, `generic_write`, `write_dacl`, `write_owner`, `force_change_password`, `all_extended_rights`, `add_member`, `chained_acl_abuse`, `gpo_control_privileged`, `non_admin_owners`, `add_allowed_to_act`, `schema_config_control`, `write_spn_paths`, `addself_privileged`

- **Executive Summary DCSync Count**: Fixed DCSync non-admin count in executive summary that incorrectly included legitimate replication groups. Now properly excludes Domain Controllers (-516), RODC (-521), and admin groups by RID

- **NULL Owner Display in Owns Relationships**: Fixed display of "-" for NULL owner names in `owns_relationships.py` and `non_admin_owners.py` by filtering out nodes without valid names

- **NULL Name in High Value Targets**: Fixed GPO objects with empty/NULL names appearing in High Value Targets listing by adding name validation filter

- **Cross-Domain Ownership False Positives**: Added case-insensitive domain comparison (`toLower()`) and empty string filtering to prevent false positives where the same domain appears with different casing (e.g., `DC01.OSCP.EXAM` vs `dc01.oscp.exam`)

- **Plaintext Passwords Empty Results**: Fixed query returning objects with empty `userpassword` attribute. Added Cypher-level filtering (`<> ''`, `trim() <> ''`) and Python post-processing to only show objects with actual password values

- **DCSync Query Consolidation**: Removed duplicate `non_admin_dcsync.py` query that used different logic than `dcsync.py`, causing count discrepancies. Updated `dcsync.py` to use actual DA/EA group membership check instead of unreliable `admincount` property

- **Stale Accounts Percentage Calculation**: Fixed incorrect calculation that showed 50% instead of 7.4%. Was dividing by users who logged in at least once; now correctly divides by total enabled users

- **Table Column Width**: Increased `max_width` from 50 to 65 characters to prevent truncation of long AD group names like "DENIED RODC PASSWORD REPLICATION GROUP@DOMAIN.COM" and "ENTERPRISE READ-ONLY DOMAIN CONTROLLERS@DOMAIN.COM"

- **Unix Timestamp Display**: Added automatic formatting of Unix epoch timestamps to human-readable dates (YYYY-MM-DD) in table output. Timestamps like `1648834256.0` now display as `2022-04-01`. Added `format_timestamp()` and `is_unix_timestamp()` utilities in `hackles/core/utils.py`

- **DCSync Query False Positive for Domain Controllers**: Fixed DCSync non-admin query incorrectly flagging Domain Controller computers as having unexpected DCSync privileges. Added membership check for Domain Controllers group (RID `-516`) in addition to existing RID exclusions. DCs legitimately have DCSync rights via their group membership

- **RBCD Attack Targets False Positives for Operator Groups**: Extended RID exclusions in RBCD query to include privileged operator groups: Account Operators (`-548`), Server Operators (`-549`), and Backup Operators (`-551`). These groups legitimately have GenericAll/GenericWrite on computers by design

- **Case-Sensitive Domain Comparison False Positives**: Fixed `foreign_group_membership.py` and `cross_domain_sessions.py` queries that used case-sensitive domain comparison (`u.domain <> g.domain`). Now uses `toLower()` for case-insensitive comparison matching the pattern in `cross_domain_ownership.py`. Prevents false positives when same domain is stored with different casing

- **LAPS Recommendation Excludes Domain Controllers**: Fixed executive summary LAPS recommendation that incorrectly listed Domain Controllers as needing LAPS. DCs don't use LAPS (they require different protection); now excluded via Domain Controllers group membership check

- **Foreign Group Membership Empty Domain Filter**: Added empty string check (`<> ''`) in addition to NULL check. Prevents entries with empty domain strings from appearing as false positive "foreign" memberships

- **Cross-Domain Sessions Empty Domain Filter**: Same empty string filtering fix applied to cross-domain sessions query

- **Malformed DC Hostname in Executive Summary Commands**: Fixed generated exploitation commands (nxc, secretsdump, GetUserSPNs, etc.) using malformed hostnames like `DC01.DC01.OSCP.EXAM` instead of the correct `DC01.OSCP.EXAM`. Added `_fix_malformed_hostname()` helper that detects and corrects duplicated hostname prefixes (e.g., `SEGMENT.SEGMENT.DOMAIN.COM` -> `SEGMENT.DOMAIN.COM`). Commands in "Recommended Next Steps" now use corrected hostnames that will actually resolve

- **EVERYONE/AUTHENTICATED USERS in Owned Group Memberships**: Filtered implicit system group memberships from "Owned Group Memberships" query results. Every authenticated user is automatically a member of EVERYONE and AUTHENTICATED USERS, making these entries non-actionable noise. Now excludes groups with well-known SIDs (`S-1-1-0`, `S-1-5-11`) and name patterns (`EVERYONE@*`, `AUTHENTICATED USERS@*`)

- **Cross-Domain Ownership Admin Group Exclusion**: Added RID exclusions for built-in admin groups (`-512`, `-519`, `-544`) to prevent false positives. Built-in admin groups like ADMINISTRATORS legitimately own domain objects and should not be flagged as suspicious cross-domain ownership

- **Malformed Computer Names Detection Fix**: Fixed query not detecting duplicated hostname prefixes (e.g., `DC01.DC01.DOMAIN.COM`). Neo4j's regex engine doesn't fully support backreferences (`\1`), so replaced regex approach with Cypher string functions: `split()` to extract first segment, then `STARTS WITH` to check for duplication pattern. This reliably detects malformed FQDNs

- **Foreign Group Membership False Positives**: Added RID exclusions for well-known universal groups (`-513` Domain Users, `-514` Domain Guests, `-515` Domain Computers) and special identity SIDs (`S-1-1-0` EVERYONE, `S-1-5-11` AUTHENTICATED USERS). These groups exist in every domain and their membership is not a security finding

- **Foreign Group Membership EVERYONE/AUTHENTICATED USERS Fix**: Added name-based filters (`g.name STARTS WITH 'EVERYONE@'` and `g.name STARTS WITH 'AUTHENTICATED USERS@'`) in addition to SID filters. BloodHound stores these well-known groups with domain-specific SIDs rather than universal SIDs, so the original SID-based filters weren't matching

- **Dangerous ACL Relationships Operator Group Exclusions**: Extended RID exclusions in `acl_abuse.py` to include all privileged operator groups: Account Operators (`-548`), Server Operators (`-549`), Print Operators (`-550`), and Backup Operators (`-551`). These groups legitimately have GenericAll/GenericWrite permissions on AD objects by design and are protected by AdminSDHolder. This prevents 70+ false positives from appearing in the "Dangerous ACL Relationships" output

- **LAPS Recommendation Count Clarification**: Updated "Low LAPS Coverage" recommendation in Executive Summary to show "N non-DC computers" instead of just "N computers". This clarifies why the recommendation count (excludes Domain Controllers) differs from the Security Posture count (includes all computers). DCs don't need LAPS since their admin password is the DSRM recovery password

### Added

- **Domain Data Quality Warning**: Added startup check that warns users when object `.domain` properties don't match Domain node names. This is common with BloodHound collection issues where objects are stored with `DC01.OSCP.EXAM` instead of `OSCP.EXAM`. The warning explains that domain filtering (`-d`) may not work as expected and suggests running `--hygiene` to check for malformed computer names

- **Malformed Computer Names Detection** (`hackles/queries/hygiene/malformed_computer_names.py`): New data quality query that detects computer names with duplicated hostname prefixes (e.g., `DC01.DC01.DOMAIN.COM` instead of `DC01.DOMAIN.COM`). This indicates AD misconfiguration in the `dNSHostName` attribute. Includes remediation guidance using `Set-ADComputer`

### Changed

- **Abuse Templates**: Now contain 2,135+ lines of exploitation commands across 9 template files
- **Query Registry**: Consolidated to prevent duplicate query names with different results

## [2.4.0] - 2026-01-05

### Added

- **16 New Security Queries** (150 → 166 total):

  **Credential/ACL Queries (5):**
  - `ManageCertificates Rights` - ADCS certificate management abuse (ESC7 variant)
  - `WriteOwner Abuse Paths` - Object takeover via ownership change
  - `GetChangesAll Only` - Partial DCSync detection
  - `Chained ACL Abuse` - Two-hop privilege escalation to high-value targets
  - `AddSelf to Privileged Groups` - Self-add to DA/privileged groups

  **Coercion Relay Separation (4):**
  - `Coercion Relay to LDAP` - LDAP relay for RBCD/shadow credentials
  - `Coercion Relay to LDAPS` - LDAPS relay (bypasses signing)
  - `Coercion Relay to ADCS (ESC8)` - Certificate request via relay
  - `Coercion Relay to SMB` - SMB relay for code execution

  **Azure/Hybrid Expansion (6):**
  - `Sync Account Excessive Privileges` - MSOL/AAD accounts with more than DCSync
  - `Service Accounts with On-Prem Admin` - SPNs with local admin rights
  - `Paths to AAD Connect Servers` - Attack paths from owned to AADC
  - `Privileged Accounts Synced to Azure` - Identify synced privileged accounts
  - `Azure-Related SPNs` - Systems hosting Azure services
  - `Hybrid Identity Attack Surface` - Summary of all hybrid components

  **ACL (1):**
  - `Non-Admin Owners of High-Value Objects` - Ownership-based privilege escalation

## [2.3.0] - 2026-01-04

### Added

- **Executive Summary**: Comprehensive end-of-run summary displayed after all queries complete (table output only):
  - **Domain Profile**: Domain name, DC hostname, functional level, user/computer/group counts, ADCS infrastructure
  - **Data Quality**: Active session count, stale account percentage (configurable threshold)
  - **Trust Analysis**: Domain trust count, external/forest trusts, SID filtering disabled warnings
  - **Azure/Hybrid Identity**: AAD Connect server detection, MSOL/AAD sync accounts, DCSync-capable sync accounts
  - **Security Posture**: LAPS coverage %, Kerberoastable admins, AS-REP roastable users, unconstrained delegation, DCSync non-admin status
  - **GPO Security**: GPOs on DC OU, non-admin GPO control, interesting GPO names
  - **Session Hygiene**: Tier Zero sessions on non-T0 hosts, Domain Admin sessions on workstations
  - **Key Findings**: Severity breakdown (CRITICAL/HIGH/MEDIUM/LOW counts)
  - **Recommended Next Steps**: Prioritized attack commands with real target data:
    - Lists actual target names (DCSync principals, vulnerable templates, Kerberoastable users, etc.)
    - Commands pre-filled with domain name and DC hostname
    - Up to 5 targets shown per category with "+N more" overflow
  - Only shown for table output (suppressed for `--json`, `--csv`, `--html`)
  - Always displays, even in quiet mode (`-q`)
  - Sections are conditional (only display when relevant data exists)
  - Linux-first tooling: Impacket (secretsdump, GetUserSPNs, GetNPUsers), Certipy, nxc

- **BloodHound CE API Endpoints**:
  - `get_asset_groups()` - Retrieve asset groups from BloodHound CE
  - `get_data_quality_stats()` - Retrieve data quality statistics (graceful fallback for older versions)

## [2.2.0] - 2026-01-04

### Added

- **`--abuse` Flag**: Re-implemented abuse command display with simplified, Linux-first approach:
  - Shows context-aware exploitation commands alongside query findings
  - Only displays when `--abuse` flag is passed (explicit opt-in)
  - Target-type aware: Different commands for User vs Group vs Computer vs Domain
  - Linux-first tooling: Impacket, Certipy, bloodyAD, CrackMapExec
  - Static placeholders (`<DC_IP>`, `<TARGET>`, `<USERNAME>`, etc.) - no config files needed
  - OPSEC notes with Event IDs and detection considerations
  - 5 YAML template files covering:
    - ACL abuse (GenericAll, WriteDacl, AddMember, ForceChangePassword, etc.)
    - Credential attacks (Kerberoasting, AS-REP, DCSync, LAPS, gMSA)
    - ADCS attacks (ESC1-ESC11, GoldenCert)
    - Delegation attacks (Unconstrained, Constrained, RBCD)
    - Lateral movement (AdminTo, RDP, WinRM, DCOM)
  - Example: `hackles -p 'pass' --acl --abuse`

## [2.1.1] - 2026-01-04

### Fixed

- **Domain Controller detection**: Fixed DC detection in 8 queries that incorrectly used `objectid ENDS WITH '-516'` on computers. The `-516` RID belongs to the Domain Controllers **group**, not individual computer SIDs. Now correctly uses group membership pattern: `MATCH (c:Computer)-[:MemberOf*1..]->(g:Group) WHERE g.objectid ENDS WITH '-516'`
  - Affected: `domain_stats.py`, `computer_delegation.py`, `unconstrained_krbtgt_paths.py`, `delegation_chains.py`, `main.py` (stats and --unconstrained filter)

- **Print Spooler counting**: Fixed spooler detection counting "Unknown" status as enabled. Changed `if r.get("spooler_enabled")` to `if r.get("spooler_enabled") is True` to only count explicit True values

- **Null node name handling**: Fixed `TypeError: argument of type 'NoneType' is not iterable` crash when path nodes have null names. Now displays "Unknown" instead of crashing

- **Owned marker spacing**: Fixed `[!]` marker touching usernames (was `[!]E.HILLS`, now `[!] E.HILLS`)

- **Null name filtering**: Added `AND g.name IS NOT NULL` filter to Domain Users queries to exclude corrupted nodes with null names from results
  - Affected: `domain_users_to_highvalue.py`, `domain_users_dangerous_acls.py`

### Changed

- **Code cleanup**: Removed unused variables (`perm_findings`, `esc_findings`) and fixed bare `except` clause to catch specific exceptions (`ValueError`, `OSError`, `OverflowError`)

## [2.1.0] - 2026-01-04

### Removed

- **Abuse Commands Functionality**: Removed all `--abuse` command functionality and attack templates:
  - Removed `--abuse` CLI flag for displaying attack commands
  - Removed `--abuse-var` and `--abuse-config` CLI arguments
  - Removed `hackles/abuse/` directory with 58 YAML attack templates
  - Removed abuse command display from `--investigate` output
  - Removed `~/.hackles/abuse.conf` auto-loading
  - Vulnerability findings now include clear impact descriptions in warnings instead of executable commands

### Changed

- Query output now focuses on vulnerability impact descriptions explaining what each misconfiguration allows (e.g., "Can request certificates as ANY domain user including Domain Admins") rather than providing attack commands

## [2.0.0] - 2026-01-03

### Added

- **`--ingest-history` Command**: View file upload/ingest history from BloodHound CE API:
  - Lists all file upload jobs with status, timestamps, and messages
  - Supports `--json` and `--csv` output formats
  - Color-coded status display (green=complete, red=failed, blue=running)
  - Example: `hackles --ingest-history`, `hackles --ingest-history --json`

- **BloodHound CE API Integration**: New API client for BloodHound CE operations (no Neo4j password required):
  - `--auth` - Authenticate to BloodHound CE and store API token in `~/.config/hackles/hackles.ini`
  - `--api-url URL` - Custom BloodHound CE URL (default: `http://localhost:8080`)
  - `--api-config FILE` - Custom config file location
  - Uses HMAC-SHA256 authentication per BloodHound CE API spec

- **BloodHound CE API: Data Ingestion**: New `--ingest` command to upload collector data directly via API:
  - Supports JSON and ZIP files from SharpHound/BloodHound.py collectors
  - Glob pattern support: `--ingest *.zip`, `--ingest /path/to/*.json`
  - Multiple files in single upload job
  - Progress feedback and ingestion status polling
  - Example: `hackles --ingest bloodhound_data.zip computers.json`

- **BloodHound CE API: Database Clearing**: New `--clear-database` command to delete data from BloodHound CE via the API:
  - `--delete-all` - Delete all graph data + history
  - `--delete-ad` - Delete Active Directory graph data only
  - `--delete-azure` - Delete Azure/Entra ID graph data only
  - `--delete-sourceless` - Delete sourceless graph data only
  - `--delete-ingest-history` - Delete file ingest history
  - `--delete-quality-history` - Delete data quality history
  - `-y, --yes` - Skip confirmation prompt for scripting
  - Safety features: Requires typing "DELETE" to confirm, fails in non-interactive mode without `--yes`
  - Example: `hackles --clear-database --delete-all --yes`

- **`--audit` Consolidated Security Audit**: New command for quick security hygiene assessment:
  - Kerberoastable admin accounts (HIGH)
  - AS-REP roastable users (HIGH)
  - Unconstrained delegation on non-DC systems (HIGH)
  - Unsupported operating systems (MEDIUM)
  - Computers without LAPS (MEDIUM)
  - Enabled guest accounts (HIGH)
  - Admin accounts with password never expires (MEDIUM)
  - Users with path to Domain Admins (HIGH)
  - Supports `--json`, `--csv`, `--html` output formats
  - Example: `hackles -p 'pass' --audit --json`

- **Enhanced `--stats` with ADCS and Infrastructure Counts**:
  - Enterprise CAs count
  - Certificate Templates count
  - Domain Controllers count
  - Protected Users count
  - New "ADCS" and "Infrastructure" sections in table output
  - Added to JSON/CSV output formats

### Fixed

- **BloodHound CE API file upload status tracking**: Fixed incorrect API endpoint for checking upload job status. Was using `GET /api/v2/file-upload/{id}` (405 error), now correctly uses `GET /api/v2/file-upload?id=eq:{id}`
- **Missing type imports**: Added missing `Dict` and `Any` imports to `bloodhound.py` that caused `NameError` on startup
- **Improved API error messages**: `BloodHoundAPIError` now includes HTTP status code in error messages (e.g., "Failed to get job status (HTTP 404)")
- **CLI validation for `--delete-*` flags**: Using `--delete-all`, `--delete-ad`, etc. without `--clear-database` now shows a helpful error instead of confusing "Neo4j password required" message

## [0.3.0] - 2025-12-30

### Added

- **Full JSON/CSV/HTML output format support for all CLI commands**: Previously only `-a` (run all queries) supported output formats. Now 21 additional commands support `--json`, `--csv`, and `--html` output:
  - **Bulk lists**: `--computers`, `--users`, `--spns`
  - **Quick filters**: `--kerberoastable`, `--asrep`, `--unconstrained`, `--no-laps`
  - **Node operations**: `--list`, `--info`, `--search`
  - **Path commands**: `--path`, `--path-to-da`, `--path-to-dc`
  - **Membership**: `--members`, `--memberof`
  - **Admin rights**: `--adminto`, `--adminof`, `--sessions`
  - **Edge exploration**: `--edges-from`, `--edges-to`
  - **Summaries**: `--quick-wins`, `--tier-zero`
  - Example: `hackles --computers --json` returns `[{"name": "DC01.CORP.LOCAL", "os": "Windows Server 2022", ...}]`

- **Simple HTML reports for single commands**: New `generate_simple_html()` function creates clean single-table HTML reports with search and CSV export functionality

- **JSON/CSV output for `--stats` command**: The `--stats` flag now properly outputs structured data when combined with `--json` or `--csv`:
  - JSON output includes nested objects for users, computers, groups, and risk metrics
  - CSV output uses category/metric/value format for easy parsing
  - Example: `hackles --stats --json` returns `{"domain": "CORP.LOCAL", "users": {...}, "risk": {"score": 40, ...}}`

- **Comprehensive test suite**: 157 automated tests covering all CLI flags and output formats with full output logging

- **`--investigate` command**: Comprehensive one-command investigation of any node (user/computer/group):
  - Auto-detects node type and shows relevant information
  - **User investigation**: Properties, group memberships, outbound/inbound attack edges, admin rights, active sessions, path to DA
  - **Computer investigation**: Properties, active sessions, local admins, group memberships, attack edges
  - **Group investigation**: Properties, members (with Admin column), parent groups, inbound control edges
  - Supports wildcards for triage: `--investigate '*.DOMAIN.COM'` shows summary table sorted by attack relevance
  - Critical attack edges (GenericAll, WriteDacl, etc.) highlighted in red

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

### Fixed

- **Cypher double-WHERE syntax errors**: Fixed 3 query files that caused "Invalid input 'WHERE'" errors when using domain filter (`-d`):
  - `esc6_san_flag.py` - ESC6 ADCS query
  - `unresolved_sids.py` - Unresolved SIDs ACL query
  - `logon_scripts_foreign.py` - Logon scripts in trusted domains query
  - Root cause: `domain_filter = "WHERE ..."` placed after existing WHERE clause; changed to `"AND ..."`

- **JSON output pollution**: Fixed "Risk Score" line appearing before JSON array when using `--json` flag with queries
  - Added output format check in `domain_stats.py` to suppress non-JSON text

- **Empty output for `--stats --json` and `--stats --csv`**: The `--stats` command now properly outputs data in JSON/CSV format instead of empty output
  - Previously bypassed the JSON/CSV output handling entirely

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
  - `--stale-days N`: Customize stale account threshold (default: 90 days) - affects stale accounts and computer stale password queries
  - `--max-path-depth N`: Maximum hops in path queries (default: 5) - affects 15 path-finding queries
  - `--max-paths N`: Maximum paths to return from queries (default: 25) - affects 15 path-finding queries

- Comprehensive test suite for config singleton and utils module (77 tests total)

### Fixed

- README examples now include correct `-u neo4j` flag and default password
- Test files use correct function names from abuse loader module
- **Domain Functional Level query**: Fixed type comparison error when BloodHound returns level as string (e.g., "2016") instead of integer
- **RODC Allowed Replication query**: Fixed Cypher syntax error with ORDER BY after RETURN DISTINCT
- **Delegation Chains query**: Fixed Cypher syntax error - ORDER BY now uses aliased column names after RETURN DISTINCT

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

[Unreleased]: https://github.com/Real-Fruit-Snacks/hackles/compare/v2.5.0...HEAD
[2.5.0]: https://github.com/Real-Fruit-Snacks/hackles/compare/v2.3.0...v2.5.0
[2.3.0]: https://github.com/Real-Fruit-Snacks/hackles/compare/v2.2.0...v2.3.0
[2.2.0]: https://github.com/Real-Fruit-Snacks/hackles/compare/v2.1.1...v2.2.0
[2.1.1]: https://github.com/Real-Fruit-Snacks/hackles/compare/v2.1.0...v2.1.1
[2.1.0]: https://github.com/Real-Fruit-Snacks/hackles/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/Real-Fruit-Snacks/hackles/compare/v0.3.0...v2.0.0
[0.3.0]: https://github.com/Real-Fruit-Snacks/hackles/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/Real-Fruit-Snacks/hackles/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Real-Fruit-Snacks/hackles/releases/tag/v0.1.0
