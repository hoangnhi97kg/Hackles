# Hackles

[![Version](https://img.shields.io/badge/version-2.4.0-blue.svg)](https://github.com/Real-Fruit-Snacks/hackles/releases/tag/v2.4.0)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Neo4j 5.0+](https://img.shields.io/badge/neo4j-5.0+-green.svg)](https://neo4j.com/)
[![GitHub stars](https://img.shields.io/github/stars/Real-Fruit-Snacks/hackles)](https://github.com/Real-Fruit-Snacks/hackles/stargazers)

> **Extract quick wins from BloodHound Community Edition**

A fast CLI tool for identifying Active Directory attack paths, misconfigurations, and privilege escalation opportunities. **166 security queries** across 13 categories with clear vulnerability impact descriptions.

```bash
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' -a                    # Run all 166 queries
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' --adcs --privesc      # ADCS + privilege escalation
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' -a --html report.html # Generate HTML report
```

---

## Features

| Feature | Description |
|---------|-------------|
| **166 Security Queries** | Privilege escalation, ACL abuse, ADCS (ESC1-ESC15), delegation, coercion, lateral movement, Azure/Hybrid |
| **Quick Wins Summary** | `--quick-wins` shows 1-2 hop paths to DA, Kerberoastable admins, AS-REP targets, ACL abuse |
| **Security Audit** | `--audit` consolidated hygiene report: Kerberoastable admins, AS-REP, unconstrained delegation, unsupported OS, LAPS, guest accounts |
| **Quick Enumeration** | `--computers`, `--users`, `--spns` for rapid domain enumeration |
| **Node Investigation** | `--investigate USER` shows properties, attack edges, group memberships, paths to DA in one command |
| **Wildcard Support** | Use `*` patterns in node operations: `--investigate '*.DOMAIN.COM'`, `--sessions '*.DOMAIN.COM'` |
| **Multiple Outputs** | Table, JSON, CSV, HTML reports |
| **Severity Filtering** | Focus on CRITICAL/HIGH findings only |
| **Owned Tracking** | Highlights compromised accounts with `[!]` markers |
| **Abuse Commands** | `--abuse` shows exploitation commands (Impacket, Certipy, bloodyAD) with OPSEC notes |
| **Executive Summary** | Automatic end-of-run summary with domain profile, security posture, and prioritized next steps |
| **Path Finding** | Shortest paths to Domain Admin, Domain Controllers |
| **Configurable Thresholds** | Customize stale days, path depth, result limits |
| **BloodHound CE API** | Ingest data files, view ingest history, and clear database without Neo4j access |
| **Shell Completion** | Tab completion for bash/zsh/fish |

---

## Quick Start

### Requirements

- Python 3.8+
- BloodHound Community Edition with ingested data
- Network access to Neo4j (default: `bolt://127.0.0.1:7687`)

### Installation

```bash
git clone https://github.com/Real-Fruit-Snacks/hackles.git
cd hackles

# Create and activate virtual environment (recommended, required on some systems)
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# venv\Scripts\activate   # Windows

pip install -r requirements.txt
```

### First Run

```bash
# List available domains
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' -l

# Run all queries
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' -a

# Generate HTML report
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' -a --html report.html
```

<details>
<summary><b>Shell Completion Setup</b></summary>

```bash
# Bash
eval "$(register-python-argcomplete hackles)"

# Zsh
autoload -U bashcompinit && bashcompinit
eval "$(register-python-argcomplete hackles)"

# Fish
register-python-argcomplete --shell fish hackles | source
```

</details>

---

## Query Categories

| Category | Queries | Flag | Focus |
|----------|:-------:|------|-------|
| ACL Abuse | 26 | `--acl` | GenericAll, WriteDacl, WriteOwner, ForceChangePassword, AddMember, chained abuse |
| Credentials | 19 | `--privesc` | Kerberoasting, DCSync, shadow creds, service account security |
| Security Hygiene | 19 | `--hygiene` | LAPS, SMB signing, AdminSDHolder, stale passwords |
| ADCS | 18 | `--adcs` | ESC1-ESC15, golden certs, ManageCA, ManageCertificates |
| Lateral Movement | 19 | `--lateral` | RDP, DCOM, PSRemote, SQL, coercion relay (LDAP/LDAPS/ADCS/SMB) |
| Domain Analysis | 14 | `--basic` | Trusts, functional level, single DC |
| Owned Principals | 11 | `--owned-queries` | Paths from compromised accounts |
| Dangerous Groups | 10 | `--groups` | DNSAdmins, Backup Ops, RODC replication |
| Delegation | 12 | `--delegation` | Constrained, unconstrained, RBCD, delegation chains, S4U2Self |
| Azure/Hybrid | 9 | `--azure` | AAD Connect, sync accounts, hybrid attack surface |
| Attack Paths | 6 | `--attack-paths` | Shortest paths, attack chains |
| Miscellaneous | 3 | `--misc` | Circular groups, duplicate SPNs |
| Exchange | 2 | `--exchange` | Exchange domain rights |

**Run multiple categories:** `python -m hackles -u neo4j -p 'bloodhoundcommunityedition' --adcs --acl --privesc`

---

## Usage

### Running Queries

```bash
# All queries
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' -a

# Specific categories
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' --privesc --adcs

# Filter by severity
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' -a --severity CRITICAL,HIGH

# Quiet mode (hide banner + zero-result queries)
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' -a -q

# Filter by domain
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' -a -d CORP.LOCAL

# Debug mode (show Cypher queries and timing)
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' -a --debug
```

### Output Formats

All commands support `--json`, `--csv`, and `--html` output formats for scripting and automation.

```bash
# Query output
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' -a --json > results.json
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' -a --csv > results.csv
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' -a --html report.html

# Quick filters with structured output
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' --computers --json    # All computers as JSON
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' --users --csv         # All users as CSV
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' --kerberoastable --json

# Node operations with structured output
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' --members 'DOMAIN ADMINS@CORP.LOCAL' --json
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' --path-to-da 'USER@CORP.LOCAL' --csv
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' --search '*ADMIN*' --html admins.html

# Other options
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' --stats --json        # Stats as JSON
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' -a --no-color | tee output.txt
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' -a --progress         # Show progress bar
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' --acl --abuse         # Show exploitation commands
```

### Quick Filters

```bash
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' --kerberoastable  # Kerberoastable users
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' --asrep           # AS-REP roastable
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' --unconstrained   # Unconstrained delegation
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' --no-laps         # Computers without LAPS
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' --computers       # All domain computers
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' --users           # All domain users
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' --spns            # All SPNs for targeting
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' --quick-wins      # Quick wins summary
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' --audit           # Security audit report
```

### Node Operations

All node operations support `*` wildcards for pattern matching.

```bash
# Comprehensive investigation (auto-detects user/computer/group)
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' --investigate 'USER@CORP.LOCAL'
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' --investigate 'DC01.CORP.LOCAL'
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' --investigate '*.CORP.LOCAL'  # Triage view

# Search and explore
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' --search '*ADMIN*'
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' --info 'USER@CORP.LOCAL'
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' --info '*.CORP.LOCAL'  # Wildcard

# Path finding
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' --path 'USER@CORP.LOCAL' 'DC01.CORP.LOCAL'
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' --path-to-da 'USER@CORP.LOCAL'
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' --path-to-dc 'USER@CORP.LOCAL'

# Group membership (includes Admin column, sorted by admin status)
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' --members 'DOMAIN ADMINS@CORP.LOCAL'
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' --members 'DOMAIN *'   # Wildcard
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' --memberof 'USER@CORP.LOCAL'
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' --memberof 'SVC_*'     # Wildcard

# Admin rights and sessions
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' --adminto 'DC01.CORP.LOCAL'
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' --adminto '*.CORP.LOCAL'   # Wildcard
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' --adminof 'USER@CORP.LOCAL'
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' --sessions 'SERVER01.CORP.LOCAL'
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' --sessions '*.CORP.LOCAL'  # Wildcard

# Edge exploration
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' --edges-from 'USER@CORP.LOCAL'
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' --edges-from '*.CORP.LOCAL'        # Wildcard
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' --edges-to 'DOMAIN ADMINS@CORP.LOCAL'
```

### Owned & Tier Zero Management

```bash
# Mark principals as owned (persists in Neo4j)
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' -o 'USER@CORP.LOCAL'
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' -o 'USER1@CORP.LOCAL' -o 'USER2@CORP.LOCAL' -a

# Remove owned status
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' --unown 'USER@CORP.LOCAL'
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' --clear-owned

# Tier Zero management
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' --tier-zero 'SVC_BACKUP@CORP.LOCAL'
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' --untier-zero 'SVC_OLD@CORP.LOCAL'

# Focus owned queries on specific principal (useful with multiple owned accounts)
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' --owned-queries --from-owned 'USER1@CORP.LOCAL'
```

### Advanced Configuration

```bash
# Customize path query limits
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' --attack-paths --max-path-depth 10 --max-paths 50

# Customize stale account threshold (default: 90 days)
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' --hygiene --stale-days 30
```

### BloodHound CE API Operations

Hackles can interact directly with the BloodHound CE API for data ingestion and management (no Neo4j password required).

```bash
# Authenticate and store API token (interactive prompts for token ID/key)
python -m hackles --auth
python -m hackles --auth --api-url http://bloodhound.local:8080  # Custom URL

# Ingest data files
python -m hackles --ingest *.zip
python -m hackles --ingest bloodhound_data.json computers.json users.json

# View file ingest history
python -m hackles --ingest-history                    # Table output
python -m hackles --ingest-history --json             # JSON output

# Clear database (requires confirmation)
python -m hackles --clear-database --delete-all              # Delete everything
python -m hackles --clear-database --delete-all --yes        # Skip confirmation
python -m hackles --clear-database --delete-ad               # Delete AD data only
python -m hackles --clear-database --delete-azure            # Delete Azure data only
python -m hackles --clear-database --delete-ad --delete-azure
python -m hackles --clear-database --delete-ingest-history   # Clear ingest history
python -m hackles --clear-database --delete-quality-history  # Clear quality history
```

<details>
<summary><b>API Token Setup</b></summary>

1. Log into BloodHound CE web interface
2. Go to **Administration > API Tokens > Create Token**
3. Copy the Token ID and Token Key
4. Run `python -m hackles --auth` and paste when prompted
5. Credentials are stored in `~/.config/hackles/hackles.ini`

</details>

### Custom Queries

```bash
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' -c my_query.cypher
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' -c ./custom_queries/
```

Query format with optional severity:
```cypher
# Find all service accounts with SPNs
# severity: HIGH
MATCH (u:User) WHERE u.hasspn = true AND u.enabled = true
RETURN u.name AS username, u.displayname AS displayname
```

---

## ADCS Coverage

Comprehensive ESC1-ESC15 vulnerability detection:

| ESC | Severity | Description |
|:---:|:--------:|-------------|
| ESC1 | CRITICAL | Vulnerable certificate templates (enrollee supplies SAN) |
| ESC2 | HIGH | Any Purpose / Certificate Agent templates |
| ESC3 | HIGH | Enrollment agent abuse |
| ESC4 | HIGH | Template ACL abuse (modify template) |
| ESC5 | HIGH | PKI object control |
| ESC6 | CRITICAL | EDITF_ATTRIBUTESUBJECTALTNAME2 flag |
| ESC7 | HIGH | ManageCA rights |
| ESC8 | HIGH | NTLM relay to web enrollment |
| ESC9 | HIGH | No security extension |
| ESC10 | HIGH | Weak certificate mapping |
| ESC11 | HIGH | SAN enabled on CA |
| ESC13 | HIGH | Issuance policy abuse |
| ESC15 | HIGH | CVE-2024-49019 |

Plus: Golden Certificate paths, enrollment abuse detection.

---

## Severity Levels

| Level | Color | Meaning |
|-------|-------|---------|
| `CRITICAL` | Bold Red | Immediate exploitation path |
| `HIGH` | Red | Serious security risk |
| `MEDIUM` | Orange | Concerning misconfiguration |
| `LOW` | Yellow | Informational / hardening opportunity |
| `INFO` | Gray | Statistics and metadata |

---

## Sample Output

```
[*] Connecting to bolt://127.0.0.1:7687...
[+] Connected successfully
[*] Found 3 owned principal(s)

[*] [CRITICAL] DCSync Privileges (Non-Admin)
    Found 1 non-admin principal(s) with DCSync rights
+---------------------------+-------+-------------+
| Principal                 | Type  | Domain      |
+---------------------------+-------+-------------+
| YOURUSER@CORP.LOCAL       | User  | CORP.LOCAL  |
+---------------------------+-------+-------------+

[*] [HIGH] Kerberoastable Users (SPN Set)
    Found 2 Kerberoastable user(s)
    [!] 1 have passwords older than 6 months (easier to crack)
+-------------------------------+--------------+---------+-------+----------+
| Name                          | Display Name | Enabled | Admin | Pwd Age  |
+-------------------------------+--------------+---------+-------+----------+
| [!] R.HAGGARD@CORP.LOCAL      | R. Haggard   | True    | No    | >1 year  |
| SVC_SQL@CORP.LOCAL            | SQL Service  | True    | No    | >3 months|
+-------------------------------+--------------+---------+-------+----------+

    [ABUSE COMMANDS]  # Shown with --abuse flag
    ==================================================
    Target: R.HAGGARD@CORP.LOCAL (+1 more)
    --------------------------------------------------
    [1] Kerberoast (Impacket)
        GetUserSPNs.py -request -dc-ip <DC_IP> '<DOMAIN>/<USERNAME>:<PASSWORD>'

    OPSEC:
      - Creates Event ID 4769 with encryption type 0x17

[*] Executive Summary
    ══════════════════════════════════════════════════

    DOMAIN PROFILE
    ──────────────────────────────────────────────────
    Domain:              CORP.LOCAL
    Domain Controller:   DC01.CORP.LOCAL
    Functional Level:    2016
    Users:               145 enabled (162 total)
    Computers:           28 enabled
    Groups:              89
    ADCS:                1 CA(s), 12 templates

    DATA QUALITY
    ──────────────────────────────────────────────────
    [*] Active Sessions:      47
    [+] Stale Accounts:       12% (18 users >90d)

    TRUST ANALYSIS
    ──────────────────────────────────────────────────
    [*] Domain Trusts:        2 total (1 external, 0 forest)
    [!] SID Filter Disabled:  1 trust(s) - ESCALATION RISK
        → CORP.LOCAL <-> PARTNER.COM

    SECURITY POSTURE
    ──────────────────────────────────────────────────
    [!] LAPS Coverage:            32% (9/28 computers)
    [!] Kerberoastable Admins:    2 accounts
    [!] AS-REP Roastable:         3 accounts
    [!] Unconstrained Delegation: 1 non-DC system
    [+] DCSync Non-Admin:         None detected

    GPO SECURITY
    ──────────────────────────────────────────────────
    [!] GPOs on DC OU:            4 (high-value targets)
    [!] Non-Admin GPO Control:    2 GPO(s) by 1 principal(s)

    SESSION HYGIENE
    ──────────────────────────────────────────────────
    [!] DA on Workstations:       2 admin(s) on 3 computer(s)
    [!] Total Exposure:           5 privileged session(s) at risk

    KEY FINDINGS
    ──────────────────────────────────────────────────
    CRITICAL: 1 | HIGH: 2 | MEDIUM: 5 | LOW: 3

[*] Recommended Next Steps
    ══════════════════════════════════════════════════

    [HIGH] Kerberoastable Admin Accounts
    $ GetUserSPNs.py -request -dc-ip DC01.CORP.LOCAL 'CORP/<USER>:<PASS>'
      → SVC_SQL@CORP.LOCAL
      → SVC_BACKUP@CORP.LOCAL

    [HIGH] AS-REP Roastable Users
    $ GetNPUsers.py -dc-ip DC01.CORP.LOCAL 'CORP/' -usersfile users.txt
      → J.SMITH@CORP.LOCAL
      → GUEST@CORP.LOCAL
      → TESTUSER@CORP.LOCAL

[*] Findings Summary
    CRITICAL: 1 | HIGH: 2 | MEDIUM: 5 | LOW: 3

[+] Analysis completed in 1.23s (152 queries)
```

Owned principals are marked with `[!]` (yellow for standard, red for admin).

---

## Troubleshooting

<details>
<summary><b>Authentication Failed</b></summary>

```
[!] Connection failed: The client is unauthorized
```

BloodHound CE web credentials differ from Neo4j. Find Neo4j password:
```bash
cat ~/.config/bloodhound/docker-compose.yml | grep NEO4J_AUTH
# Default: neo4j / bloodhoundcommunityedition
```

</details>

<details>
<summary><b>Connection Issues</b></summary>

```bash
# Check Neo4j is running
nc -zv 127.0.0.1 7687
docker ps | grep neo4j

# Try explicit connection
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' -b 'bolt://127.0.0.1:7687' -l
```

</details>

<details>
<summary><b>No Results</b></summary>

1. Verify data is ingested in BloodHound GUI
2. Check domain filter matches exactly: `python -m hackles -u neo4j -p 'bloodhoundcommunityedition' -l`
3. Mark principals as "owned" in BloodHound UI for owned queries to work

</details>

---

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Run tests: `pytest tests/`
4. Commit changes (`git commit -m 'Add amazing feature'`)
5. Push to branch (`git push origin feature/amazing-feature`)
6. Open a Pull Request

### Development Setup

```bash
# Activate virtual environment first (see Installation)
source venv/bin/activate

pip install -r requirements-dev.txt
pytest tests/ --cov=hackles
```

---

## References

- [bloodhound-quickwin](https://github.com/kaluche/bloodhound-quickwin) - The original quick wins tool that inspired this project
- [BloodHound CE Documentation](https://bloodhound.specterops.io/)
- [ADCS Attack Paths - Part 1](https://posts.specterops.io/adcs-attack-paths-in-bloodhound-part-1-799f3d3b03cf)
- [ADCS Attack Paths - Part 2](https://specterops.io/blog/2024/05/01/adcs-attack-paths-in-bloodhound-part-2/)
- [Certified Pre-Owned](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)

---

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history and release notes.

---

## License

MIT License - see [LICENSE](LICENSE) for details.

---

## Disclaimer

This tool is intended for authorized security assessments only. Always obtain proper authorization before use. The authors are not responsible for misuse or damage caused by this tool.
