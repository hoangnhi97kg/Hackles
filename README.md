# Hackles

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Neo4j 5.0+](https://img.shields.io/badge/neo4j-5.0+-green.svg)](https://neo4j.com/)

> **Extract quick wins from BloodHound Community Edition**

A fast CLI tool for identifying Active Directory attack paths, misconfigurations, and privilege escalation opportunities. **150 security queries** across 13 categories with **58 ready-to-use attack templates**.

```bash
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' -a                    # Run all 150 queries
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' --adcs --privesc      # ADCS + privilege escalation
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' -a --html report.html # Generate HTML report
```

---

## Features

| Feature | Description |
|---------|-------------|
| **152 Security Queries** | Privilege escalation, ACL abuse, ADCS (ESC1-ESC15), delegation, coercion, lateral movement |
| **58 Abuse Templates** | Copy-paste attack commands with OPSEC notes and BloodHound.py integration |
| **Quick Wins Summary** | `--quick-wins` shows 1-2 hop paths to DA, Kerberoastable admins, AS-REP targets, ACL abuse |
| **Quick Enumeration** | `--computers`, `--users`, `--spns` for rapid domain enumeration |
| **Node Investigation** | `--investigate USER` shows properties, attack edges, group memberships, paths to DA in one command |
| **Wildcard Support** | Use `*` patterns in node operations: `--investigate '*.DOMAIN.COM'`, `--sessions '*.DOMAIN.COM'` |
| **Multiple Outputs** | Table, JSON, CSV, HTML reports |
| **Severity Filtering** | Focus on CRITICAL/HIGH findings only |
| **Owned Tracking** | Highlights compromised accounts with `[!]` markers |
| **Path Finding** | Shortest paths to Domain Admin, Domain Controllers |
| **Configurable Thresholds** | Customize stale days, path depth, result limits |
| **Abuse Template Variables** | Pre-fill DC_IP, YOUR_PASSWORD, and other placeholders |
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

# Run all queries with abuse commands shown
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' -a --abuse

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
| ACL Abuse | 22 | `--acl` | GenericAll, WriteDacl, WriteOwner, ForceChangePassword, AddMember, AllExtendedRights |
| Credentials | 18 | `--privesc` | Kerberoasting, DCSync, shadow creds, service account security |
| Security Hygiene | 19 | `--hygiene` | LAPS, SMB signing, AdminSDHolder, stale passwords |
| ADCS | 17 | `--adcs` | ESC1-ESC15, golden certs, ManageCA, enrollment agents |
| Lateral Movement | 14 | `--lateral` | RDP, DCOM, PSRemote, SQL, sessions |
| Domain Analysis | 14 | `--basic` | Trusts, functional level, single DC |
| Owned Principals | 11 | `--owned-queries` | Paths from compromised accounts |
| Dangerous Groups | 10 | `--groups` | DNSAdmins, Backup Ops, RODC replication |
| Delegation | 11 | `--delegation` | Constrained, unconstrained, RBCD, delegation chains, S4U2Self attacks |
| Attack Paths | 6 | `--attack-paths` | Shortest paths, attack chains |
| Azure/Hybrid | 3 | `--azure` | AAD Connect, hybrid DCSync |
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

# Show abuse commands for each finding
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' -a --abuse

# Filter by domain
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' -a -d CORP.LOCAL

# Debug mode (show Cypher queries and timing)
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' -a --debug
```

### Output Formats

```bash
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' -a --json > results.json
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' -a --csv > results.csv
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' -a --html report.html
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' -a --no-color | tee output.txt
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' -a --progress  # Show progress bar
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
```

### Node Operations

All node operations support `*` wildcards for pattern matching.

```bash
# Comprehensive investigation (auto-detects user/computer/group)
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' --investigate 'USER@CORP.LOCAL'
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' --investigate 'USER@CORP.LOCAL' --abuse  # With attack commands
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

# Pre-fill abuse template placeholders
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' -a --abuse --abuse-var DC_IP=192.168.1.10
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' -a --abuse --abuse-var DC_IP=192.168.1.10 --abuse-var YOUR_PASSWORD='Summer2024!'

# Load abuse variables from config file
python -m hackles -u neo4j -p 'bloodhoundcommunityedition' -a --abuse --abuse-config ~/pentest/vars.conf
```

<details>
<summary><b>Abuse Config File Format</b></summary>

Create `~/.hackles/abuse.conf` (auto-loaded) or specify with `--abuse-config`:

```bash
# Abuse template variables
DC_IP=192.168.1.10
ATTACKER_IP=10.10.14.5
YOUR_PASSWORD=Summer2024!
YOUR_USER=jsmith
```

CLI `--abuse-var` arguments override config file values.

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

[*] Findings Summary
    CRITICAL: 1 | HIGH: 2 | MEDIUM: 5 | LOW: 3

[+] Analysis completed in 1.23s (150 queries)
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

## License

MIT License - see [LICENSE](LICENSE) for details.

---

## Disclaimer

This tool is intended for authorized security assessments only. Always obtain proper authorization before use. The authors are not responsible for misuse or damage caused by this tool.
