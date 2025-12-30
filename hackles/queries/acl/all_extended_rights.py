"""AllExtendedRights ACL Abuse"""
from __future__ import annotations

from typing import Optional, TYPE_CHECKING

from hackles.queries.base import register_query
from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.abuse.printer import print_abuse_info
from hackles.core.cypher import node_type
from hackles.core.utils import extract_domain

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="AllExtendedRights ACL Abuse",
    category="ACL Abuse",
    default=True,
    severity=Severity.CRITICAL
)
def get_all_extended_rights(bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None) -> int:
    """Find non-admin principals with AllExtendedRights over other objects.

    AllExtendedRights grants all extended rights including:
    - User-Force-Change-Password (reset passwords without knowing current)
    - DS-Replication-Get-Changes / DS-Replication-Get-Changes-All (DCSync)
    - Certificate enrollment rights
    - LAPS password read rights
    """
    domain_filter = "AND toUpper(m.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (n)-[:AllExtendedRights]->(m)
    WHERE (n.admincount IS NULL OR n.admincount = false)
    AND n.enabled <> false
    AND NOT n.name STARTS WITH 'SYSTEM@'
    AND NOT n.name STARTS WITH 'LOCAL SERVICE@'
    AND NOT n.name STARTS WITH 'NETWORK SERVICE@'
    {domain_filter}
    RETURN
        n.name AS principal,
        {node_type('n')} AS principal_type,
        m.name AS target,
        {node_type('m')} AS target_type,
        CASE WHEN m.enabled = false THEN 'Disabled' ELSE 'Enabled' END AS target_status,
        CASE WHEN m.admincount = true THEN 'Yes' ELSE 'No' END AS target_is_admin,
        CASE WHEN 'admin_tier_0' IN m.system_tags OR m:Tag_Tier_Zero THEN 'T0' ELSE '' END AS tier_zero
    ORDER BY m.admincount DESC, tier_zero DESC, n.name
    LIMIT 200
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("AllExtendedRights ACL Abuse", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} AllExtendedRights relationship(s) from non-admin principals (limit 200)")

    if results:
        # Count high-value targets
        admin_targets = sum(1 for r in results if r.get("target_is_admin") == "Yes")
        t0_targets = sum(1 for r in results if r.get("tier_zero") == "T0")

        if admin_targets > 0:
            print_warning(f"[!] {admin_targets} target(s) are admin accounts!")
        if t0_targets > 0:
            print_warning(f"[!] {t0_targets} target(s) are Tier Zero assets!")

        print_warning("")
        print_warning("    AllExtendedRights includes: Password reset, DCSync, LAPS read, Cert enrollment")

        print_table(
            ["Principal", "Type", "Target", "Target Type", "Status", "Admin", "T0"],
            [[r["principal"], r["principal_type"], r["target"], r["target_type"],
              r.get("target_status", "Unknown"), r.get("target_is_admin", "No"),
              r.get("tier_zero", "")] for r in results]
        )
        print_abuse_info("AllExtendedRights", results, extract_domain(results, domain))

    return result_count
