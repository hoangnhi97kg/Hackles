"""WriteSPN Permissions"""

from __future__ import annotations

from typing import TYPE_CHECKING

from hackles.abuse import print_abuse_section
from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="WriteSPN Permissions", category="ACL Abuse", default=True, severity=Severity.HIGH
)
def get_write_spn_paths(
    bh: BloodHoundCE, domain: str | None = None, severity: Severity = None
) -> int:
    """Find principals with WriteSPN permissions (can Kerberoast any target)"""
    domain_filter = "AND toUpper(target.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (n)-[:WriteSPN]->(target:User)
    WHERE (n.admincount IS NULL OR n.admincount = false)
    AND NOT n.objectid ENDS WITH '-512'  // Domain Admins
    AND NOT n.objectid ENDS WITH '-519'  // Enterprise Admins
    AND NOT n.objectid ENDS WITH '-544'  // Administrators
    AND NOT n.objectid ENDS WITH '-548'  // Account Operators
    AND NOT n.objectid ENDS WITH '-549'  // Server Operators
    AND NOT n.objectid ENDS WITH '-550'  // Print Operators
    AND NOT n.objectid ENDS WITH '-551'  // Backup Operators
    AND target.enabled = true
    {domain_filter}
    RETURN
        n.name AS principal,
        CASE WHEN n:User THEN 'User' WHEN n:Computer THEN 'Computer' WHEN n:Group THEN 'Group' ELSE 'Other' END AS principal_type,
        target.name AS target,
        target.hasspn AS has_spn,
        target.admincount AS target_admin
    ORDER BY target.admincount DESC, n.name
    LIMIT 100
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("WriteSPN Permissions", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} WriteSPN permission(s)")

    if results:
        admin_targets = sum(1 for r in results if r.get("target_admin"))
        if admin_targets:
            print_warning(f"[!] {admin_targets} target(s) are admin accounts - HIGH VALUE!")
        print_warning("[!] WriteSPN allows targeted Kerberoasting - set SPN, request TGS, crack!")

        print_table(
            ["Principal", "Type", "Target", "Has SPN", "Target Admin"],
            [
                [r["principal"], r["principal_type"], r["target"], r["has_spn"], r["target_admin"]]
                for r in results
            ],
        )
        print_abuse_section(results, "WriteSPN")

    return result_count
