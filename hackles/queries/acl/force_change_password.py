"""ForceChangePassword ACL Abuse"""

from __future__ import annotations

from typing import TYPE_CHECKING

from hackles.abuse import print_abuse_section
from hackles.core.cypher import node_type
from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="ForceChangePassword Targets", category="ACL Abuse", default=True, severity=Severity.HIGH
)
def get_force_change_password(
    bh: BloodHoundCE, domain: str | None = None, severity: Severity = None
) -> int:
    """Find non-admin principals that can force password changes on users.

    ForceChangePassword allows resetting a user's password without knowing
    the current password, enabling account takeover.
    """
    domain_filter = "AND toUpper(m.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (n)-[:ForceChangePassword]->(m:User)
    WHERE (n.admincount IS NULL OR n.admincount = false)
    AND NOT n.objectid ENDS WITH '-512'  // Domain Admins
    AND NOT n.objectid ENDS WITH '-519'  // Enterprise Admins
    AND NOT n.objectid ENDS WITH '-544'  // Administrators
    AND NOT n.objectid ENDS WITH '-548'  // Account Operators
    AND NOT n.objectid ENDS WITH '-549'  // Server Operators
    AND NOT n.objectid ENDS WITH '-550'  // Print Operators
    AND NOT n.objectid ENDS WITH '-551'  // Backup Operators
    AND NOT n.name STARTS WITH 'SYSTEM@'
    AND NOT n.name STARTS WITH 'LOCAL SERVICE@'
    AND NOT n.name STARTS WITH 'NETWORK SERVICE@'
    {domain_filter}
    RETURN
        n.name AS principal,
        {node_type("n")} AS principal_type,
        m.name AS target,
        CASE WHEN m.enabled = false THEN 'Disabled' ELSE 'Enabled' END AS target_status,
        CASE WHEN m.admincount = true THEN 'Yes' ELSE 'No' END AS target_is_admin,
        CASE WHEN m.hasspn = true THEN 'Yes' ELSE 'No' END AS has_spn
    ORDER BY m.admincount DESC, n.name
    LIMIT 200
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("ForceChangePassword Targets", severity, result_count):
        return result_count
    print_subheader(
        f"Found {result_count} ForceChangePassword relationship(s) from non-admin principals (limit 200)"
    )

    if results:
        # Count high-value targets
        admin_targets = sum(1 for r in results if r.get("target_is_admin") == "Yes")
        sum(1 for r in results if r.get("target_status") == "Enabled")
        if admin_targets > 0:
            print_warning(
                f"[!] {admin_targets} target(s) are admin accounts - direct path to privilege escalation!"
            )

        print_table(
            ["Principal", "Type", "Target User", "Status", "Admin", "Has SPN"],
            [
                [
                    r["principal"],
                    r["principal_type"],
                    r["target"],
                    r.get("target_status", "Unknown"),
                    r.get("target_is_admin", "No"),
                    r.get("has_spn", "No"),
                ]
                for r in results
            ],
        )
        # ForceChangePassword only applies to users
        user_results = [dict(r, target_type="User") for r in results]
        print_abuse_section(user_results, edge_type="ForceChangePassword")

    return result_count
