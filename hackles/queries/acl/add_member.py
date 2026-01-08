"""AddMember ACL Abuse"""

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
    name="AddMember ACL Abuse", category="ACL Abuse", default=True, severity=Severity.HIGH
)
def get_add_member(bh: BloodHoundCE, domain: str | None = None, severity: Severity = None) -> int:
    """Find non-admin principals that can add members to groups.

    AddMember allows adding users/computers to groups, which can be used
    to escalate privileges by adding yourself to privileged groups.
    """
    domain_filter = "AND toUpper(g.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (n)-[:AddMember]->(g:Group)
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
        g.name AS target_group,
        CASE WHEN g.admincount = true THEN 'Yes' ELSE 'No' END AS group_is_admin,
        CASE
            WHEN g.objectid ENDS WITH '-512' THEN 'Domain Admins'
            WHEN g.objectid ENDS WITH '-519' THEN 'Enterprise Admins'
            WHEN g.objectid ENDS WITH '-544' THEN 'Administrators'
            ELSE ''
        END AS special_group
    ORDER BY g.admincount DESC, n.name
    LIMIT 200
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("AddMember ACL Abuse", severity, result_count):
        return result_count
    print_subheader(
        f"Found {result_count} AddMember relationship(s) from non-admin principals (limit 200)"
    )

    if results:
        # Count high-value targets
        admin_groups = sum(1 for r in results if r.get("group_is_admin") == "Yes")
        special_groups = sum(1 for r in results if r.get("special_group"))
        if special_groups > 0:
            print_warning(
                f"[!] {special_groups} can add to Domain Admins/Enterprise Admins/Administrators!"
            )
        elif admin_groups > 0:
            print_warning(f"[!] {admin_groups} target group(s) are admin protected groups!")

        print_table(
            ["Principal", "Type", "Target Group", "Admin Group", "Special"],
            [
                [
                    r["principal"],
                    r["principal_type"],
                    r["target_group"],
                    r.get("group_is_admin", "No"),
                    r.get("special_group", ""),
                ]
                for r in results
            ],
        )
        # AddMember only applies to groups - remap keys for abuse display
        group_results = [{"target": r["target_group"], "target_type": "Group"} for r in results]
        print_abuse_section(group_results, edge_type="AddMember")

    return result_count
