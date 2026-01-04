"""WriteDacl ACL Abuse"""

from __future__ import annotations

from typing import TYPE_CHECKING

from hackles.abuse.printer import print_abuse_info
from hackles.core.cypher import node_type
from hackles.core.utils import extract_domain
from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="WriteDacl ACL Abuse", category="ACL Abuse", default=True, severity=Severity.HIGH
)
def get_write_dacl(bh: BloodHoundCE, domain: str | None = None, severity: Severity = None) -> int:
    """Find non-admin principals with WriteDacl over other objects.

    WriteDacl allows modifying permissions on the target object, which can be
    used to grant yourself GenericAll and then abuse that.
    """
    domain_filter = "AND toUpper(m.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (n)-[:WriteDacl]->(m)
    WHERE (n.admincount IS NULL OR n.admincount = false)
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
        CASE WHEN m.admincount = true THEN 'Yes' ELSE 'No' END AS target_is_admin
    ORDER BY m.admincount DESC, n.name
    LIMIT 200
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("WriteDacl ACL Abuse", severity, result_count):
        return result_count
    print_subheader(
        f"Found {result_count} WriteDacl relationship(s) from non-admin principals (limit 200)"
    )

    if results:
        # Count high-value targets
        admin_targets = sum(1 for r in results if r.get("target_is_admin") == "Yes")
        if admin_targets > 0:
            print_warning(
                f"[!] {admin_targets} target(s) are admin accounts - can escalate to GenericAll!"
            )

        print_table(
            ["Principal", "Type", "Target", "Target Type", "Status", "Admin"],
            [
                [
                    r["principal"],
                    r["principal_type"],
                    r["target"],
                    r["target_type"],
                    r.get("target_status", "Unknown"),
                    r.get("target_is_admin", "No"),
                ]
                for r in results
            ],
        )
        print_abuse_info("WriteDacl", results, extract_domain(results, domain))

    return result_count
