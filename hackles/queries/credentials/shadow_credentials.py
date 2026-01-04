"""Shadow Credentials (AddKeyCredentialLink)"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from hackles.abuse.printer import print_abuse_info
from hackles.core.cypher import node_type
from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="Shadow Credentials (AddKeyCredentialLink)",
    category="Privilege Escalation",
    default=True,
    severity=Severity.HIGH,
)
def get_shadow_credentials(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Get principals with AddKeyCredentialLink rights (Shadow Credentials)"""
    domain_filter = "AND toUpper(target.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH p=(n)-[:AddKeyCredentialLink]->(target)
    WHERE (n.admincount IS NULL OR n.admincount = false)
    AND NOT target.objectid ENDS WITH '-500'
    {domain_filter}
    RETURN n.name AS principal, {node_type('n')} AS type, target.name AS target, {node_type('target')} AS target_type
    LIMIT 100
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Shadow Credentials (AddKeyCredentialLink)", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} Shadow Credential path(s)")

    if results:
        print_table(
            ["Principal", "Type", "Target", "Target Type"],
            [[r["principal"], r["type"], r["target"], r["target_type"]] for r in results],
        )
        print_abuse_info("ShadowCredentials", results, domain)

    return result_count
