"""ADCS ESC13 - Issuance Policy Abuse"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from hackles.abuse.printer import print_abuse_info
from hackles.core.cypher import node_type
from hackles.core.utils import extract_domain
from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="ADCS ESC13 - Issuance Policy Abuse", category="ADCS", default=True, severity=Severity.HIGH
)
def get_esc13_issuance_policy(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Find ESC13 vulnerable configurations - issuance policy linked to group.

    ESC13 exploits certificate templates with issuance policies linked to
    universal groups via OID group link. When a user enrolls in such a template,
    they receive the SIDs of linked groups, granting elevated privileges.
    """
    domain_filter = "WHERE toUpper(n.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (n)-[:ADCSESC13]->(g:Group)
    {domain_filter}
    RETURN DISTINCT
        n.name AS principal,
        {node_type('n')} AS type,
        g.name AS linked_group,
        g.highvalue AS high_value
    ORDER BY g.highvalue DESC, g.name, n.name
    LIMIT 100
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("ADCS ESC13 - Issuance Policy Abuse", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} ESC13 path(s) (limit 100)")

    if results:
        print_warning(
            "[!] Certificate enrollment grants membership to linked groups via issuance policy"
        )
        print_table(
            ["Principal", "Type", "Linked Group", "High Value"],
            [
                [
                    r["principal"],
                    r["type"],
                    r["linked_group"],
                    "Yes" if r.get("high_value") else "No",
                ]
                for r in results
            ],
        )
        print_abuse_info("ADCSESC13", results, extract_domain(results, domain))

    return result_count
