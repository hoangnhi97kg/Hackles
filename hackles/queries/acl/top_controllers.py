"""Top ACL Controllers"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from hackles.core.cypher import node_type
from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="Top ACL Controllers", category="ACL Abuse", default=True, severity=Severity.MEDIUM
)
def get_top_controllers(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Top principals by outbound ACL control (attack surface)"""
    domain_filter = "AND toUpper(n.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (n)-[r]->(m)
    WHERE r.isacl = true
    {domain_filter}
    WITH n, COLLECT(DISTINCT m.name)[0..5] AS sample_targets, COUNT(DISTINCT m) AS controlled
    WHERE controlled > 10
    RETURN n.name AS principal, {node_type('n')} AS type, controlled AS objects_controlled, sample_targets
    ORDER BY controlled DESC
    LIMIT 50
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Top ACL Controllers", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} principal(s) controlling 10+ objects")

    if results:
        print_table(
            ["Principal", "Type", "Count", "Sample Targets"],
            [
                [r["principal"], r["type"], r["objects_controlled"], r["sample_targets"]]
                for r in results
            ],
        )

    return result_count
