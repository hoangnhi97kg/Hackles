"""Resource-Based Constrained Delegation"""

from __future__ import annotations

from typing import TYPE_CHECKING

from hackles.abuse import print_abuse_for_query
from hackles.core.cypher import node_type
from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="Resource-Based Constrained Delegation",
    category="Delegation",
    default=True,
    severity=Severity.HIGH,
)
def get_rbcd(bh: BloodHoundCE, domain: str | None = None, severity: Severity = None) -> int:
    """Get Resource-Based Constrained Delegation relationships"""
    domain_filter = "WHERE toUpper(c.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH p=(n)-[:AllowedToAct]->(c:Computer)
    {domain_filter}
    RETURN
        n.name AS principal,
        {node_type("n")} AS type,
        c.name AS target
    ORDER BY c.name, n.name
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Resource-Based Constrained Delegation (RBCD)", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} RBCD relationship(s)")

    if results:
        print_table(
            ["Principal", "Type", "Can Act On"],
            [[r["principal"], r["type"], r["target"]] for r in results],
        )
        print_abuse_for_query("rbcd", results, target_key="target")

    return result_count
