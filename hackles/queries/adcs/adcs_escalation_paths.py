"""ADCS Escalation Paths (ESC1-13)"""

from __future__ import annotations

from typing import TYPE_CHECKING

from hackles.core.cypher import node_type
from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="ADCS Escalation Paths (ESC1-13)", category="ADCS", default=True, severity=Severity.HIGH
)
def get_adcs_escalation_paths(
    bh: BloodHoundCE, domain: str | None = None, severity: Severity = None
) -> int:
    """Get all ADCS escalation paths (ESC1-ESC13)"""
    domain_filter = "AND toUpper(n.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH p=(n)-[r:ADCSESC1|ADCSESC3|ADCSESC4|ADCSESC5|ADCSESC6a|ADCSESC6b|ADCSESC7|ADCSESC9a|ADCSESC9b|ADCSESC10a|ADCSESC10b|ADCSESC13]->(m)
    WHERE (n.admincount IS NULL OR n.admincount = false)
    AND NOT n.objectid ENDS WITH '-512'  // Domain Admins
    AND NOT n.objectid ENDS WITH '-519'  // Enterprise Admins
    AND NOT n.objectid ENDS WITH '-544'  // Administrators
    {domain_filter}
    OPTIONAL MATCH (m)-[:PublishedTo]->(ca:EnterpriseCA)
    RETURN
        n.name AS principal,
        {node_type("n")} AS type,
        type(r) AS escalation,
        m.name AS target,
        ca.name AS ca
    ORDER BY type(r), n.name
    LIMIT 200
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("ADCS Escalation Paths (ESC1-ESC13)", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} ADCS escalation path(s) (limit 200)")

    if results:
        # Group by escalation type
        esc_types = {}
        for r in results:
            esc = r["escalation"]
            if esc not in esc_types:
                esc_types[esc] = 0
            esc_types[esc] += 1

        print_subheader("Escalation Types Found:")
        for esc, count in sorted(esc_types.items()):
            print(f"      {esc}: {count}")

        print()
        print_table(
            ["Principal", "Type", "Escalation", "Target", "CA"],
            [
                [r["principal"], r["type"], r["escalation"], r["target"], r.get("ca", "-")]
                for r in results
            ],
        )

    return result_count
