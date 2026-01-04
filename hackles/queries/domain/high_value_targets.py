"""High Value / Tier Zero Targets"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from hackles.core.cypher import node_type
from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="High Value / Tier Zero Targets",
    category="Basic Info",
    default=True,
    severity=Severity.INFO,
)
def get_high_value_targets(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Get objects marked as high value / Tier Zero"""
    domain_filter = "AND toUpper(n.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    # BloodHound CE uses 'admin_tier_0' for Tier Zero assets
    query = f"""
    MATCH (n)
    WHERE ('admin_tier_0' IN n.system_tags OR 'high_value' IN n.system_tags)
    {domain_filter}
    RETURN
        n.name AS name,
        {node_type('n')} AS type,
        n.description AS description
    ORDER BY {node_type('n')}, n.name
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("High Value / Tier Zero Targets", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} high value/tier zero target(s)")

    if results:
        print_table(
            ["Name", "Type", "Description"],
            [[r["name"], r["type"], r["description"]] for r in results],
        )

    return result_count
