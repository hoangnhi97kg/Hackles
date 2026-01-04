"""Tier Zero Principal Count"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="Tier Zero Principal Count", category="Basic Info", default=True, severity=Severity.INFO
)
def get_tier_zero_count(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Count Tier Zero principals per domain"""
    domain_filter = "WHERE toUpper(d.name) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (d:Domain)
    {domain_filter}
    OPTIONAL MATCH (d)-[:Contains*1..]->(n)
    WHERE 'admin_tier_0' IN n.system_tags
    WITH d, COUNT(n) AS tier_zero_count
    RETURN d.name AS domain, tier_zero_count
    ORDER BY tier_zero_count DESC
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Tier Zero Principal Count", severity, result_count):
        return result_count
    print_subheader(f"Tier Zero principals per domain")

    if results:
        total = sum(r["tier_zero_count"] or 0 for r in results)
        print_table(
            ["Domain", "Tier Zero Count"], [[r["domain"], r["tier_zero_count"]] for r in results]
        )
        if total > 50:
            print_warning(
                f"Total of {total} Tier Zero principals - consider reducing attack surface!"
            )

    return result_count
