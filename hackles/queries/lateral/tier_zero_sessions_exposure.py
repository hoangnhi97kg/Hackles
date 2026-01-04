"""Tier Zero Session Exposure"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="Tier Zero Session Exposure",
    category="Lateral Movement",
    default=True,
    severity=Severity.HIGH,
)
def get_tier_zero_sessions_exposure(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Tier Zero sessions on non-Tier Zero computers"""
    domain_filter = "AND toUpper(c.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (c:Computer)-[:HasSession]->(u)
    WHERE (u:Tag_Tier_Zero OR 'admin_tier_0' IN COALESCE(u.system_tags, []))
      AND NOT (c:Tag_Tier_Zero OR 'admin_tier_0' IN COALESCE(c.system_tags, []))
    {domain_filter}
    RETURN c.name AS computer, u.name AS tier_zero_principal
    ORDER BY c.name
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Tier Zero Sessions on Non-T0 Hosts", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} Tier Zero session(s) exposed")

    if results:
        print_warning("[!] Tier Zero credentials exposed on lower-tier systems!")
        print_table(
            ["Computer", "Tier Zero Principal"],
            [[r["computer"], r["tier_zero_principal"]] for r in results],
        )

    return result_count
