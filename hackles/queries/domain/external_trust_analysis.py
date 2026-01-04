"""External Trust Analysis"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="External Trust Analysis", category="Basic Info", default=True, severity=Severity.MEDIUM
)
def get_external_trust_analysis(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """External and forest trust analysis"""
    query = """
    MATCH (d1:Domain)-[r:TrustedBy]->(d2:Domain)
    RETURN d1.name AS trusting_domain,
           COALESCE(r.trusttype, 'Unknown') AS trust_type,
           d2.name AS trusted_domain,
           COALESCE(r.sidfilteringenabled, true) AS sid_filtering,
           COALESCE(r.transitive, false) AS transitive
    ORDER BY d1.name
    """
    results = bh.run_query(query, {})
    result_count = len(results)

    if not print_header("Domain Trust Analysis", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} trust relationship(s)")

    if results:
        no_filter = sum(1 for r in results if r.get("sid_filtering") == False)
        if no_filter:
            print_warning(
                f"[!] {no_filter} trust(s) without SID filtering - Golden Ticket abuse possible!"
            )
        print_table(
            ["Trusting Domain", "Trust Type", "Trusted Domain", "SID Filtering", "Transitive"],
            [
                [
                    r["trusting_domain"],
                    r["trust_type"],
                    r["trusted_domain"],
                    r["sid_filtering"],
                    r["transitive"],
                ]
                for r in results
            ],
        )

    return result_count
