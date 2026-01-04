"""Domain Trusts"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(name="Domain Trusts", category="Basic Info", default=True, severity=Severity.INFO)
def get_domain_trusts(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Get domain trust relationships"""
    query = """
    MATCH (d1:Domain)-[r:TrustedBy]->(d2:Domain)
    RETURN
        d1.name AS trusting_domain,
        d2.name AS trusted_domain,
        r.trusttype AS trust_type,
        r.transitive AS transitive,
        r.sidfiltering AS sid_filtering
    ORDER BY d1.name, d2.name
    """
    results = bh.run_query(query)
    result_count = len(results)

    if not print_header("Domain Trusts", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} trust relationship(s)")

    if results:
        print_table(
            ["Trusting Domain", "Trusted Domain", "Type", "Transitive", "SID Filtering"],
            [
                [
                    r["trusting_domain"],
                    r["trusted_domain"],
                    r["trust_type"],
                    r["transitive"],
                    r["sid_filtering"],
                ]
                for r in results
            ],
        )

    return result_count
