"""Cross-Domain Sessions"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="Cross-Domain Sessions", category="Attack Paths", default=True, severity=Severity.LOW
)
def get_cross_domain_sessions(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Find sessions crossing domain boundaries"""
    query = """
    MATCH (c:Computer)-[:HasSession]->(u:User)
    WHERE c.domain <> u.domain
    RETURN c.name AS computer, c.domain AS computer_domain, u.name AS user, u.domain AS user_domain
    LIMIT 50
    """
    results = bh.run_query(query)
    result_count = len(results)

    if not print_header("Cross-Domain Sessions", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} cross-domain session(s)")

    if results:
        print_warning("Cross-domain sessions may allow lateral movement between domains!")
        print_table(
            ["Computer", "Computer Domain", "User", "User Domain"],
            [[r["computer"], r["computer_domain"], r["user"], r["user_domain"]] for r in results],
        )

    return result_count


# ============================================================================
# NEW QUERIES - ADCS Enhancements & Miscellaneous
# ============================================================================
