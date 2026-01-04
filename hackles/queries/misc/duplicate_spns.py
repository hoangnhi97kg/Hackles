"""Duplicate SPNs"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="Duplicate SPNs", category="Miscellaneous", default=False, severity=Severity.LOW
)
def get_duplicate_spns(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Duplicate SPNs (Kerberos authentication issues)"""
    query = """
    MATCH (n)
    WHERE n.serviceprincipalnames IS NOT NULL
    UNWIND n.serviceprincipalnames AS spn
    WITH spn, COLLECT(n.name) AS principals
    WHERE SIZE(principals) > 1
    RETURN spn AS duplicate_spn, principals
    ORDER BY spn
    """
    results = bh.run_query(query, {})
    result_count = len(results)

    if not print_header("Duplicate SPNs", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} duplicate SPN(s)")

    if results:
        print_warning("[!] Duplicate SPNs can cause Kerberos authentication issues!")
        print_table(
            ["Duplicate SPN", "Principals"],
            [[r["duplicate_spn"], ", ".join(r["principals"])] for r in results],
        )

    return result_count
