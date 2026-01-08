"""Computers Without LAPS"""

from __future__ import annotations

from typing import TYPE_CHECKING

from hackles.abuse import print_abuse_for_query
from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="Computers Without LAPS",
    category="Security Hygiene",
    default=True,
    severity=Severity.MEDIUM,
)
def get_computers_without_laps(
    bh: BloodHoundCE, domain: str | None = None, severity: Severity = None
) -> int:
    """Get computers without LAPS enabled"""
    domain_filter = "WHERE toUpper(c.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (c:Computer)
    {domain_filter}
    {"AND" if domain_filter else "WHERE"} (c.haslaps IS NULL OR c.haslaps = false)
    AND c.enabled = true
    RETURN
        c.name AS computer,
        c.operatingsystem AS os,
        c.enabled AS enabled
    ORDER BY c.name
    LIMIT 100
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Computers Without LAPS", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} computer(s) without LAPS (enabled, limit 100)")

    if results:
        # Count by OS
        os_counts = {}
        for r in results:
            os_name = r.get("os") or "Unknown"
            os_counts[os_name] = os_counts.get(os_name, 0) + 1

        print_subheader("Breakdown by OS:")
        for os_name, count in sorted(os_counts.items(), key=lambda x: -x[1]):
            print(f"      {os_name}: {count}")

        print()
        print_table(
            ["Computer", "Operating System"], [[r["computer"], r["os"]] for r in results[:20]]
        )
        if len(results) > 20:
            print_warning(f"... and {len(results) - 20} more")
        print_abuse_for_query("laps", results, target_key="computer")

    return result_count
