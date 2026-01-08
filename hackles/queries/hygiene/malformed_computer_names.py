"""Malformed Computer Names (Data Quality)"""

from __future__ import annotations

from typing import TYPE_CHECKING

from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="Malformed Computer Names",
    category="Security Hygiene",
    default=True,
    severity=Severity.LOW,
)
def get_malformed_computer_names(
    bh: BloodHoundCE, domain: str | None = None, severity: Severity = None
) -> int:
    """Detect computer names with duplicated hostname prefixes (data quality issue)"""
    domain_filter = "AND toUpper(c.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    # Detect names like DC01.DC01.DOMAIN.COM where hostname is duplicated
    # Uses string functions instead of regex backreferences (more reliable in Neo4j)
    # Logic: Extract first segment, check if name starts with "segment.segment."
    query = f"""
    MATCH (c:Computer)
    WHERE c.name CONTAINS '.'
    WITH c, split(c.name, '.')[0] AS first_segment
    WHERE size(first_segment) > 0
    AND c.name STARTS WITH (first_segment + '.' + first_segment + '.')
    {domain_filter}
    RETURN c.name AS computer,
           c.operatingsystem AS os,
           c.enabled AS enabled
    ORDER BY c.name
    LIMIT 50
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Malformed Computer Names", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} computer(s) with malformed names")

    if results:
        print_warning("[!] Data Quality Issue: Computer names have duplicated hostname prefix!")
        print_warning("    Example: DC01.DC01.DOMAIN.COM should be DC01.DOMAIN.COM")
        print_warning("    This indicates AD misconfiguration or collection issues.")
        print()
        print("    To fix in Active Directory:")
        print("    Set-ADComputer -Identity 'NAME' -DNSHostName 'CORRECT.FQDN'")
        print()
        print_table(
            ["Computer", "Operating System", "Enabled"],
            [[r["computer"], r["os"], r["enabled"]] for r in results],
        )

    return result_count
