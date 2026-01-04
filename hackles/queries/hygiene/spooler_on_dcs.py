"""Print Spooler on DCs"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="Print Spooler on DCs", category="Security Hygiene", default=True, severity=Severity.HIGH
)
def get_spooler_on_dcs(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Print Spooler enabled on Domain Controllers (coercion attacks)"""
    domain_filter = "AND toUpper(c.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (c:Computer)-[:MemberOf*1..]->(g:Group)
    WHERE g.objectid ENDS WITH '-516'
    {domain_filter}
    RETURN c.name AS domain_controller, c.operatingsystem AS os,
           COALESCE(c.spoolersvcenabled, 'Unknown') AS spooler_enabled
    ORDER BY c.name
    """
    results = bh.run_query(query, params)
    result_count = len(results)
    enabled_count = sum(1 for r in results if r.get("spooler_enabled") == True)

    if not print_header("Print Spooler on DCs", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} DC(s), {enabled_count} with spooler enabled")

    if results:
        if enabled_count:
            print_warning("[!] Spooler enables PrinterBug/PetitPotam coercion attacks!")
        print_table(
            ["Domain Controller", "OS", "Spooler Enabled"],
            [[r["domain_controller"], r["os"], r["spooler_enabled"]] for r in results],
        )

    return result_count
