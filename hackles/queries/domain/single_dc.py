"""Single Domain Controller Detection"""
from __future__ import annotations

from typing import Optional, TYPE_CHECKING

from hackles.queries.base import register_query
from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="Single Point of Failure DCs",
    category="Basic Info",
    default=True,
    severity=Severity.MEDIUM
)
def get_single_dc(bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None) -> int:
    """Find domains with only one Domain Controller - availability risk."""
    domain_filter = "WHERE toUpper(d.name) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (d:Domain)
    {domain_filter}
    OPTIONAL MATCH (c:Computer)-[:MemberOf*1..]->(g:Group)
    WHERE g.objectid ENDS WITH '-516'
    AND toUpper(c.domain) = toUpper(d.name)
    WITH d, count(DISTINCT c) AS dc_count
    RETURN
        d.name AS domain,
        dc_count
    ORDER BY dc_count ASC, d.name
    """
    results = bh.run_query(query, params)

    # Filter to domains with only 1 DC
    single_dc_domains = [r for r in results if r.get("dc_count", 0) == 1]
    result_count = len(single_dc_domains)

    if not print_header("Single Point of Failure DCs", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} domain(s) with only one DC")

    if single_dc_domains:
        print_warning("[!] Single DC = no redundancy - failure impacts entire domain!")
        print_warning("[*] Consider adding additional Domain Controllers")
        print_table(
            ["Domain", "DC Count"],
            [[r["domain"], r["dc_count"]] for r in single_dc_domains]
        )
    elif results:
        # Show all domains with their DC counts for info
        print_table(
            ["Domain", "DC Count"],
            [[r["domain"], r["dc_count"]] for r in results]
        )

    return result_count
