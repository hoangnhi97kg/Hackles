"""Exchange Rights on Domain"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from hackles.abuse.printer import print_abuse_info
from hackles.core.utils import extract_domain
from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="Exchange Rights on Domain", category="Exchange", default=True, severity=Severity.CRITICAL
)
def get_exchange_domain_rights(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Find Exchange groups with dangerous rights on domain"""
    domain_filter = "AND toUpper(d.name) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (g:Group)-[r:WriteDacl|GenericAll|GenericWrite|WriteOwner]->(d:Domain)
    WHERE toUpper(g.name) CONTAINS 'EXCHANGE'
    {domain_filter}
    RETURN
        g.name AS exchange_group,
        type(r) AS permission,
        d.name AS domain
    ORDER BY g.name
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Exchange Rights on Domain", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} Exchange group(s) with domain-level rights")

    if results:
        print_warning("[!] CRITICAL: Exchange WriteDacl on domain allows granting DCSync rights!")
        print_table(
            ["Exchange Group", "Permission", "Domain"],
            [[r["exchange_group"], r["permission"], r["domain"]] for r in results],
        )
        print_abuse_info("ExchangePrivEsc", results, extract_domain(results, domain))

    return result_count
