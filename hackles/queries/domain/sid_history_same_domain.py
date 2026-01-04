"""SID History (Same Domain)"""

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
    name="SID History (Same Domain)", category="Basic Info", default=True, severity=Severity.HIGH
)
def get_sid_history_same_domain(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """SID History within same domain (persistence mechanism)"""
    domain_filter = "AND toUpper(n.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (n)-[:HasSIDHistory]->(m)
    WHERE n.domainsid = m.domainsid
    {domain_filter}
    RETURN n.name AS principal, m.name AS sid_history_target
    ORDER BY n.name
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("SID History (Same Domain)", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} same-domain SID history relationship(s)")

    if results:
        print_warning("[!] Same-domain SID history indicates potential persistence!")
        print_table(
            ["Principal", "SID History Target"],
            [[r["principal"], r["sid_history_target"]] for r in results],
        )
        print_abuse_info("HasSIDHistory", results, extract_domain(results, domain))

    return result_count
