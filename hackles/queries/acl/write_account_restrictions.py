"""WriteAccountRestrictions"""
from __future__ import annotations

from typing import Optional, TYPE_CHECKING

from hackles.queries.base import register_query
from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.abuse.printer import print_abuse_info
from hackles.core.utils import extract_domain

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE

@register_query(
    name="WriteAccountRestrictions",
    category="ACL Abuse",
    default=True,
    severity=Severity.HIGH
)
def get_write_account_restrictions(bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None) -> int:
    """WriteAccountRestrictions permissions (alternative RBCD setup)"""
    domain_filter = "AND toUpper(n.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH p=(n)-[:WriteAccountRestrictions]->(c:Computer)
    WHERE NOT n.objectid ENDS WITH '-512'
      AND NOT n.objectid ENDS WITH '-519'
    {domain_filter}
    RETURN n.name AS principal, labels(n)[1] AS type, c.name AS target
    ORDER BY n.name
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("WriteAccountRestrictions", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} WriteAccountRestrictions relationship(s)")

    if results:
        print_warning("[!] Can modify logon restrictions - alternative RBCD setup path!")
        print_table(
            ["Principal", "Type", "Target Computer"],
            [[r["principal"], r["type"], r["target"]] for r in results]
        )
        print_abuse_info("WriteAccountRestrictions", results, extract_domain(results, domain))

    return result_count
