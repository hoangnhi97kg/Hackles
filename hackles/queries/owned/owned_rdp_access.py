"""Owned RDP Access"""
from __future__ import annotations

from typing import Optional, TYPE_CHECKING

from hackles.queries.base import register_query
from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table
from hackles.abuse.printer import print_abuse_info
from hackles.core.cypher import node_type
from hackles.core.utils import extract_domain
from hackles.core.config import config


if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE

@register_query(
    name="Owned RDP Access",
    category="Owned",
    default=True,
    severity=Severity.MEDIUM
)
def get_owned_rdp_access(bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None) -> int:
    """Find computers where owned principals have RDP access"""
    from_owned_filter = "AND toUpper(owned.name) = toUpper($from_owned)" if config.from_owned else ""
    params = {"from_owned": config.from_owned} if config.from_owned else {}

    query = f"""
    MATCH (owned)-[:CanRDP|MemberOf*1..3]->(c:Computer)
    WHERE (owned:Tag_Owned OR 'owned' IN owned.system_tags OR owned.owned = true)
    {from_owned_filter}
    RETURN owned.name AS owned_principal, {node_type('owned')} AS owned_type,
           c.name AS computer, c.operatingsystem AS os, c.enabled AS enabled
    ORDER BY owned.name
    LIMIT 50
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Owned RDP Access", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} RDP access relationship(s)")

    if results:
        print_table(
            ["Owned Principal", "Type", "Computer", "OS", "Enabled"],
            [[r["owned_principal"], r["owned_type"], r["computer"], r["os"], r["enabled"]] for r in results]
        )
        print_abuse_info("CanRDP", [{"principal": r["owned_principal"], "computer": r["computer"]} for r in results], extract_domain(results, None))

    return result_count
