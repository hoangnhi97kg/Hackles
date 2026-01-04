"""Domain Users -> High Value"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from hackles.core.config import config
from hackles.core.cypher import node_type
from hackles.display.colors import Severity
from hackles.display.paths import print_paths_grouped
from hackles.display.tables import print_header, print_subheader, print_warning
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="Domain Users -> High Value",
    category="Attack Paths",
    default=True,
    severity=Severity.CRITICAL,
)
def get_domain_users_to_highvalue(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Shortest paths from Domain Users group to high value targets"""
    domain_filter = "AND toUpper(g.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH p=shortestPath((g:Group)-[*1..{config.max_path_depth}]->(t))
    WHERE g.objectid ENDS WITH '-513'
      AND (t.highvalue = true OR t.objectid ENDS WITH '-512' OR t.objectid ENDS WITH '-519')
      AND g <> t
      {domain_filter}
    RETURN
        [n IN nodes(p) | n.name] AS nodes,
        [n IN nodes(p) | {node_type('n')}] AS node_types,
        [r IN relationships(p) | type(r)] AS relationships,
        length(p) AS path_length
    LIMIT {config.max_paths}
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Domain Users → High Value Targets", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} path(s) from Domain Users to high value targets")

    if results:
        print_warning("[!] ANY domain user can escalate via these paths!")
        print_paths_grouped(results)

    return result_count
