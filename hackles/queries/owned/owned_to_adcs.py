"""Owned -> ADCS Templates"""
from __future__ import annotations

from typing import Optional, TYPE_CHECKING

from hackles.queries.base import register_query
from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader
from hackles.display.paths import print_paths_grouped
from hackles.abuse.printer import print_abuse_info
from hackles.core.cypher import node_type
from hackles.core.utils import extract_domain
from hackles.core.config import config


if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE

@register_query(
    name="Owned -> ADCS Templates",
    category="Owned",
    default=True,
    severity=Severity.HIGH
)
def get_owned_to_adcs(bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None) -> int:
    """Find paths from owned principals to ADCS escalation (ESC1, ESC4, etc.)"""
    from_owned_filter = "AND toUpper(owned.name) = toUpper($from_owned)" if config.from_owned else ""
    params = {"from_owned": config.from_owned} if config.from_owned else {}

    query = f"""
    MATCH (owned)
    WHERE (owned:Tag_Owned OR 'owned' IN owned.system_tags OR owned.owned = true)
    {from_owned_filter}
    WITH owned
    MATCH p=(owned)-[*1..{config.max_path_depth}]->(template:CertTemplate)-[:PublishedTo]->(ca:EnterpriseCA)
    WHERE template.enrolleesuppliessubject = true
    OR template.authenticationenabled = true
    RETURN
        [node IN nodes(p) | node.name] AS nodes,
        [node IN nodes(p) | CASE
            WHEN node:User THEN 'User'
            WHEN node:Group THEN 'Group'
            WHEN node:Computer THEN 'Computer'
            WHEN node:CertTemplate THEN 'CertTemplate'
            WHEN node:EnterpriseCA THEN 'EnterpriseCA'
            WHEN node:Domain THEN 'Domain'
            ELSE 'Other' END] AS node_types,
        [r IN relationships(p) | type(r)] AS relationships,
        length(p) AS path_length,
        template.name AS template,
        ca.name AS ca
    ORDER BY length(p)
    LIMIT {config.max_paths}
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Owned -> ADCS Templates", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} path(s) to certificate templates")

    if results:
        print_paths_grouped(results)
        # Extract info for abuse templates
        abuse_data = [{"principal": r["nodes"][0], "template": r.get("template"), "ca": r.get("ca")} for r in results if r.get("nodes")]
        print_abuse_info("ADCSESC1", abuse_data, extract_domain([{"name": r["nodes"][0]} for r in results if r.get("nodes")], None))

    return result_count
