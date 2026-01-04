"""Privileged OU Delegation"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from hackles.core.cypher import node_type
from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="Privileged OU Delegation",
    category="Security Hygiene",
    default=True,
    severity=Severity.HIGH,
)
def get_privileged_ou_delegation(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Find non-admins with dangerous rights over OUs containing privileged objects"""
    domain_filter = "AND toUpper(ou.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (ou:OU)<-[:Contains*1..]-(parentOU:OU)
    WHERE ou.name =~ '(?i).*(admin|tier.?0|privileged|domain controller|server).*'
    {domain_filter}
    WITH ou
    MATCH (p)-[r:GenericAll|GenericWrite|WriteDacl|WriteOwner|Owns]->(ou)
    WHERE NOT EXISTS {{
        MATCH (p)-[:MemberOf*1..]->(g:Group)
        WHERE g.objectid ENDS WITH '-512' OR g.objectid ENDS WITH '-519'
    }}
    RETURN p.name AS principal, {node_type('p')} AS principal_type,
           type(r) AS permission, ou.name AS ou_name, ou.domain AS domain
    ORDER BY ou.name, p.name
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Privileged OU Delegation", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} dangerous OU delegation(s)")

    if results:
        print_warning("[!] Non-admins have control over privileged OUs!")
        print_warning(
            "    Can move/create objects, modify GPO links, or take control of OU contents"
        )
        print()

        # Count unique OUs affected
        unique_ous = len(set(r["ou_name"] for r in results))
        print_warning(f"    {unique_ous} privileged OU(s) affected")

        print_table(
            ["Principal", "Type", "Permission", "OU Name", "Domain"],
            [
                [r["principal"], r["principal_type"], r["permission"], r["ou_name"], r["domain"]]
                for r in results
            ],
        )

    return result_count
