"""Resource-Based Constrained Delegation Targets"""

from __future__ import annotations

from typing import TYPE_CHECKING

from hackles.abuse.printer import print_abuse_info
from hackles.core.cypher import node_type
from hackles.core.utils import extract_domain
from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="RBCD Attack Targets", category="Delegation", default=True, severity=Severity.HIGH
)
def get_rbcd_targets(bh: BloodHoundCE, domain: str | None = None, severity: Severity = None) -> int:
    """Find computers where non-admins can write msDS-AllowedToActOnBehalfOfOtherIdentity (RBCD)"""
    domain_filter = "AND toUpper(c.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (p)-[:GenericAll|GenericWrite|WriteAccountRestrictions]->(c:Computer)
    WHERE NOT EXISTS {{
        MATCH (p)-[:MemberOf*1..]->(g:Group)
        WHERE g.objectid ENDS WITH '-512' OR g.objectid ENDS WITH '-519'
    }}
    {domain_filter}
    RETURN p.name AS principal, {node_type('p')} AS principal_type,
           c.name AS target_computer, c.domain AS domain,
           c.enabled AS enabled
    ORDER BY c.name, p.name
    LIMIT 100
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("RBCD Attack Targets", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} potential RBCD target(s)")

    if results:
        print_warning("[!] These computers can have RBCD configured by non-admins!")
        print_warning("    Allows impersonation attacks via S4U2Self/S4U2Proxy")
        print()
        print("    Requirements for RBCD attack:")
        print("    1. Control over a computer account (or create one via MachineAccountQuota)")
        print("    2. Write access to target's msDS-AllowedToActOnBehalfOfOtherIdentity")
        print()

        # Count unique targets
        unique_targets = len({r["target_computer"] for r in results})
        unique_attackers = len({r["principal"] for r in results})
        print_warning(
            f"    {unique_attackers} principal(s) can configure RBCD on {unique_targets} computer(s)"
        )

        print_table(
            ["Principal", "Type", "Target Computer", "Domain", "Enabled"],
            [
                [
                    r["principal"],
                    r["principal_type"],
                    r["target_computer"],
                    r["domain"],
                    r["enabled"],
                ]
                for r in results
            ],
        )
        print_abuse_info("WriteAccountRestrictions", results, extract_domain(results, domain))

    return result_count
