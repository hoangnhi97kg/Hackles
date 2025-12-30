"""Multi-hop Delegation Chains to High-Value Targets"""
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
    name="Delegation Chains to High-Value",
    category="Delegation",
    default=True,
    severity=Severity.CRITICAL
)
def get_delegation_chains(bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None) -> int:
    """Find multi-hop delegation chains that reach high-value targets.

    Identifies principals that can delegate to services which can then
    delegate to Domain Controllers or Domain Admins - critical attack paths.
    """
    domain_filter = "AND toUpper(start.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    # Find delegation paths to DCs or high-value services
    query = f"""
    MATCH (start)
    WHERE (start:User OR start:Computer)
    AND start.allowedtodelegate IS NOT NULL
    AND size(start.allowedtodelegate) > 0
    {domain_filter}
    WITH start, start.allowedtodelegate AS targets
    UNWIND targets AS target
    WITH start, target
    WHERE target CONTAINS 'ldap/' OR target CONTAINS 'cifs/' OR target CONTAINS 'HOST/'
    // Extract hostname from SPN
    WITH start, target, split(split(target, '/')[1], '.')[0] AS target_host
    OPTIONAL MATCH (dc:Computer)
    WHERE toUpper(dc.name) STARTS WITH toUpper(target_host)
    AND (dc.objectid ENDS WITH '-516' OR dc:Tag_Tier_Zero)
    WITH start, target, dc
    WHERE dc IS NOT NULL
    RETURN DISTINCT
        start.name AS source,
        CASE WHEN start:User THEN 'User' ELSE 'Computer' END AS source_type,
        target AS delegation_target,
        dc.name AS reaches_dc,
        CASE WHEN start.admincount = true THEN 'Yes' ELSE 'No' END AS source_is_admin
    ORDER BY source_is_admin DESC, source
    LIMIT 100
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Delegation Chains to High-Value", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} delegation chain(s) reaching DCs/high-value (limit 100)")

    if results:
        # Count non-admin sources (more dangerous)
        non_admin = sum(1 for r in results if r.get("source_is_admin") == "No")
        if non_admin > 0:
            print_warning(f"[!] {non_admin} chain(s) start from non-admin principals - privilege escalation paths!")

        print_table(
            ["Source", "Type", "Delegation Target", "Reaches DC", "Source Admin"],
            [[r["source"], r["source_type"], r["delegation_target"],
              r["reaches_dc"], r.get("source_is_admin", "No")] for r in results]
        )
        print_abuse_info("ConstrainedDelegation", results, extract_domain(results, domain))

    return result_count
