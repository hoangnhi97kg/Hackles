"""Computer Accounts with Dangerous Delegation"""
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
    name="Computer Accounts with Delegation",
    category="Delegation",
    default=True,
    severity=Severity.HIGH
)
def get_computer_delegation(bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None) -> int:
    """Find computer accounts with delegation configured.

    Computer accounts with delegation can be abused if the computer is
    compromised - attackers can impersonate any user to the delegated services.
    """
    domain_filter = "AND toUpper(c.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (c:Computer)
    WHERE (c.unconstraineddelegation = true
        OR (c.allowedtodelegate IS NOT NULL AND size(c.allowedtodelegate) > 0))
    AND c.enabled = true
    {domain_filter}
    RETURN
        c.name AS computer,
        c.operatingsystem AS os,
        CASE WHEN c.unconstraineddelegation = true THEN 'Yes' ELSE 'No' END AS unconstrained,
        c.allowedtodelegate AS constrained_targets,
        CASE
            WHEN c.unconstraineddelegation = true THEN 'Unconstrained'
            WHEN c.allowedtodelegate IS NOT NULL THEN 'Constrained'
            ELSE 'None'
        END AS delegation_type,
        CASE WHEN c.objectid ENDS WITH '-516' THEN 'Yes' ELSE 'No' END AS is_dc
    ORDER BY c.unconstraineddelegation DESC, c.name
    LIMIT 100
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Computer Accounts with Delegation", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} computer(s) with delegation configured (limit 100)")

    if results:
        # Count dangerous types
        unconstrained = sum(1 for r in results if r.get("unconstrained") == "Yes" and r.get("is_dc") == "No")
        non_dc = sum(1 for r in results if r.get("is_dc") == "No")
        if unconstrained > 0:
            print_warning(f"[!] {unconstrained} non-DC computer(s) have UNCONSTRAINED delegation - critical risk!")
        if non_dc > 0:
            print_warning(f"[!] {non_dc} non-DC computer(s) have delegation - compromise enables impersonation!")

        def format_targets(r):
            """Format constrained delegation targets."""
            targets = r.get("constrained_targets") or []
            if not targets:
                return "N/A (Unconstrained)"
            if len(targets) > 2:
                return ", ".join(targets[:2]) + f" (+{len(targets) - 2} more)"
            return ", ".join(targets)

        print_table(
            ["Computer", "OS", "Delegation Type", "Targets", "Is DC"],
            [[r["computer"], r.get("os", "Unknown"), r.get("delegation_type", ""),
              format_targets(r), r.get("is_dc", "No")] for r in results]
        )

        # Different abuse info based on delegation type
        unconstrained_results = [r for r in results if r.get("unconstrained") == "Yes"]
        constrained_results = [r for r in results if r.get("unconstrained") != "Yes"]

        if unconstrained_results:
            print_abuse_info("UnconstrainedDelegation", unconstrained_results, extract_domain(results, domain))
        if constrained_results:
            print_abuse_info("ConstrainedDelegation", constrained_results, extract_domain(results, domain))

    return result_count
