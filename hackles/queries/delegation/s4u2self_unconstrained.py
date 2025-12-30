"""S4U2Self with Unconstrained Delegation (Protocol Transition Attack)"""
from __future__ import annotations

from typing import Optional, TYPE_CHECKING

from hackles.queries.base import register_query
from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.core.cypher import node_type

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="S4U2Self + Unconstrained Delegation",
    category="Delegation",
    default=True,
    severity=Severity.CRITICAL
)
def get_s4u2self_unconstrained(bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None) -> int:
    """Find accounts with both S4U2Self (Protocol Transition) and Unconstrained Delegation.

    This dangerous combination allows:
    - Using S4U2Self to get a forwardable TGS for ANY user (even those marked sensitive)
    - The unconstrained delegation then allows using that ticket against any service
    - Result: Complete user impersonation across the domain

    Note: Accounts marked 'sensitive' cannot be delegated, but S4U2Self bypasses this!
    """
    domain_filter = "AND toUpper(n.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (n)
    WHERE (n:User OR n:Computer)
    AND n.unconstraineddelegation = true
    AND n.trustedtoauthforimpersonation = true
    AND n.enabled <> false
    {domain_filter}
    RETURN
        n.name AS principal,
        {node_type('n')} AS type,
        n.enabled AS enabled,
        CASE WHEN n.admincount = true THEN 'Yes' ELSE 'No' END AS is_admin,
        CASE WHEN 'admin_tier_0' IN n.system_tags OR n:Tag_Tier_Zero THEN 'T0' ELSE '' END AS tier_zero,
        COALESCE(n.serviceprincipalnames, []) AS spns,
        n.domain AS domain
    ORDER BY is_admin DESC, n.name
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("S4U2Self + Unconstrained Delegation", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} principal(s) with Protocol Transition + Unconstrained Delegation")

    if results:
        print_warning("[!] CRITICAL: These accounts can impersonate ANY user to ANY service!")
        print_warning("    Protocol Transition (S4U2Self) + Unconstrained Delegation = Full impersonation")
        print_warning("")
        print_warning("    Attack chain:")
        print_warning("    1. Use S4U2Self to get a forwardable TGS for target user (even 'sensitive' accounts)")
        print_warning("    2. S4U2Proxy is unrestricted due to unconstrained delegation")
        print_warning("    3. Present ticket to any service as the impersonated user")
        print_warning("")

        # Check for admin accounts with this config
        admin_count = sum(1 for r in results if r.get("is_admin") == "Yes")
        if admin_count > 0:
            print_warning(f"    [{admin_count}] are already admin accounts - may be legitimate DCs")

        # Format SPNs for display (truncate long lists)
        display_results = []
        for r in results:
            spns = r.get("spns", [])
            if isinstance(spns, list):
                spn_display = ", ".join(spns[:3])
                if len(spns) > 3:
                    spn_display += f" (+{len(spns) - 3} more)"
            else:
                spn_display = str(spns) if spns else "None"

            display_results.append([
                r["principal"], r["type"], r.get("is_admin", "No"),
                r.get("tier_zero", ""), spn_display
            ])

        print_table(
            ["Principal", "Type", "Admin", "T0", "SPNs"],
            display_results
        )

        print()
        print("    Exploitation:")
        print("    # Get TGS for DA via S4U2Self (bypass 'sensitive' flag)")
        print("    Rubeus.exe s4u /user:<COMPROMISED> /rc4:<HASH> /impersonateuser:Administrator /msdsspn:cifs/dc01.domain.com /ptt")

    return result_count
