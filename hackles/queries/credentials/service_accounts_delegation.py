"""Service Accounts with Dangerous Delegation"""
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
    name="Service Accounts with Dangerous Delegation",
    category="Privilege Escalation",
    default=True,
    severity=Severity.CRITICAL
)
def get_service_accounts_delegation(bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None) -> int:
    """Find service accounts with constrained delegation to high-value targets.

    Service accounts with delegation to Domain Admins, Domain Controllers, or
    other high-value targets represent critical privilege escalation paths.
    """
    domain_filter = "AND toUpper(u.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    # Find service accounts with constrained delegation to high-value targets
    query = f"""
    MATCH (u:User {{hasspn: true}})
    WHERE u.enabled = true
    AND u.allowedtodelegate IS NOT NULL
    AND size(u.allowedtodelegate) > 0
    {domain_filter}
    WITH u, u.allowedtodelegate AS targets
    // Check if any target contains DC or high-value service
    WITH u, targets,
        ANY(t IN targets WHERE
            t CONTAINS '/DC' OR
            t CONTAINS 'ldap/' OR
            t CONTAINS 'cifs/' OR
            t CONTAINS 'http/' OR
            t CONTAINS 'HOST/'
        ) AS targets_dc
    RETURN
        u.name AS service_account,
        u.displayname AS display_name,
        u.serviceprincipalnames[0] AS primary_spn,
        targets AS delegation_targets,
        targets_dc AS targets_high_value,
        CASE WHEN u.unconstraineddelegation = true THEN 'Yes' ELSE 'No' END AS unconstrained
    ORDER BY targets_dc DESC, u.name
    LIMIT 100
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Service Accounts with Dangerous Delegation", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} service account(s) with delegation configured (limit 100)")

    if results:
        # Count critical ones
        high_value_count = sum(1 for r in results if r.get("targets_high_value"))
        unconstrained_count = sum(1 for r in results if r.get("unconstrained") == "Yes")
        if high_value_count:
            print_warning(f"[!] {high_value_count} delegate to DC/high-value services - critical risk!")
        if unconstrained_count:
            print_warning(f"[!] {unconstrained_count} have UNCONSTRAINED delegation!")

        print_table(
            ["Service Account", "Display Name", "Primary SPN", "Delegation Targets", "High Value", "Unconstrained"],
            [[r["service_account"], r.get("display_name", ""),
              r.get("primary_spn", ""),
              ", ".join(r.get("delegation_targets", [])[:3]),
              "Yes" if r.get("targets_high_value") else "No",
              r.get("unconstrained", "No")] for r in results]
        )
        print_abuse_info("ConstrainedDelegation", results, extract_domain(results, domain))

    return result_count
