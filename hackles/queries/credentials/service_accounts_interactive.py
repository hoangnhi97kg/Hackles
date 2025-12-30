"""Service Accounts Allowing Interactive Logon"""
from __future__ import annotations

from typing import Optional, TYPE_CHECKING

from hackles.queries.base import register_query
from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="Service Accounts with Interactive Logon",
    category="Privilege Escalation",
    default=True,
    severity=Severity.MEDIUM
)
def get_service_accounts_interactive(bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None) -> int:
    """Find service accounts that can be used for interactive logon.

    Service accounts that allow interactive logon increase credential theft risk
    as their credentials may be cached on machines where admins log in.
    """
    domain_filter = "AND toUpper(u.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    # Service accounts with sessions (indicating interactive use) or logoncount > 0
    # Also check for service accounts that are members of Remote Desktop Users
    query = f"""
    MATCH (u:User {{hasspn: true}})
    WHERE u.enabled = true
    AND NOT u.name STARTS WITH 'KRBTGT'
    {domain_filter}
    OPTIONAL MATCH (u)-[:HasSession]->(c:Computer)
    OPTIONAL MATCH (u)-[:MemberOf*1..3]->(g:Group)
    WHERE g.name CONTAINS 'REMOTE DESKTOP' OR g.name CONTAINS 'RDP'
    WITH u,
        count(DISTINCT c) AS session_count,
        collect(DISTINCT g.name) AS rdp_groups
    WHERE session_count > 0 OR size(rdp_groups) > 0
    RETURN
        u.name AS service_account,
        u.displayname AS display_name,
        u.serviceprincipalnames[0] AS primary_spn,
        session_count,
        u.lastlogontimestamp AS last_logon,
        CASE WHEN u.admincount = true THEN 'Yes' ELSE 'No' END AS is_admin,
        rdp_groups
    ORDER BY session_count DESC, u.admincount DESC
    LIMIT 100
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Service Accounts with Interactive Logon", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} service account(s) with interactive logon indicators (limit 100)")

    if results:
        # Count admin service accounts with sessions
        admin_with_sessions = sum(1 for r in results if r.get("is_admin") == "Yes" and r.get("session_count", 0) > 0)
        if admin_with_sessions:
            print_warning(f"[!] {admin_with_sessions} ADMIN service account(s) have active sessions - credential theft risk!")

        print_table(
            ["Service Account", "Display Name", "Primary SPN", "Sessions", "Admin", "RDP Groups"],
            [[r["service_account"], r.get("display_name", ""),
              r.get("primary_spn", ""), r.get("session_count", 0),
              r.get("is_admin", "No"),
              ", ".join(r.get("rdp_groups", [])[:2])] for r in results]
        )

    return result_count
