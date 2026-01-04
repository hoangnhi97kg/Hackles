"""Protected Users Group Membership"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="Admins Missing from Protected Users",
    category="Dangerous Groups",
    default=True,
    severity=Severity.MEDIUM,
)
def get_protected_users_missing(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Find privileged users NOT in the Protected Users group"""
    domain_filter = "AND toUpper(u.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (u:User)-[:MemberOf*1..]->(g:Group)
    WHERE g.objectid ENDS WITH '-512' OR g.objectid ENDS WITH '-519'
    OR g.objectid ENDS WITH '-518' OR g.name =~ '(?i).*admin.*'
    {domain_filter}
    WITH DISTINCT u
    WHERE u.enabled = true
    AND NOT EXISTS {{
        MATCH (u)-[:MemberOf*1..]->(pu:Group)
        WHERE pu.objectid ENDS WITH '-525'
    }}
    RETURN u.name AS user, u.domain AS domain,
           u.admincount AS is_admin,
           u.sensitive AS sensitive,
           u.lastlogontimestamp AS last_logon
    ORDER BY u.name
    LIMIT 100
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Admins Missing from Protected Users", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} privileged user(s) NOT in Protected Users")

    if results:
        print_warning("[!] These privileged users are NOT in Protected Users group!")
        print_warning("    Protected Users prevents:")
        print_warning("    - NTLM authentication (no hash exposure)")
        print_warning("    - DES or RC4 Kerberos encryption")
        print_warning("    - Unconstrained or constrained delegation")
        print_warning("    - Kerberos TGT renewal beyond 4 hours")
        print()
        print("    Recommendation: Add high-privilege accounts to Protected Users")
        print("    Note: Some service accounts may break with Protected Users membership")
        print()

        # Count those with sensitive flag
        sensitive_count = sum(1 for r in results if r["sensitive"])
        print_warning(f"    {sensitive_count} already marked sensitive (partial protection)")

        print_table(
            ["User", "Domain", "Admin Flag", "Sensitive Flag"],
            [[r["user"], r["domain"], r["is_admin"], r["sensitive"]] for r in results],
        )

    return result_count
