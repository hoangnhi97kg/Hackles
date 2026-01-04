"""LDAP Channel Binding Status"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="LDAP Channel Binding Status",
    category="Security Hygiene",
    default=True,
    severity=Severity.MEDIUM,
)
def get_ldap_channel_binding(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """LDAP signing and channel binding status on DCs"""
    domain_filter = "WHERE toUpper(d.name) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (c:Computer)-[:DCFor]->(d:Domain)
    {domain_filter}
    RETURN c.name AS dc,
           COALESCE(c.ldapsigning, 'Unknown') AS ldap_signing,
           COALESCE(c.ldapchannelbinding, 'Unknown') AS channel_binding
    ORDER BY c.name
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("LDAP Signing/Channel Binding Status", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} DC(s)")

    if results:
        vulnerable = sum(
            1
            for r in results
            if r.get("ldap_signing") == False or r.get("channel_binding") == False
        )
        if vulnerable:
            print_warning(f"[!] {vulnerable} DC(s) vulnerable to NTLM relay!")
        print_table(
            ["DC", "LDAP Signing", "Channel Binding"],
            [[r["dc"], r["ldap_signing"], r["channel_binding"]] for r in results],
        )

    return result_count
