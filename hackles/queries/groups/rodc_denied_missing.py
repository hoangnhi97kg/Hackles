"""Tier Zero Not in Denied RODC Password Replication Group"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="Tier Zero Missing from Denied RODC Replication",
    category="Dangerous Groups",
    default=True,
    severity=Severity.HIGH,
)
def get_rodc_denied_missing(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Find Tier Zero accounts NOT in Denied RODC Password Replication Group.

    Tier Zero accounts should be in the Denied RODC Password Replication Group
    to prevent their password hashes from being cached on Read-Only Domain Controllers.
    If an RODC is compromised, accounts not in the Denied group could have credentials extracted.
    """
    domain_filter = "AND toUpper(n.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    # RID -572 is "Denied RODC Password Replication Group"
    # Find Tier Zero principals that are NOT members of the Denied group
    query = f"""
    MATCH (n)
    WHERE (n:User OR n:Computer)
    AND (n:Tag_Tier_Zero OR n.admincount = true)
    AND n.enabled = true
    {domain_filter}
    WITH n
    OPTIONAL MATCH (n)-[:MemberOf*1..]->(denied:Group)
    WHERE denied.objectid ENDS WITH '-572'
    WITH n, denied
    WHERE denied IS NULL
    RETURN
        n.name AS principal,
        CASE WHEN n:User THEN 'User' WHEN n:Computer THEN 'Computer' ELSE 'Other' END AS type,
        n.domain AS domain,
        COALESCE(n.admincount, false) AS admincount
    ORDER BY type, n.name
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Tier Zero Missing from Denied RODC Replication", severity, result_count):
        return result_count
    print_subheader(
        f"Found {result_count} Tier Zero principal(s) not in Denied RODC Password Replication Group"
    )

    if results:
        print_warning(
            "[!] These privileged accounts could have passwords cached on compromised RODCs!"
        )
        print_warning("[*] Add to 'Denied RODC Password Replication Group' to protect")
        print_table(
            ["Principal", "Type", "Domain", "AdminCount"],
            [[r["principal"], r["type"], r["domain"], r["admincount"]] for r in results],
        )

    return result_count
