"""Non-Tier Zero Principals Controlling AdminSDHolder"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from hackles.core.utils import extract_domain
from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="Non-Tier Zero AdminSDHolder Controllers",
    category="Security Hygiene",
    default=True,
    severity=Severity.CRITICAL,
)
def get_adminsdholder_controllers(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Find non-Tier Zero principals with control over AdminSDHolder.

    AdminSDHolder is a critical container that propagates permissions to all
    protected accounts (Domain Admins, Enterprise Admins, etc.) every 60 minutes.
    Non-privileged accounts with write access can backdoor all protected accounts.
    """
    domain_filter = "AND toUpper(n.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    # Find principals with dangerous rights to AdminSDHolder container
    # that are NOT Tier Zero themselves
    query = f"""
    MATCH (adminsdholder:Container)
    WHERE adminsdholder.name STARTS WITH 'ADMINSDHOLDER@'
    MATCH (n)-[r]->(adminsdholder)
    WHERE type(r) IN ['GenericAll', 'GenericWrite', 'WriteDacl', 'WriteOwner', 'Owns', 'AllExtendedRights']
    AND NOT n:Tag_Tier_Zero
    AND NOT n.objectid ENDS WITH '-512'
    AND NOT n.objectid ENDS WITH '-519'
    AND NOT n.objectid ENDS WITH '-544'
    {domain_filter}
    RETURN DISTINCT
        n.name AS principal,
        CASE WHEN n:User THEN 'User' WHEN n:Group THEN 'Group' WHEN n:Computer THEN 'Computer' ELSE 'Other' END AS type,
        type(r) AS permission,
        n.domain AS domain
    ORDER BY type(r), n.name
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Non-Tier Zero AdminSDHolder Controllers", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} non-Tier Zero principal(s) with AdminSDHolder control")

    if results:
        print_warning("[!] CRITICAL: These accounts can backdoor ALL protected accounts!")
        print_warning("[*] AdminSDHolder propagates ACLs to Domain Admins, Enterprise Admins, etc.")
        print_warning("[*] Remove unnecessary permissions immediately")
        print_table(
            ["Principal", "Type", "Permission", "Domain"],
            [[r["principal"], r["type"], r["permission"], r["domain"]] for r in results],
        )

    return result_count
