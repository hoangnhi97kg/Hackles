"""Unresolved SIDs with Outbound Control"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="Unresolved SIDs with Outbound Control",
    category="ACL Abuse",
    default=True,
    severity=Severity.MEDIUM,
)
def get_unresolved_sids(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Find ACL entries with unresolved SIDs that have outbound control.

    Unresolved SIDs in ACLs indicate deleted accounts that still have permissions.
    These orphaned permissions could be exploited if the SID is recreated or
    if the SID belongs to a deleted account from a trusted domain.
    """
    domain_filter = "AND toUpper(target.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    # Look for principals that only have a SID-like name (S-1-5-21-...)
    # and have outbound dangerous edges
    query = f"""
    MATCH (n)-[r]->(target)
    WHERE n.name STARTS WITH 'S-1-'
    AND type(r) IN ['GenericAll', 'GenericWrite', 'WriteDacl', 'WriteOwner', 'Owns', 'ForceChangePassword', 'AddMember', 'AllExtendedRights', 'AddSelf']
    {domain_filter}
    RETURN DISTINCT
        n.name AS unresolved_sid,
        n.objectid AS sid,
        type(r) AS permission,
        target.name AS target,
        CASE WHEN target:User THEN 'User' WHEN target:Group THEN 'Group' WHEN target:Computer THEN 'Computer' WHEN target:Domain THEN 'Domain' ELSE 'Other' END AS target_type
    ORDER BY type(r), target.name
    LIMIT 100
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Unresolved SIDs with Outbound Control", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} unresolved SID(s) with dangerous permissions")

    if results:
        print_warning("[!] Orphaned SIDs with permissions = potential security risk")
        print_warning("[*] These may be deleted accounts with residual permissions")
        print_warning("[*] Review and remove unnecessary ACL entries")
        print_table(
            ["Unresolved SID", "Permission", "Target", "Target Type"],
            [
                [
                    (
                        r["unresolved_sid"][:40] + "..."
                        if len(r["unresolved_sid"]) > 40
                        else r["unresolved_sid"]
                    ),
                    r["permission"],
                    r["target"],
                    r["target_type"],
                ]
                for r in results
            ],
        )

    return result_count
