"""Azure sync account excessive privileges detection."""

from __future__ import annotations

from typing import TYPE_CHECKING

from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="Sync Account Excessive Privileges",
    category="Azure/Hybrid",
    default=True,
    severity=Severity.CRITICAL,
)
def get_sync_account_privesc(
    bh: BloodHoundCE, domain: str | None = None, severity: Severity = None
) -> int:
    """Find Azure sync accounts with privileges beyond DCSync.

    MSOL_*, AAD_*, and SYNC_* accounts should only have DCSync rights.
    Additional permissions like GenericAll, WriteDacl, or AdminTo indicate
    misconfiguration or compromise that expands the attack surface.
    """
    domain_filter = "AND toUpper(target.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (n)-[r]->(target)
    WHERE n.name =~ '(?i).*(MSOL_|AAD_|SYNC_|AZUREADSSOACC).*'
    AND NOT type(r) IN ['GetChanges', 'GetChangesAll', 'DCSync', 'MemberOf']
    AND type(r) IN ['GenericAll', 'GenericWrite', 'WriteDacl', 'WriteOwner',
                    'AdminTo', 'ForceChangePassword', 'AddMember', 'Owns']
    {domain_filter}
    RETURN n.name AS sync_account,
           type(r) AS permission,
           target.name AS target
    ORDER BY n.name, type(r)
    LIMIT 100
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Sync Account Excessive Privileges", severity, result_count):
        return result_count

    print_subheader(f"Found {result_count} excessive permission(s)")

    if results:
        print_warning("[!] CRITICAL: Sync accounts have more than DCSync rights!")
        print_warning(
            "    Compromise AADC server -> Use these extra permissions for lateral movement"
        )
        print_table(
            ["Sync Account", "Permission", "Target"],
            [[r["sync_account"], r["permission"], r["target"]] for r in results],
        )

    return result_count
