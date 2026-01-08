"""Dangerous ACL Relationships"""

from __future__ import annotations

from typing import TYPE_CHECKING

from hackles.core.cypher import node_type
from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="Dangerous ACL Relationships", category="ACL Abuse", default=True, severity=Severity.HIGH
)
def get_acl_abuse(bh: BloodHoundCE, domain: str | None = None, severity: Severity = None) -> int:
    """Get dangerous ACL relationships"""
    print_warning("This query may take a while on large datasets...")

    domain_filter = "AND toUpper(m.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    # Query for dangerous ACL edges
    # Excludes admin groups by admincount AND by well-known RIDs
    query = f"""
    MATCH (n)-[r]->(m)
    WHERE type(r) IN ['GenericAll', 'WriteDacl', 'WriteOwner', 'GenericWrite',
                       'ForceChangePassword', 'AddMember', 'AllExtendedRights',
                       'AddSelf', 'WriteSPN', 'AddKeyCredentialLink']
    AND (n.admincount IS NULL OR n.admincount = false)
    AND NOT n.objectid ENDS WITH '-512'  // Domain Admins
    AND NOT n.objectid ENDS WITH '-519'  // Enterprise Admins
    AND NOT n.objectid ENDS WITH '-544'  // Administrators
    AND NOT n.objectid ENDS WITH '-548'  // Account Operators
    AND NOT n.objectid ENDS WITH '-549'  // Server Operators
    AND NOT n.objectid ENDS WITH '-550'  // Print Operators
    AND NOT n.objectid ENDS WITH '-551'  // Backup Operators
    {domain_filter}
    RETURN
        n.name AS principal,
        {node_type("n")} AS principal_type,
        type(r) AS permission,
        m.name AS target,
        {node_type("m")} AS target_type
    ORDER BY type(r), n.name
    LIMIT 500
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Dangerous ACL Relationships", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} dangerous ACL relationship(s) (limit 500)")

    if results:
        print_table(
            ["Principal", "Type", "Permission", "Target", "Target Type"],
            [
                [
                    r["principal"],
                    r["principal_type"],
                    r["permission"],
                    r["target"],
                    r["target_type"],
                ]
                for r in results
            ],
        )

    return result_count
