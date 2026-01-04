"""Dangerous ACL Relationships"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from hackles.abuse.printer import print_abuse_info
from hackles.core.cypher import node_type
from hackles.core.utils import extract_domain
from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="Dangerous ACL Relationships", category="ACL Abuse", default=True, severity=Severity.HIGH
)
def get_acl_abuse(bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None) -> int:
    """Get dangerous ACL relationships"""
    print_warning("This query may take a while on large datasets...")

    domain_filter = "AND toUpper(m.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    # Query for dangerous ACL edges
    query = f"""
    MATCH (n)-[r]->(m)
    WHERE type(r) IN ['GenericAll', 'WriteDacl', 'WriteOwner', 'GenericWrite',
                       'ForceChangePassword', 'AddMember', 'AllExtendedRights',
                       'AddSelf', 'WriteSPN', 'AddKeyCredentialLink']
    AND (n.admincount IS NULL OR n.admincount = false)
    {domain_filter}
    RETURN
        n.name AS principal,
        {node_type('n')} AS principal_type,
        type(r) AS permission,
        m.name AS target,
        {node_type('m')} AS target_type
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

        # Print abuse info for each unique permission type found
        unique_permissions = set(r["permission"] for r in results)
        extracted_domain = extract_domain(results, domain)
        for perm in sorted(unique_permissions):
            # Filter findings for this specific permission type
            perm_findings = [r for r in results if r["permission"] == perm]
            print_abuse_info(perm, perm_findings, extracted_domain)

    return result_count
