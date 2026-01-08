"""WriteDACL/WriteOwner on Schema and Configuration Partitions"""

from __future__ import annotations

from typing import TYPE_CHECKING

from hackles.core.cypher import node_type
from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="Schema/Configuration Partition Control",
    category="ACL Abuse",
    default=True,
    severity=Severity.CRITICAL,
)
def get_schema_config_control(
    bh: BloodHoundCE, domain: str | None = None, severity: Severity = None
) -> int:
    """Find non-admin principals with WriteDACL/WriteOwner over Schema or Configuration partitions.

    Control over these critical AD partitions enables:
    - Schema modifications (add malicious attributes/classes)
    - Configuration partition changes (Sites, Subnets, ADCS objects)
    - Potential forest-wide compromise via schema attacks
    """
    domain_filter = "AND toUpper(m.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    # Look for control over Schema, Configuration containers, and critical AD objects
    query = f"""
    MATCH (n)-[r:WriteDacl|WriteOwner|GenericAll|Owns]->(m)
    WHERE (n.admincount IS NULL OR n.admincount = false)
    AND NOT n.objectid ENDS WITH '-512'  // Domain Admins
    AND NOT n.objectid ENDS WITH '-519'  // Enterprise Admins
    AND NOT n.objectid ENDS WITH '-544'  // Administrators
    AND NOT n.objectid ENDS WITH '-548'  // Account Operators
    AND NOT n.objectid ENDS WITH '-549'  // Server Operators
    AND NOT n.objectid ENDS WITH '-550'  // Print Operators
    AND NOT n.objectid ENDS WITH '-551'  // Backup Operators
    AND n.enabled <> false
    AND (
        m.name CONTAINS 'SCHEMA' OR
        m.name CONTAINS 'CONFIGURATION' OR
        m.name CONTAINS 'SITES' OR
        m.distinguishedname CONTAINS 'CN=Schema,CN=Configuration' OR
        m.distinguishedname CONTAINS 'CN=Configuration,DC=' OR
        m.distinguishedname CONTAINS 'CN=Sites,CN=Configuration' OR
        m.distinguishedname CONTAINS 'CN=Services,CN=Configuration'
    )
    AND NOT n.name STARTS WITH 'SYSTEM@'
    AND NOT n.name STARTS WITH 'LOCAL SERVICE@'
    AND NOT n.name STARTS WITH 'ENTERPRISE ADMINS@'
    AND NOT n.name STARTS WITH 'DOMAIN ADMINS@'
    AND NOT n.name STARTS WITH 'SCHEMA ADMINS@'
    {domain_filter}
    RETURN
        n.name AS principal,
        {node_type("n")} AS principal_type,
        type(r) AS permission,
        m.name AS target,
        {node_type("m")} AS target_type,
        COALESCE(m.distinguishedname, 'N/A') AS target_dn
    ORDER BY permission, n.name
    LIMIT 100
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Schema/Configuration Partition Control", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} principal(s) with control over critical AD partitions")

    if results:
        print_warning(
            "[!] CRITICAL: Control over Schema/Configuration enables forest-wide attacks!"
        )
        print_warning("    - Schema changes affect ALL domains in the forest")
        print_warning("    - Configuration controls Sites, Subnets, and PKI objects")
        print_warning("")

        # Categorize by partition type
        schema_count = sum(
            1
            for r in results
            if "SCHEMA" in r.get("target", "").upper() or "Schema" in r.get("target_dn", "")
        )
        config_count = sum(
            1
            for r in results
            if "CONFIGURATION" in r.get("target", "").upper()
            or "Configuration" in r.get("target_dn", "")
        )

        if schema_count > 0:
            print_warning(f"    [{schema_count}] Schema partition control - can modify AD schema!")
        if config_count > 0:
            print_warning(
                f"    [{config_count}] Configuration partition control - can modify forest config!"
            )

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
