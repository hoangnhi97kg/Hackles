"""GPOs on DC OU"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from hackles.abuse.printer import print_abuse_info
from hackles.core.utils import extract_domain
from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(name="GPOs on DC OU", category="ACL Abuse", default=True, severity=Severity.HIGH)
def get_gpos_dc_ou(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Find GPOs linked to Domain Controllers OU"""
    domain_filter = "AND toUpper(ou.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (gpo:GPO)-[:GpLink]->(ou)
    WHERE toUpper(ou.name) CONTAINS 'DOMAIN CONTROLLERS'
    OR toUpper(ou.distinguishedname) CONTAINS 'OU=DOMAIN CONTROLLERS'
    {domain_filter}
    OPTIONAL MATCH (controller)-[r]->(gpo)
    WHERE r.isacl = true AND type(r) IN ['GenericAll', 'WriteDacl', 'WriteOwner', 'Owns', 'GenericWrite']
    WITH gpo, ou, COLLECT(DISTINCT controller.name) AS all_controllers
    RETURN
        gpo.name AS gpo_name,
        ou.name AS linked_to,
        all_controllers[0..3] AS controllers,
        size(all_controllers) AS controller_count,
        gpo.gpcpath AS gpo_path
    ORDER BY gpo.name
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("GPOs on DC OU", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} GPO(s) linked to Domain Controllers OU")

    if results:
        print_warning("[!] GPOs affecting DCs are high-value targets for persistence!")

        def format_controllers(r):
            """Format controllers with count if truncated."""
            controllers = r.get("controllers", [])
            total = r.get("controller_count", 0)
            if total > 3:
                return ", ".join(controllers) + f" (+{total - 3} more)"
            elif controllers:
                return ", ".join(controllers)
            return "None"

        print_table(
            ["GPO Name", "Linked To", "Controllers", "GPO Path"],
            [
                [r["gpo_name"], r["linked_to"], format_controllers(r), r["gpo_path"]]
                for r in results
            ],
        )
        print_abuse_info("GPOAbuse", results, extract_domain(results, domain))

    return result_count
