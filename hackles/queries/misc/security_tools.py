"""Security Tools Detection"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from hackles.core.cypher import node_type
from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="Security Tools Detection", category="Miscellaneous", default=False, severity=Severity.INFO
)
def get_security_tools(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Security tools detected via naming conventions"""
    domain_filter = "AND toUpper(n.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    UNWIND ['crowdstrike', 'carbonblack', 'sentinel', 'defender', 'sophos', 'symantec',
            'mcafee', 'cylance', 'fireeye', 'splunk', 'cyberark', 'tanium'] AS tool
    MATCH (n)
    WHERE toLower(n.name) CONTAINS tool OR toLower(COALESCE(n.description, '')) CONTAINS tool
    {domain_filter}
    RETURN tool AS security_tool, {node_type('n')} AS type, n.name AS name
    ORDER BY tool, {node_type('n')}
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    if not print_header("Security Tools Detection", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} security tool reference(s)")

    if results:
        print_table(
            ["Security Tool", "Type", "Name"],
            [[r["security_tool"], r["type"], r["name"]] for r in results],
        )

    return result_count
