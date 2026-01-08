"""Plaintext userPassword Attribute"""

from __future__ import annotations

from typing import TYPE_CHECKING

from hackles.core.cypher import node_type
from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="Plaintext userPassword Attribute",
    category="Privilege Escalation",
    default=True,
    severity=Severity.CRITICAL,
)
def get_userpassword_attribute(
    bh: BloodHoundCE, domain: str | None = None, severity: Severity = None
) -> int:
    """Plaintext passwords in LDAP userPassword attribute"""
    domain_filter = "AND toUpper(n.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (n)
    WHERE n.userpassword IS NOT NULL
    AND n.userpassword <> ''
    AND trim(n.userpassword) <> ''
    {domain_filter}
    RETURN n.name AS name, {node_type("n")} AS type, n.userpassword AS password
    """
    results = bh.run_query(query, params)
    # Additional Python-side filtering for empty/whitespace-only passwords
    results = [r for r in results if r.get("password") and str(r["password"]).strip()]
    result_count = len(results)

    if not print_header("Plaintext Passwords (userPassword)", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} object(s) with userPassword attribute")

    if results:
        print_warning("[!] Plaintext or base64-encoded passwords in LDAP!")
        print_table(
            ["Name", "Type", "Password"], [[r["name"], r["type"], r["password"]] for r in results]
        )

    return result_count
