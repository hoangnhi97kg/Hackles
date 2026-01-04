"""Trust SID Filtering Analysis"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


@register_query(
    name="Trust SID Filtering Analysis", category="Basic Info", default=True, severity=Severity.HIGH
)
def get_trust_sid_filtering(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Find domain trusts with SID filtering disabled (cross-domain escalation risk)"""
    query = """
    MATCH (d1:Domain)-[r:TrustedBy]->(d2:Domain)
    RETURN
        d1.name AS trusting_domain,
        d2.name AS trusted_domain,
        COALESCE(r.trusttype, 'Unknown') AS trust_type,
        COALESCE(r.sidfilteringenabled, true) AS sid_filtering,
        COALESCE(r.transitive, false) AS transitive,
        CASE WHEN r.sidfilteringenabled = false THEN 'VULNERABLE' ELSE 'Protected' END AS status
    ORDER BY r.sidfilteringenabled ASC, d1.name
    """
    results = bh.run_query(query)
    result_count = len(results)

    if not print_header("Trust SID Filtering Analysis", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} trust relationship(s)")

    if results:
        vulnerable_count = sum(1 for r in results if r.get("sid_filtering") == False)
        if vulnerable_count:
            print_warning(f"[!] {vulnerable_count} trust(s) have SID filtering DISABLED!")
            print_warning("    SID History attacks possible across these trusts!")
            print()
            print("    Exploitation: Create Golden Ticket with SID History from trusted domain")
            print(
                "    mimikatz # kerberos::golden /user:Administrator /domain:<CHILD> /sid:<CHILD_SID> /krbtgt:<HASH> /sids:<PARENT>-519 /ptt"
            )
            print()

        print_table(
            ["Trusting Domain", "Trusted Domain", "Type", "SID Filtering", "Transitive", "Status"],
            [
                [
                    r["trusting_domain"],
                    r["trusted_domain"],
                    r["trust_type"],
                    r["sid_filtering"],
                    r["transitive"],
                    r["status"],
                ]
                for r in results
            ],
        )

    return result_count
