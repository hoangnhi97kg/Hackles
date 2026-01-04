"""Domain Functional Level Check"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from hackles.display.colors import Severity
from hackles.display.tables import print_header, print_subheader, print_table, print_warning
from hackles.queries.base import register_query

if TYPE_CHECKING:
    from hackles.core.bloodhound import BloodHoundCE


# Functional levels and their Windows Server equivalents
FUNCTIONAL_LEVELS = {
    0: "Windows 2000",
    1: "Windows Server 2003 Interim",
    2: "Windows Server 2003",
    3: "Windows Server 2008",
    4: "Windows Server 2008 R2",
    5: "Windows Server 2012",
    6: "Windows Server 2012 R2",
    7: "Windows Server 2016",
}

# Current recommended minimum
RECOMMENDED_LEVEL = 7  # Windows Server 2016


@register_query(
    name="Domain Functional Level", category="Basic Info", default=True, severity=Severity.INFO
)
def get_domain_functional_level(
    bh: BloodHoundCE, domain: Optional[str] = None, severity: Severity = None
) -> int:
    """Check domain functional level - outdated levels miss security features."""
    domain_filter = "WHERE toUpper(d.name) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    query = f"""
    MATCH (d:Domain)
    {domain_filter}
    RETURN
        d.name AS domain,
        d.functionallevel AS level
    ORDER BY d.name
    """
    results = bh.run_query(query, params)
    result_count = len(results)

    # Count outdated domains - handle string or int level values
    def parse_level(level):
        if level is None:
            return None
        if isinstance(level, int):
            return level
        # Handle string versions like "2016", "2012 R2", etc.
        level_str = str(level).upper()
        for lvl, name in FUNCTIONAL_LEVELS.items():
            if level_str in name.upper() or name.upper() in level_str:
                return lvl
        # Try parsing as integer
        try:
            return int(level)
        except (ValueError, TypeError):
            return None

    outdated = [
        r
        for r in results
        if parse_level(r.get("level")) is not None and parse_level(r["level"]) < RECOMMENDED_LEVEL
    ]
    outdated_count = len(outdated)

    if not print_header("Domain Functional Level", severity, result_count):
        return result_count
    print_subheader(f"Found {result_count} domain(s)")

    if results:
        # Add human-readable level names
        display_results = []
        for r in results:
            level = r.get("level")
            parsed = parse_level(level)
            level_name = (
                FUNCTIONAL_LEVELS.get(parsed, f"Unknown ({level})")
                if parsed is not None
                else str(level) if level else "Unknown"
            )
            is_outdated = parsed is not None and parsed < RECOMMENDED_LEVEL
            display_results.append(
                [
                    r["domain"],
                    level if level is not None else "N/A",
                    level_name,
                    "Yes" if is_outdated else "No",
                ]
            )

        if outdated_count > 0:
            print_warning(
                f"[!] {outdated_count} domain(s) below recommended level (Windows Server 2016)"
            )
            print_warning("[*] Outdated functional levels lack modern security features")

        print_table(["Domain", "Level", "Windows Version", "Outdated"], display_results)

    return result_count
