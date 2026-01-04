"""Shared utility functions for hackles"""

from typing import Dict, List, Optional


def extract_domain(results: List[Dict], domain: Optional[str] = None) -> Optional[str]:
    """Extract domain from query results or use provided domain.

    Searches through common field names in results to find a domain name.

    Args:
        results: List of query result dictionaries
        domain: Optional domain to use (returned if provided)

    Returns:
        Domain string or None if not found
    """
    if domain:
        return domain
    if not results:
        return None
    for r in results:
        for field in ["name", "principal", "user", "computer", "target"]:
            name = r.get(field, "")
            if name and "@" in name:
                return name.split("@")[-1]
    return None
