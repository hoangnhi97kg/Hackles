"""Shared utility functions for hackles"""

from datetime import datetime
from typing import Any, Dict, List, Optional, Union


def format_timestamp(value: Union[int, float, None]) -> str:
    """Format a Unix timestamp to human-readable date string.

    Args:
        value: Unix timestamp (seconds since epoch) or None

    Returns:
        Formatted date string (YYYY-MM-DD) or "-" if invalid/None
    """
    if value is None:
        return "-"

    try:
        # Handle various timestamp formats from BloodHound
        ts = float(value)

        # Invalid or unset timestamps
        if ts <= 0 or ts == -1:
            return "Never"

        # BloodHound uses seconds since epoch
        # Sanity check: timestamps should be between 1970 and 2100
        if ts < 0 or ts > 4102444800:  # 2100-01-01
            return "-"

        dt = datetime.utcfromtimestamp(ts)
        return dt.strftime("%Y-%m-%d")
    except (ValueError, TypeError, OSError):
        return "-"


def is_unix_timestamp(value: Any) -> bool:
    """Check if a value looks like a Unix timestamp.

    Args:
        value: Any value to check

    Returns:
        True if value appears to be a Unix timestamp
    """
    if value is None:
        return False

    try:
        ts = float(value)
        # Valid range: 1990-01-01 to 2100-01-01
        # Excludes small numbers that might be counts or IDs
        return 631152000 < ts < 4102444800
    except (ValueError, TypeError):
        return False


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
