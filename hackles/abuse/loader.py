"""YAML abuse template loader"""

import sys
from pathlib import Path
from typing import Any, Dict, Optional

# Global abuse info dictionary - populated by load_abuse_templates()
ABUSE_INFO: Dict[str, Any] = {}
_loaded = False


def load_abuse_templates(templates_dir: Optional[Path] = None) -> Dict[str, Any]:
    """Load abuse templates from YAML files in templates directory.

    Args:
        templates_dir: Path to templates directory. Defaults to abuse/templates/

    Returns:
        Dictionary of abuse templates keyed by attack name
    """
    global ABUSE_INFO, _loaded

    # Return cached templates if already loaded
    if _loaded and ABUSE_INFO:
        return ABUSE_INFO

    if templates_dir is None:
        templates_dir = Path(__file__).parent / "templates"

    if not templates_dir.exists():
        return ABUSE_INFO

    try:
        import yaml
    except ImportError:
        print("[!] Warning: pyyaml not installed - abuse templates disabled", file=sys.stderr)
        print("    Install with: pip install pyyaml", file=sys.stderr)
        return ABUSE_INFO

    for yaml_file in sorted(templates_dir.glob("*.yml")):
        try:
            with open(yaml_file, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
                if data and "name" in data:
                    # Validate required fields
                    if "commands" not in data or not data["commands"]:
                        print(
                            f"[!] Warning: {yaml_file.name} missing 'commands' field",
                            file=sys.stderr,
                        )
                        continue
                    # Store by name for lookup
                    ABUSE_INFO[data["name"]] = {
                        "description": data.get("description", ""),
                        "commands": data.get("commands", []),
                        "opsec": data.get("opsec", []),
                        "references": data.get("references", []),
                    }
        except Exception as e:
            # Log malformed files to stderr
            print(f"[!] Warning: Failed to load {yaml_file.name}: {e}", file=sys.stderr)

    _loaded = True  # Only mark loaded after successful completion
    return ABUSE_INFO


def get_abuse_template(attack_type: str) -> Optional[Dict[str, Any]]:
    """Get a specific abuse template by name.

    Args:
        attack_type: Name of the attack (e.g., "Kerberoasting")

    Returns:
        Abuse template dict or None if not found
    """
    # Ensure templates are loaded
    if not _loaded:
        load_abuse_templates()

    return ABUSE_INFO.get(attack_type)


def list_abuse_templates() -> list:
    """List all available abuse template names.

    Returns:
        Sorted list of template names
    """
    if not _loaded:
        load_abuse_templates()

    return sorted(ABUSE_INFO.keys())
