"""Abuse command display functions"""
import re
from typing import List, Dict, Any, Optional
from hackles.display.colors import Colors
from hackles.core.utils import extract_domain


def get_abuse_info(attack_type: str) -> Optional[Dict[str, Any]]:
    """Get abuse info for a specific attack type.

    Args:
        attack_type: Name of the attack (e.g., "Kerberoasting")

    Returns:
        Abuse info dict or None if not found
    """
    from hackles.abuse.loader import get_abuse_template
    return get_abuse_template(attack_type)


def _build_context_from_result(result: Dict, domain: Optional[str] = None) -> Dict[str, str]:
    """Build a placeholder context dictionary from a query result.

    Maps common query result fields to template placeholders.

    Args:
        result: Single query result dictionary
        domain: Domain name

    Returns:
        Context dictionary for placeholder substitution
    """
    context = {}

    # Domain
    if domain:
        context['DOMAIN'] = domain

    # Extract username part from name@domain format
    def get_username(value: str) -> str:
        if value and '@' in value:
            return value.split('@')[0]
        return value or ''

    def get_value(value: Any) -> str:
        """Extract string value from scalar or list, handling None."""
        if value is None:
            return ''
        if isinstance(value, list):
            return value[0] if value else ''
        return str(value)

    # Target user - from 'name' or 'target' fields (the victim/target)
    if result.get('name'):
        context['TARGET_USER'] = get_username(result['name'])
        context['TARGET'] = get_username(result['name'])
    if result.get('target'):
        target_val = get_username(get_value(result['target']))
        context['TARGET'] = target_val
        context['TARGET_USER'] = target_val
        context['TARGET_COMPUTER'] = target_val

    # Group target - when target is a group, also set GROUP placeholder
    target_type = result.get('target_type', '').lower() if result.get('target_type') else ''
    if target_type == 'group' and result.get('target'):
        context['GROUP'] = get_username(get_value(result['target']))
    elif result.get('group'):
        context['GROUP'] = get_username(result['group'])

    # Computer target with $ suffix for RBCD attacks
    if target_type == 'computer' and result.get('target'):
        target_name = get_username(get_value(result['target']))
        if not target_name.endswith('$'):
            context['TARGET$'] = target_name + '$'
        else:
            context['TARGET$'] = target_name

    # Principal - the attacker's compromised account
    if result.get('principal'):
        principal = get_username(result['principal'])
        context['USER'] = principal
        context['YOUR_USER'] = principal

    # Computer targets (for lateral movement abuse templates)
    if result.get('computer'):
        computer_name = get_username(result['computer'])
        context['COMPUTER'] = computer_name
        context['TARGET_COMPUTER'] = computer_name
        # Also set TARGET for lateral movement templates (WinRM, RDP, etc.)
        if 'TARGET' not in context:
            context['TARGET'] = computer_name

    # SPN targets (constrained delegation)
    if result.get('targets'):
        targets = result['targets']
        if isinstance(targets, list) and targets:
            context['TARGET_SPN'] = targets[0]
        elif isinstance(targets, str):
            context['TARGET_SPN'] = targets

    # Certificate Authority
    if result.get('ca'):
        context['CA_NAME'] = result['ca']
        context['CA'] = result['ca']

    # GPO name
    if result.get('gpo_name'):
        context['GPO_NAME'] = result['gpo_name']

    # gMSA account
    if result.get('gmsa'):
        context['GMSA_NAME'] = get_username(result['gmsa'])
    if result.get('gmsa_account'):
        context['GMSA_NAME'] = get_username(result['gmsa_account'])

    # SQL Server
    if result.get('sql_server'):
        context['SQL_SERVER'] = get_username(result['sql_server'])

    # Template name (ADCS)
    if result.get('template'):
        context['TEMPLATE'] = result['template']

    return context


def _highlight_placeholders(command: str) -> str:
    """Highlight remaining placeholders in yellow."""
    return re.sub(r'(<[A-Z_]+>)', f'{Colors.WARNING}\\1{Colors.END}', command)


def _has_placeholders(command: str) -> bool:
    """Check if command still has unfilled placeholders."""
    return bool(re.search(r'<[A-Z_]+>', command))


def print_abuse_info(attack_type: str, results: List[Dict] = None, domain: Optional[str] = None) -> None:
    """Print abuse commands for a specific attack type.

    Shows two sections:
    1. Commands - Generic templates with placeholders highlighted
    2. Ready-to-Paste - Commands with values filled in from query results

    Args:
        attack_type: Name of the attack (e.g., "Kerberoasting")
        results: Query results to extract context from
        domain: Domain name for template substitution
    """
    from hackles.core.config import config
    from hackles.abuse.loader import load_abuse_templates, ABUSE_INFO

    # Don't print abuse info if disabled or in non-table output mode
    if not config.show_abuse or config.output_format != 'table':
        return

    # Ensure templates are loaded
    load_abuse_templates()

    info = ABUSE_INFO.get(attack_type)
    if not info:
        return

    # Extract domain from results if not provided
    if not domain and results:
        domain = _extract_domain(results)

    # Build context from first result (if available)
    context = {}
    if domain:
        context['DOMAIN'] = domain
    if results and len(results) > 0:
        context.update(_build_context_from_result(results[0], domain))

    # Merge user-provided abuse vars (override auto-detected values)
    context.update(config.abuse_vars)

    # Sync PASSWORD and YOUR_PASSWORD aliases (templates use both interchangeably)
    if 'YOUR_PASSWORD' in context and 'PASSWORD' not in context:
        context['PASSWORD'] = context['YOUR_PASSWORD']
    elif 'PASSWORD' in context and 'YOUR_PASSWORD' not in context:
        context['YOUR_PASSWORD'] = context['PASSWORD']

    # Get target info for header
    target_name = None
    if results and len(results) > 0:
        r = results[0]
        target_name = r.get('name') or r.get('target') or r.get('principal') or r.get('computer')

    print(f"\n    {Colors.CYAN}{Colors.BOLD}[Abuse Info]{Colors.END}")

    if info.get('description'):
        print(f"    {Colors.WHITE}{info['description']}{Colors.END}")

    if target_name:
        print(f"    {Colors.CYAN}Target:{Colors.END} {Colors.BOLD}{target_name}{Colors.END}")

    if info.get('commands'):
        # Section 1: Generic Commands (templates)
        print(f"\n    {Colors.BLUE}{Colors.BOLD}Commands:{Colors.END}")
        for cmd in info['commands']:
            if not cmd:  # Empty line
                print()
                continue

            cmd_str = str(cmd)

            # Comments get green color
            if cmd_str.strip().startswith('#'):
                print(f"      {Colors.GREEN}{cmd_str}{Colors.END}")
            else:
                # Show template with placeholders highlighted in yellow
                highlighted = _highlight_placeholders(cmd_str)
                print(f"      {highlighted}")

        # Section 2: Ready-to-Paste Commands (with values filled in)
        # Only show if we have context to fill in
        if context:
            # Build list of commands that can be filled in first
            ready_commands = []
            for cmd in info['commands']:
                if not cmd:
                    continue

                cmd_str = str(cmd)

                # Skip comments
                if cmd_str.strip().startswith('#'):
                    continue

                # Fill in placeholders
                filled = _fill_command_placeholders(cmd_str, context)

                # Only include if different from template (something was filled in)
                if filled != cmd_str or not _has_placeholders(filled):
                    # Highlight any remaining placeholders in the filled command
                    if _has_placeholders(filled):
                        filled = _highlight_placeholders(filled)
                    ready_commands.append(filled)

            # Only print header if we have commands to show
            if ready_commands:
                print(f"\n    {Colors.GREEN}{Colors.BOLD}Ready-to-Paste:{Colors.END}")
                for filled in ready_commands:
                    print(f"      {Colors.WHITE}{filled}{Colors.END}")

    # Show all targets if multiple results
    if results and len(results) > 1:
        print(f"\n    {Colors.CYAN}{Colors.BOLD}All Targets ({len(results)}):{Colors.END}")
        for r in results[:10]:  # Limit to first 10
            target = r.get('name') or r.get('target') or r.get('principal') or r.get('computer')
            if target:
                print(f"      {Colors.WHITE}- {target}{Colors.END}")
        if len(results) > 10:
            print(f"      {Colors.GRAY}... and {len(results) - 10} more{Colors.END}")

    if info.get('opsec'):
        print(f"\n    {Colors.WARNING}{Colors.BOLD}OPSEC:{Colors.END}")
        for note in info['opsec']:
            print(f"      {Colors.WARNING}- {note}{Colors.END}")

    if info.get('references'):
        print(f"\n    {Colors.BLUE}References:{Colors.END}")
        for ref in info['references']:
            print(f"      {Colors.GRAY}- {ref}{Colors.END}")


# Alias for backwards compatibility with any code importing from here
_extract_domain = extract_domain


def _fill_command_placeholders(command: str, context: Dict[str, str]) -> str:
    """Fill in command template placeholders with actual values.

    Args:
        command: Command string with <PLACEHOLDER> markers
        context: Dictionary of placeholder values

    Returns:
        Command with placeholders replaced
    """
    result = command
    for placeholder, value in context.items():
        result = result.replace(f'<{placeholder}>', value)
    return result
