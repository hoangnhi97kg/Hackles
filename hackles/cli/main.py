"""Main entry point for Hackles CLI"""
import csv
import json
import sys
import time
from pathlib import Path
from typing import List, Dict, Any, Tuple, Optional

from hackles.cli.parser import create_parser
from hackles.cli.completion import setup_completion
from hackles.core.config import config
from hackles.core.bloodhound import BloodHoundCE
from hackles.display.banner import print_banner
from hackles.display.colors import Colors, Severity
from hackles.display.tables import (
    print_header, print_subheader, print_table, print_warning,
    print_node_info, print_severity_summary
)
from hackles.display.paths import print_path
from hackles.queries import get_query_registry

# Mapping of CLI flags to category names in the registry
CATEGORY_FLAGS = {
    'acl': 'ACL Abuse',
    'adcs': 'ADCS',
    'attack_paths': 'Attack Paths',
    'azure': 'Azure/Hybrid',
    'basic': 'Basic Info',
    'groups': 'Dangerous Groups',
    'delegation': 'Delegation',
    'exchange': 'Exchange',
    'lateral': 'Lateral Movement',
    'misc': 'Miscellaneous',
    'owned_queries': 'Owned',
    'privesc': 'Privilege Escalation',
    'hygiene': 'Security Hygiene',
}

# Import specific query functions for quick filters
from hackles.queries.credentials.kerberoastable import get_kerberoastable
from hackles.queries.credentials.asrep_roastable import get_asrep_roastable
from hackles.queries.delegation.unconstrained_delegation import get_unconstrained_delegation
from hackles.queries.hygiene.computers_without_laps import get_computers_without_laps
from hackles.queries.owned.owned_principals import get_owned_principals
from hackles.queries.domain.high_value_targets import get_high_value_targets
from hackles.queries.domain.domain_stats import get_domain_stats


def init_owned_cache(bh: BloodHoundCE) -> None:
    """Initialize the owned principals cache with admin status."""
    query = """
    MATCH (n)
    WHERE (n:Tag_Owned OR 'owned' IN n.system_tags OR n.owned = true)
    RETURN n.name AS name,
           COALESCE(n.admincount, false) AS is_admin
    """
    try:
        results = bh.run_query(query)
        config.owned_cache = {r["name"]: r["is_admin"] for r in results if r.get("name")}
    except Exception as e:
        if config.debug_mode:
            print(f"{Colors.WARNING}[!] Warning: Could not initialize owned cache: {e}{Colors.END}")
        config.owned_cache = {}


def list_domains(bh: BloodHoundCE) -> None:
    """List all domains in the database."""
    print_header("Domains")
    domains = bh.get_domains()
    print_subheader(f"Found {len(domains)} domain(s)")

    if domains:
        print_table(
            ["Domain", "Functional Level", "SID"],
            [[d["name"], d["level"], d["objectid"]] for d in domains]
        )


def load_custom_queries(path_str: str):
    """Load custom .cypher queries from file or directory.

    Supports parsing metadata from comment headers:
        # Query description goes here
        # severity: HIGH
        MATCH (n) RETURN n

    Valid severity values: CRITICAL, HIGH, MEDIUM, LOW, INFO
    """
    import re
    path = Path(path_str)
    queries = []

    if path.is_file() and path.suffix == '.cypher':
        with open(path, 'r', encoding='utf-8') as f:
            content = f.read()
        name = path.stem.replace('_', ' ').title()

        # Extract metadata from comments
        lines = content.split('\n')
        desc_lines = []
        severity = Severity.MEDIUM  # Default severity
        severity_map = {
            'CRITICAL': Severity.CRITICAL,
            'HIGH': Severity.HIGH,
            'MEDIUM': Severity.MEDIUM,
            'LOW': Severity.LOW,
            'INFO': Severity.INFO,
        }

        for line in lines:
            stripped = line.strip()
            if stripped.startswith('#'):
                comment = stripped.lstrip('#').strip()
                # Check for severity directive
                if comment.lower().startswith('severity:'):
                    sev_value = comment.split(':', 1)[1].strip().upper()
                    if sev_value in severity_map:
                        severity = severity_map[sev_value]
                else:
                    desc_lines.append(comment)
            else:
                break

        if desc_lines:
            name = ' '.join(desc_lines)

        # Strip comment lines from cypher content (Neo4j doesn't support # comments)
        cypher_lines = [line for line in lines if not line.strip().startswith('#')]
        cypher = '\n'.join(cypher_lines).strip()

        # Parse RETURN columns
        aliases = re.findall(r'\bAS\s+(\w+)', cypher, re.IGNORECASE)
        columns = aliases if aliases else ['result']

        def make_query_func(query_text, cols):
            def query_func(bh, domain=None, severity=None):
                results = bh.run_query(query_text)
                result_count = len(results)
                if not print_header(name, severity, result_count):
                    return result_count
                print_subheader(f"Found {result_count} result(s)")
                if results:
                    print_table(cols, [[r.get(c, '') for c in cols] for r in results])
                return result_count
            return query_func

        queries.append((name, make_query_func(cypher, columns), "Custom", True, severity))

    elif path.is_dir():
        for cypher_file in path.glob("*.cypher"):
            queries.extend(load_custom_queries(str(cypher_file)))

    return queries


def output_json(results: List[Dict[str, Any]]) -> None:
    """Output results as JSON."""
    # Convert Severity enum to string
    output = []
    for r in results:
        output.append({
            'query': r['query'],
            'severity': r['severity'],
            'count': r['count'],
            'results': r.get('results', [])
        })
    print(json.dumps(output, indent=2, default=str))


def output_csv(results: List[Dict[str, Any]]) -> None:
    """Output results as CSV."""
    writer = csv.writer(sys.stdout)

    # Write header
    writer.writerow(['Query', 'Severity', 'Count', 'Data'])

    for r in results:
        result_data = r.get('results', [])
        if result_data:
            for row in result_data:
                # Flatten row data, handling None values
                row_str = '; '.join(f"{k}={v if v is not None else ''}" for k, v in row.items())
                writer.writerow([r['query'], r['severity'], r['count'], row_str])
        else:
            writer.writerow([r['query'], r['severity'], r['count'], ''])


def main():
    """Main entry point for hackles CLI."""
    parser = create_parser()
    setup_completion(parser)  # Enable shell completion
    args = parser.parse_args()

    # Set config from args
    config.quiet_mode = args.quiet
    config.show_abuse = args.abuse
    config.debug_mode = args.debug
    config.no_color = args.no_color or not sys.stdout.isatty()
    config.show_progress = args.progress

    # Set output format
    if args.json:
        config.output_format = 'json'
        config.quiet_mode = True  # Suppress normal output
    elif args.csv:
        config.output_format = 'csv'
        config.quiet_mode = True
    elif args.html:
        config.output_format = 'html'
    else:
        config.output_format = 'table'

    # Parse severity filter
    if args.severity:
        severity_names = [s.strip().upper() for s in args.severity.split(',')]
        valid_severities = {'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'}
        config.severity_filter = {s for s in severity_names if s in valid_severities}
        if not config.severity_filter:
            print(f"{Colors.WARNING}[!] No valid severity levels provided. Valid: CRITICAL,HIGH,MEDIUM,LOW,INFO{Colors.END}")
            sys.exit(1)

    # Set user input enhancement config
    if args.from_owned:
        config.from_owned = args.from_owned
    if args.stale_days:
        config.stale_days = args.stale_days
    if args.max_path_depth:
        config.max_path_depth = args.max_path_depth
    if args.max_paths:
        config.max_paths = args.max_paths

    # Load abuse variables from config file first (can be overridden by CLI)
    default_abuse_config = Path.home() / '.hackles' / 'abuse.conf'
    if args.abuse_config:
        config.load_abuse_config(Path(args.abuse_config))
    elif default_abuse_config.exists():
        config.load_abuse_config(default_abuse_config)

    # CLI abuse vars override config file values
    if args.abuse_var:
        for var in args.abuse_var:
            if '=' in var:
                key, value = var.split('=', 1)
                config.abuse_vars[key.strip()] = value.strip()
            else:
                print(f"{Colors.WARNING}[!] Invalid --abuse-var format: {var} (expected KEY=VALUE){Colors.END}")

    # Helper to check if we should print status messages
    def status_print(msg: str) -> None:
        """Print status message only in table output mode."""
        if config.output_format == 'table':
            print(msg)

    if not config.quiet_mode:
        print_banner()

    status_print(f"\n{Colors.BLUE}[*] Connecting to {args.bolt}...{Colors.END}")
    bh = BloodHoundCE(args.bolt, args.username, args.password, args.debug)

    if not bh.connect():
        sys.exit(1)

    status_print(f"{Colors.GREEN}[+] Connected successfully{Colors.END}")

    # Handle ownership marking
    if args.own:
        for principal in args.own:
            if bh.mark_owned(principal):
                status_print(f"{Colors.GREEN}[+] Marked as owned: {principal}{Colors.END}")
            else:
                status_print(f"{Colors.WARNING}[!] Principal not found: {principal}{Colors.END}")

    if args.unown:
        if bh.unmark_owned(args.unown):
            status_print(f"{Colors.GREEN}[+] Removed owned status: {args.unown}{Colors.END}")
        else:
            status_print(f"{Colors.WARNING}[!] Principal not found: {args.unown}{Colors.END}")

    # Initialize owned cache
    init_owned_cache(bh)
    if config.owned_cache:
        status_print(f"{Colors.BLUE}[*] Found {len(config.owned_cache)} owned principal(s){Colors.END}")

    try:
        # === CLEAR OWNED (early exit) ===
        if args.clear_owned:
            count = bh.clear_all_owned()
            status_print(f"{Colors.GREEN}[+] Removed owned status from {count} principal(s){Colors.END}")
            init_owned_cache(bh)
            status_print(f"{Colors.BLUE}[*] Owned cache now has {len(config.owned_cache)} principal(s){Colors.END}")
            return

        # === TIER ZERO MARKING ===
        if args.tier_zero:
            for principal in args.tier_zero:
                if bh.mark_tier_zero(principal):
                    status_print(f"{Colors.GREEN}[+] Marked as Tier Zero: {principal}{Colors.END}")
                else:
                    status_print(f"{Colors.WARNING}[!] Principal not found: {principal}{Colors.END}")

        if args.untier_zero:
            if bh.unmark_tier_zero(args.untier_zero):
                status_print(f"{Colors.GREEN}[+] Removed Tier Zero status: {args.untier_zero}{Colors.END}")
            else:
                status_print(f"{Colors.WARNING}[!] Principal not found: {args.untier_zero}{Colors.END}")

        # Show tier zero and exit if no -a flag
        if (args.tier_zero or args.untier_zero) and not args.all:
            get_high_value_targets(bh, args.domain, Severity.INFO)
            return

        # List domains only
        if args.list:
            list_domains(bh)
            return

        # === STATS (early exit) ===
        if args.stats:
            get_domain_stats(bh, args.domain, Severity.INFO)
            return

        # If only marking ownership (no -a flag), show owned principals and exit
        if (args.own or args.unown) and not args.all:
            get_owned_principals(bh, args.domain, Severity.INFO)
            return

        # === NODE INFO (early exit) ===
        if args.info:
            print_header(f"Node Information: {args.info}")
            node_props = bh.get_node_info(args.info)
            if node_props:
                print_node_info(node_props)
            else:
                print_warning(f"Node not found: {args.info}")
            return

        # === NODE SEARCH (early exit) ===
        if args.search:
            print_header(f"Search Results: {args.search}")
            results = bh.search_nodes(args.search)
            if results:
                print_subheader(f"Found {len(results)} match(es)")
                print_table(
                    ["Name", "Type", "Enabled", "Domain"],
                    [[r["name"], r["type"], r["enabled"], r["domain"]] for r in results]
                )
            else:
                print_warning(f"No nodes matching: {args.search}")
            return

        # === PATH FINDING (early exit) ===
        if args.path:
            source, target = args.path
            print_header(f"Shortest Path: {source} -> {target}")
            paths = bh.find_shortest_path(source, target)
            if paths:
                for path in paths:
                    print_path(path)
            else:
                print_warning("No path found between nodes")
            return

        if args.path_to_da:
            print_header(f"Shortest Path to Domain Admin: {args.path_to_da}")
            paths = bh.find_path_to_da(args.path_to_da)
            if paths:
                for path in paths:
                    print_path(path)
            else:
                print_warning("No path to Domain Admin found")
            return

        if args.path_to_dc:
            print_header(f"Shortest Path to Domain Controller: {args.path_to_dc}")
            paths = bh.find_path_to_dc(args.path_to_dc)
            if paths:
                for path in paths:
                    print_path(path)
            else:
                print_warning("No path to Domain Controller found")
            return

        # === GROUP MEMBERS (early exit) ===
        if args.members:
            print_header(f"Group Members: {args.members}")
            results = bh.get_group_members(args.members)
            if results:
                print_subheader(f"Found {len(results)} member(s)")
                print_table(
                    ["Member", "Type", "Enabled"],
                    [[r["member"], r["type"], r["enabled"]] for r in results]
                )
            else:
                print_warning(f"Group not found or has no members: {args.members}")
            return

        # === MEMBER OF (early exit) ===
        if args.memberof:
            print_header(f"Group Memberships: {args.memberof}")
            results = bh.get_member_of(args.memberof)
            if results:
                print_subheader(f"Member of {len(results)} group(s)")
                print_table(
                    ["Group", "Tier Zero", "Description"],
                    [[r["group_name"], r["tier_zero"], r["description"]] for r in results]
                )
            else:
                print_warning(f"Principal not found or has no group memberships: {args.memberof}")
            return

        # === ADMIN TO COMPUTER (early exit) ===
        if args.adminto:
            print_header(f"Admins to: {args.adminto}")
            results = bh.get_admins_to(args.adminto)
            if results:
                print_subheader(f"Found {len(results)} admin(s)")
                print_table(
                    ["Principal", "Type", "Enabled"],
                    [[r["principal"], r["type"], r["enabled"]] for r in results]
                )
            else:
                print_warning(f"Computer not found or has no admins: {args.adminto}")
            return

        # === ADMIN OF (early exit) ===
        if args.adminof:
            print_header(f"Admin Rights: {args.adminof}")
            results = bh.get_admin_of(args.adminof)
            if results:
                print_subheader(f"Can admin {len(results)} computer(s)")
                print_table(
                    ["Computer", "Operating System", "Enabled"],
                    [[r["computer"], r["os"], r["enabled"]] for r in results]
                )
            else:
                print_warning(f"Principal not found or has no admin rights: {args.adminof}")
            return

        # === SESSIONS ON COMPUTER (early exit) ===
        if args.sessions:
            print_header(f"Sessions on: {args.sessions}")
            results = bh.get_computer_sessions(args.sessions)
            if results:
                print_subheader(f"Found {len(results)} session(s)")
                print_table(
                    ["User", "Admin", "Enabled"],
                    [[r["user"], r["admin"], r["enabled"]] for r in results]
                )
            else:
                print_warning(f"Computer not found or has no sessions: {args.sessions}")
            return

        # === EDGES FROM (early exit) ===
        if args.edges_from:
            print_header(f"Outbound Edges: {args.edges_from}")
            results = bh.get_edges_from(args.edges_from)
            if results:
                print_subheader(f"Found {len(results)} outbound edge(s)")
                print_table(
                    ["Relationship", "Target", "Target Type"],
                    [[r["relationship"], r["target"], r["target_type"]] for r in results]
                )
            else:
                print_warning(f"Principal not found or has no outbound edges: {args.edges_from}")
            return

        # === EDGES TO (early exit) ===
        if args.edges_to:
            print_header(f"Inbound Edges: {args.edges_to}")
            results = bh.get_edges_to(args.edges_to)
            if results:
                print_subheader(f"Found {len(results)} inbound edge(s)")
                print_table(
                    ["Source", "Source Type", "Relationship"],
                    [[r["source"], r["source_type"], r["relationship"]] for r in results]
                )
            else:
                print_warning(f"Principal not found or has no inbound edges: {args.edges_to}")
            return

        # === QUICK FILTERS (standalone, always exit) ===
        if args.kerberoastable:
            get_kerberoastable(bh, args.domain, Severity.HIGH)
            return

        if args.asrep:
            get_asrep_roastable(bh, args.domain, Severity.HIGH)
            return

        if args.unconstrained:
            get_unconstrained_delegation(bh, args.domain, Severity.HIGH)
            return

        if args.no_laps:
            get_computers_without_laps(bh, args.domain, Severity.MEDIUM)
            return

        # Validate domain if specified
        domain = args.domain
        if domain:
            domains = bh.get_domains()
            domain_names = [d["name"].upper() for d in domains]
            if domain.upper() not in domain_names:
                status_print(f"{Colors.FAIL}[!] Domain '{domain}' not found in database{Colors.END}")
                status_print(f"    Available domains: {', '.join(d['name'] for d in domains)}")
                sys.exit(1)
            status_print(f"{Colors.BLUE}[*] Filtering by domain: {domain}{Colors.END}")

        # Load custom queries if specified
        custom_queries = []
        if args.custom:
            for path in args.custom:
                try:
                    loaded = load_custom_queries(path)
                    custom_queries.extend(loaded)
                    p = Path(path)
                    if p.is_dir():
                        status_print(f"{Colors.GREEN}[+] Loaded {len(loaded)} custom query(ies) from {path}/{Colors.END}")
                    else:
                        status_print(f"{Colors.GREEN}[+] Loaded custom query: {loaded[0][0]}{Colors.END}")
                except Exception as e:
                    print_warning(f"Failed to load {path}: {e}")

        # Determine which queries to run
        # Check which category flags are set
        selected_categories = []
        for flag, category in CATEGORY_FLAGS.items():
            if getattr(args, flag, False):
                selected_categories.append(category)

        if args.all:
            # Run all queries (built-in + custom)
            selected_queries = [(name, func, sev) for name, func, _, _, sev in get_query_registry()]
            # Add custom queries
            selected_queries.extend([(name, func, sev) for name, func, _, _, sev in custom_queries])
            status_print(f"{Colors.BLUE}[*] Running all {len(selected_queries)} queries...{Colors.END}")
        elif selected_categories:
            # Run queries from selected categories
            registry = get_query_registry()
            selected_queries = [
                (name, func, sev) for name, func, cat, _, sev in registry
                if cat in selected_categories
            ]
            # Add custom queries if specified
            selected_queries.extend([(name, func, sev) for name, func, _, _, sev in custom_queries])
            cat_str = ", ".join(selected_categories)
            status_print(f"{Colors.BLUE}[*] Running {len(selected_queries)} queries from: {cat_str}{Colors.END}")
        elif custom_queries:
            # Custom queries only
            selected_queries = [(name, func, sev) for name, func, _, _, sev in custom_queries]
            status_print(f"{Colors.BLUE}[*] Running {len(selected_queries)} custom queries...{Colors.END}")
        else:
            # No queries selected - show help
            status_print(f"{Colors.WARNING}[!] No queries selected. Use -a for all, or specify categories:{Colors.END}")
            status_print(f"    --acl        ACL Abuse queries")
            status_print(f"    --adcs       ADCS/Certificate queries")
            status_print(f"    --privesc    Privilege Escalation queries")
            status_print(f"    --delegation Delegation queries")
            status_print(f"    --lateral    Lateral Movement queries")
            status_print(f"    --hygiene    Security Hygiene queries")
            status_print(f"    --owned-queries  Owned principal queries")
            status_print(f"    --basic      Basic Info/Domain queries")
            status_print(f"    --groups     Dangerous Groups queries")
            status_print(f"    --attack-paths   Attack Path queries")
            status_print(f"    --azure      Azure/Hybrid queries")
            status_print(f"    --exchange   Exchange queries")
            status_print(f"    --misc       Miscellaneous queries")
            status_print(f"\n    Or use -a/--all to run everything")
            return

        if not selected_queries:
            status_print(f"{Colors.WARNING}[!] No queries matched the selected categories{Colors.END}")
            return

        # Apply severity filter
        if config.severity_filter:
            filtered_queries = [
                (name, func, sev) for name, func, sev in selected_queries
                if sev.label in config.severity_filter
            ]
            skipped = len(selected_queries) - len(filtered_queries)
            if skipped > 0:
                status_print(f"{Colors.BLUE}[*] Filtered to {len(filtered_queries)} queries (skipped {skipped} by severity){Colors.END}")
            selected_queries = filtered_queries

        if not selected_queries:
            status_print(f"{Colors.WARNING}[!] No queries match the severity filter: {', '.join(config.severity_filter)}{Colors.END}")
            return

        if config.output_format == 'table':
            list_domains(bh)

        start_time = time.time()
        severity_counts = {s: 0 for s in Severity}
        all_results: List[Dict[str, Any]] = []
        query_timings: List[Tuple[str, float, int]] = []  # (name, elapsed, count)

        # Run queries with optional progress bar
        def run_query(name: str, func, severity: Severity) -> Tuple[int, List[Dict], float]:
            """Run a single query and return count, results, and elapsed time."""
            query_start = time.time()
            try:
                # Clear results cache before running query
                bh.clear_results_cache()
                result_count = func(bh, domain, severity)
                count = result_count if isinstance(result_count, int) else 0

                elapsed = time.time() - query_start

                # Show per-query timing in debug mode
                if config.debug_mode and config.output_format == 'table':
                    print(f"    {Colors.CYAN}[{elapsed:.2f}s]{Colors.END}")

                # For structured output, retrieve accumulated results from the query
                if config.output_format != 'table':
                    # Get accumulated results (handles queries with multiple sub-queries)
                    results = bh.accumulated_results.copy() if bh.accumulated_results else []
                    return count, results, elapsed
                else:
                    return count, [], elapsed
            except Exception as e:
                elapsed = time.time() - query_start
                if config.output_format == 'table':
                    print(f"{Colors.FAIL}[!] Error running '{name}': {e}{Colors.END}")
                    if config.debug_mode:
                        import traceback
                        traceback.print_exc()
                return 0, [], elapsed

        if config.show_progress and config.output_format == 'table':
            try:
                from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[cyan]{task.description}"),
                    BarColumn(),
                    TaskProgressColumn(),
                    transient=True
                ) as progress:
                    task = progress.add_task("Running queries...", total=len(selected_queries))
                    for name, func, severity in selected_queries:
                        progress.update(task, description=f"[cyan]{name[:50]}")
                        result_count, results, elapsed = run_query(name, func, severity)
                        query_timings.append((name, elapsed, result_count))
                        if result_count > 0 and severity != Severity.INFO:
                            severity_counts[severity] += 1
                        all_results.append({
                            'query': name,
                            'severity': severity.label,
                            'count': result_count,
                            'results': results
                        })
                        progress.update(task, advance=1)
            except ImportError:
                # Rich not installed, fall back to normal execution
                for name, func, severity in selected_queries:
                    result_count, results, elapsed = run_query(name, func, severity)
                    query_timings.append((name, elapsed, result_count))
                    if result_count > 0 and severity != Severity.INFO:
                        severity_counts[severity] += 1
                    all_results.append({
                        'query': name,
                        'severity': severity.label,
                        'count': result_count,
                        'results': results
                    })
        else:
            for name, func, severity in selected_queries:
                result_count, results, elapsed = run_query(name, func, severity)
                query_timings.append((name, elapsed, result_count))
                if result_count > 0 and severity != Severity.INFO:
                    severity_counts[severity] += 1
                all_results.append({
                    'query': name,
                    'severity': severity.label,
                    'count': result_count,
                    'results': results
                })

        elapsed = time.time() - start_time

        # Output results based on format
        if config.output_format == 'json':
            output_json(all_results)
        elif config.output_format == 'csv':
            output_csv(all_results)
        elif config.output_format == 'html':
            from hackles.display.report import generate_html_report
            generate_html_report(all_results, args.html)
            print(f"{Colors.GREEN}[+] HTML report saved to: {args.html}{Colors.END}")
            print_severity_summary(severity_counts)
            print(f"\n{Colors.GREEN}[+] Analysis completed in {elapsed:.2f}s{Colors.END}")
            print(f"    Ran {len(selected_queries)} queries")
        else:
            # Table output - already printed during execution
            print_severity_summary(severity_counts)
            print(f"\n{Colors.GREEN}[+] Analysis completed in {elapsed:.2f}s{Colors.END}")
            print(f"    Ran {len(selected_queries)} queries")

        # Show timing summary in debug mode
        if config.debug_mode and query_timings and config.output_format == 'table':
            print(f"\n{Colors.CYAN}[*] Query Timing Summary (slowest first){Colors.END}")
            sorted_timings = sorted(query_timings, key=lambda x: -x[1])[:10]
            for name, timing, count in sorted_timings:
                print(f"    {timing:.2f}s - {name} ({count} results)")

    finally:
        bh.close()


if __name__ == "__main__":
    main()
