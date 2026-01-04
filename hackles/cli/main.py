"""Main entry point for Hackles CLI"""

import csv
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from prettytable import PrettyTable

from hackles.cli.completion import setup_completion
from hackles.cli.parser import create_parser
from hackles.core.bloodhound import BloodHoundCE, _has_wildcard
from hackles.core.config import config
from hackles.display.banner import print_banner
from hackles.display.colors import Severity, colors
from hackles.display.paths import print_path
from hackles.display.tables import (
    print_header,
    print_node_info,
    print_severity_summary,
    print_subheader,
    print_table,
    print_warning,
)
from hackles.queries import get_query_registry

# Global to store args.html path for HTML output
_html_output_path: Optional[str] = None


def output_results(title: str, data: List[Dict[str, Any]], columns: List[str]) -> bool:
    """Output results in the configured format (json/csv/html/table).

    Args:
        title: Title/heading for the output
        data: List of dicts containing the data
        columns: List of column names (used for CSV/HTML headers)

    Returns:
        True if output was handled (non-table format), False if table output should proceed
    """
    if config.output_format == "json":
        print(json.dumps(data, indent=2, default=str))
        return True
    elif config.output_format == "csv":
        writer = csv.writer(sys.stdout)
        writer.writerow(columns)
        for row in data:
            # Try multiple key formats: exact, lowercase, lowercase with underscores
            row_values = []
            for col in columns:
                key_variants = [col, col.lower(), col.lower().replace(" ", "_")]
                value = None
                for key in key_variants:
                    if key in row:
                        value = row[key]
                        break
                row_values.append(value if value is not None else "")
            writer.writerow(row_values)
        return True
    elif config.output_format == "html":
        from hackles.display.report import generate_simple_html

        if _html_output_path:
            generate_simple_html(title, columns, data, _html_output_path)
            print(f"HTML report saved to: {_html_output_path}")
        return True
    return False


# Mapping of CLI flags to category names in the registry
CATEGORY_FLAGS = {
    "acl": "ACL Abuse",
    "adcs": "ADCS",
    "attack_paths": "Attack Paths",
    "azure": "Azure/Hybrid",
    "basic": "Basic Info",
    "groups": "Dangerous Groups",
    "delegation": "Delegation",
    "exchange": "Exchange",
    "lateral": "Lateral Movement",
    "misc": "Miscellaneous",
    "owned_queries": "Owned",
    "privesc": "Privilege Escalation",
    "hygiene": "Security Hygiene",
}

from hackles.core.scoring import calculate_exposure_metrics, calculate_risk_score, get_risk_rating
from hackles.queries.credentials.asrep_roastable import get_asrep_roastable

# Import specific query functions for quick filters
from hackles.queries.credentials.kerberoastable import get_kerberoastable
from hackles.queries.delegation.unconstrained_delegation import get_unconstrained_delegation
from hackles.queries.domain.domain_stats import get_domain_stats
from hackles.queries.domain.high_value_targets import get_high_value_targets
from hackles.queries.hygiene.computers_without_laps import get_computers_without_laps
from hackles.queries.owned.owned_principals import get_owned_principals


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
            print(f"{colors.WARNING}[!] Warning: Could not initialize owned cache: {e}{colors.END}")
        config.owned_cache = {}


def collect_stats_data(bh: BloodHoundCE, domain: Optional[str] = None) -> Dict[str, Any]:
    """Collect domain statistics as a dictionary for JSON/CSV output."""
    domain_filter = "WHERE toUpper(n.domain) = toUpper($domain)" if domain else ""
    params = {"domain": domain} if domain else {}

    stats = {"domain": domain or "all", "users": {}, "computers": {}, "groups": 0, "risk": {}}

    # User stats
    query = f"""
    MATCH (n:User) {domain_filter}
    RETURN
        count(n) AS total,
        sum(CASE WHEN n.enabled = true THEN 1 ELSE 0 END) AS enabled,
        sum(CASE WHEN n.enabled = false THEN 1 ELSE 0 END) AS disabled,
        sum(CASE WHEN n.pwdneverexpires = true THEN 1 ELSE 0 END) AS pwd_never_expires,
        sum(CASE WHEN n.passwordnotreqd = true THEN 1 ELSE 0 END) AS pwd_not_required
    """
    results = bh.run_query(query, params)
    if results:
        r = results[0]
        stats["users"] = {
            "total": r["total"],
            "enabled": r["enabled"],
            "disabled": r["disabled"],
            "pwd_never_expires": r["pwd_never_expires"],
            "pwd_not_required": r["pwd_not_required"],
        }

    # Computer stats
    query = f"""
    MATCH (n:Computer) {domain_filter}
    RETURN
        count(n) AS total,
        sum(CASE WHEN n.enabled = true THEN 1 ELSE 0 END) AS enabled,
        sum(CASE WHEN n.haslaps = true THEN 1 ELSE 0 END) AS has_laps
    """
    results = bh.run_query(query, params)
    if results:
        r = results[0]
        stats["computers"] = {
            "total": r["total"],
            "enabled": r["enabled"],
            "has_laps": r["has_laps"],
        }

    # Group stats
    query = f"""
    MATCH (n:Group) {domain_filter}
    RETURN count(n) AS total
    """
    results = bh.run_query(query, params)
    if results:
        stats["groups"] = results[0]["total"]

    # ADCS stats
    stats["adcs"] = {"enterprise_cas": 0, "cert_templates": 0}
    stats["domain_controllers"] = 0
    stats["protected_users"] = 0

    # Domain filter for ADCS nodes (use different variable name)
    adcs_filter = "WHERE toUpper(n.domain) = toUpper($domain)" if domain else ""
    adcs_and = "AND toUpper(n.domain) = toUpper($domain)" if domain else ""

    # Enterprise CAs
    query = f"""
    MATCH (n:EnterpriseCA) {adcs_filter}
    RETURN count(n) AS total
    """
    results = bh.run_query(query, params)
    if results:
        stats["adcs"]["enterprise_cas"] = results[0]["total"]

    # Certificate Templates
    query = f"""
    MATCH (n:CertTemplate) {adcs_filter}
    RETURN count(n) AS total
    """
    results = bh.run_query(query, params)
    if results:
        stats["adcs"]["cert_templates"] = results[0]["total"]

    # Domain Controllers (objectid ends with -516)
    query = f"""
    MATCH (n:Computer)
    WHERE n.objectid ENDS WITH '-516' {adcs_and}
    RETURN count(n) AS total
    """
    results = bh.run_query(query, params)
    if results:
        stats["domain_controllers"] = results[0]["total"]

    # Protected Users (members of group ending with -525)
    query = f"""
    MATCH (u:User)-[:MemberOf*1..]->(g:Group)
    WHERE g.objectid ENDS WITH '-525' {adcs_and}
    RETURN count(DISTINCT u) AS total
    """
    results = bh.run_query(query, params)
    if results:
        stats["protected_users"] = results[0]["total"]

    # Risk scoring
    metrics = calculate_exposure_metrics(bh, domain)
    score = calculate_risk_score(metrics)
    rating = get_risk_rating(score)
    stats["risk"] = {
        "score": score,
        "rating": rating,
        "users_with_path_to_da": metrics.get("users_with_path_to_da", 0),
        "pct_users_with_path_to_da": metrics.get("pct_users_with_path_to_da", 0),
        "computers_without_laps": metrics.get("computers_without_laps", 0),
        "pct_computers_without_laps": metrics.get("pct_computers_without_laps", 0),
        "kerberoastable_admins": metrics.get("kerberoastable_admins", 0),
        "asrep_roastable": metrics.get("asrep_roastable", 0),
        "unconstrained_delegation_non_dc": metrics.get("unconstrained_delegation_non_dc", 0),
        "domain_admin_count": metrics.get("domain_admin_count", 0),
        "tier_zero_count": metrics.get("tier_zero_count", 0),
    }

    return stats


def list_domains(bh: BloodHoundCE) -> None:
    """List all domains in the database."""
    print_header("Domains")
    domains = bh.get_domains()
    print_subheader(f"Found {len(domains)} domain(s)")

    if domains:
        print_table(
            ["Domain", "Functional Level", "SID"],
            [[d["name"], d["level"], d["objectid"]] for d in domains],
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

    if path.is_file() and path.suffix == ".cypher":
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        name = path.stem.replace("_", " ").title()

        # Extract metadata from comments
        lines = content.split("\n")
        desc_lines = []
        severity = Severity.MEDIUM  # Default severity
        severity_map = {
            "CRITICAL": Severity.CRITICAL,
            "HIGH": Severity.HIGH,
            "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW,
            "INFO": Severity.INFO,
        }

        for line in lines:
            stripped = line.strip()
            if stripped.startswith("#"):
                comment = stripped.lstrip("#").strip()
                # Check for severity directive
                if comment.lower().startswith("severity:"):
                    sev_value = comment.split(":", 1)[1].strip().upper()
                    if sev_value in severity_map:
                        severity = severity_map[sev_value]
                else:
                    desc_lines.append(comment)
            else:
                break

        if desc_lines:
            name = " ".join(desc_lines)

        # Strip comment lines from cypher content (Neo4j doesn't support # comments)
        cypher_lines = [line for line in lines if not line.strip().startswith("#")]
        cypher = "\n".join(cypher_lines).strip()

        # Parse RETURN columns
        aliases = re.findall(r"\bAS\s+(\w+)", cypher, re.IGNORECASE)
        columns = aliases if aliases else ["result"]

        def make_query_func(query_text, cols):
            def query_func(bh, domain=None, severity=None):
                results = bh.run_query(query_text)
                result_count = len(results)
                if not print_header(name, severity, result_count):
                    return result_count
                print_subheader(f"Found {result_count} result(s)")
                if results:
                    print_table(cols, [[r.get(c, "") for c in cols] for r in results])
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
        output.append(
            {
                "query": r["query"],
                "severity": r["severity"],
                "count": r["count"],
                "results": r.get("results", []),
            }
        )
    print(json.dumps(output, indent=2, default=str))


def output_csv(results: List[Dict[str, Any]]) -> None:
    """Output results as CSV."""
    writer = csv.writer(sys.stdout)

    # Write header
    writer.writerow(["Query", "Severity", "Count", "Data"])

    for r in results:
        result_data = r.get("results", [])
        if result_data:
            for row in result_data:
                # Flatten row data, handling None values
                row_str = "; ".join(f"{k}={v if v is not None else ''}" for k, v in row.items())
                writer.writerow([r["query"], r["severity"], r["count"], row_str])
        else:
            writer.writerow([r["query"], r["severity"], r["count"], ""])


def do_auth(args) -> None:
    """Handle --auth: Authenticate to BloodHound CE and store API token."""
    from hackles.api.client import BloodHoundAPI, BloodHoundAPIError
    from hackles.api.config import APIConfig

    api_config = APIConfig(args.api_config)

    # Use URL from args (has default) or existing config
    url = args.api_url

    print(f"\n{colors.BLUE}[*] Create an API token in BloodHound CE:{colors.END}")
    print(f"    Administration > API Tokens > Create Token")
    print()

    token_id = input("Token ID: ").strip()
    token_key = input("Token Key: ").strip()

    if not token_id or not token_key:
        print(f"{colors.FAIL}[!] Token ID and Key are required{colors.END}")
        return

    print(f"\n{colors.BLUE}[*] Testing connection to {url}...{colors.END}")

    try:
        api = BloodHoundAPI(url, token_id, token_key)
        if api.test_connection():
            user_info = api.get_self()
            user_name = user_info.get("data", {}).get("name", "Unknown")
            print(f"{colors.GREEN}[+] Authentication successful!{colors.END}")
            print(f"    User: {user_name}")

            api_config.save(url=url, token_id=token_id, token_key=token_key)
            print(f"{colors.GREEN}[+] Credentials saved to {api_config.config_file}{colors.END}")
        else:
            print(f"{colors.FAIL}[!] Authentication failed. Check your credentials.{colors.END}")
    except BloodHoundAPIError as e:
        print(f"{colors.FAIL}[!] Connection error: {e}{colors.END}")
    except Exception as e:
        print(f"{colors.FAIL}[!] Error: {e}{colors.END}")


def do_ingest(args) -> None:
    """Handle --ingest: Upload JSON/ZIP files to BloodHound CE."""
    from hackles.api.client import BloodHoundAPI, BloodHoundAPIError
    from hackles.api.config import APIConfig
    from hackles.api.ingest import expand_file_patterns, format_bytes, ingest_files

    api_config = APIConfig(args.api_config)

    if not api_config.has_credentials():
        print(f"{colors.FAIL}[!] No API credentials found. Run --auth first.{colors.END}")
        return

    url, token_id, token_key = api_config.get_credentials()

    # Expand file patterns
    files = expand_file_patterns(args.ingest)
    if not files:
        print(f"{colors.FAIL}[!] No matching files found{colors.END}")
        return

    print(f"{colors.BLUE}[*] Found {len(files)} file(s) to upload:{colors.END}")
    for f in files:
        print(f"    - {f.name}")
    print()

    api = BloodHoundAPI(url, token_id, token_key)

    # Progress callback
    def progress(filename: str, current: int, total: int) -> None:
        print(f"{colors.BLUE}[*] Uploading ({current}/{total}): {filename}{colors.END}")

    print(f"{colors.BLUE}[*] Starting upload job...{colors.END}")

    try:
        result = ingest_files(
            api, files, wait_for_completion=True, timeout=300, progress_callback=progress
        )

        print()
        if result["files_uploaded"] > 0:
            print(f"{colors.GREEN}[+] Upload complete!{colors.END}")
            print(f"    Files uploaded: {result['files_uploaded']}")
            print(f"    Total size: {format_bytes(result['total_bytes'])}")
            if result["completed"]:
                print(f"    Ingestion: Complete")
            else:
                print(f"    Ingestion: Pending (check BloodHound UI)")

        if result["files_failed"] > 0:
            print(f"{colors.WARNING}[!] Failed uploads: {result['files_failed']}{colors.END}")

        for error in result["errors"]:
            print(f"{colors.FAIL}    - {error}{colors.END}")

    except BloodHoundAPIError as e:
        print(f"{colors.FAIL}[!] API error: {e}{colors.END}")
    except Exception as e:
        print(f"{colors.FAIL}[!] Error: {e}{colors.END}")
        if config.debug_mode:
            import traceback

            traceback.print_exc()


def do_clear_database(args) -> None:
    """Handle --clear-database: Clear data from BloodHound CE database."""
    from hackles.api.client import BloodHoundAPI, BloodHoundAPIError
    from hackles.api.config import APIConfig

    api_config = APIConfig(args.api_config)

    if not api_config.has_credentials():
        print(f"{colors.FAIL}[!] No API credentials found. Run --auth first.{colors.END}")
        return

    # Check if --delete-all expands to all flags
    delete_all = args.delete_all
    delete_ad = args.delete_ad or delete_all
    delete_azure = args.delete_azure or delete_all
    delete_sourceless = args.delete_sourceless or delete_all
    delete_ingest_history = args.delete_ingest_history or delete_all
    delete_quality_history = args.delete_quality_history or delete_all

    # Require at least one deletion flag
    if not any(
        [delete_ad, delete_azure, delete_sourceless, delete_ingest_history, delete_quality_history]
    ):
        print(f"{colors.WARNING}[!] No deletion options specified.{colors.END}")
        print(f"    Use one or more of the following flags with --clear-database:")
        print(f"      --delete-all             Delete everything")
        print(f"      --delete-ad              Delete AD graph data")
        print(f"      --delete-azure           Delete Azure graph data")
        print(f"      --delete-sourceless      Delete sourceless graph data")
        print(f"      --delete-ingest-history  Delete file ingest history")
        print(f"      --delete-quality-history Delete data quality history")
        return

    # Build summary of what will be deleted
    deletions = []
    if delete_ad:
        deletions.append("AD graph data")
    if delete_azure:
        deletions.append("Azure graph data")
    if delete_sourceless:
        deletions.append("Sourceless graph data")
    if delete_ingest_history:
        deletions.append("File ingest history")
    if delete_quality_history:
        deletions.append("Data quality history")

    url, token_id, token_key = api_config.get_credentials()

    print(f"\n{colors.WARNING}[!] WARNING: This will permanently delete the following:{colors.END}")
    for item in deletions:
        print(f"    - {item}")
    print(f"\n    Target: {url}")

    # Require confirmation unless --yes is provided
    if not args.yes:
        if not sys.stdout.isatty():
            print(
                f"{colors.FAIL}[!] Non-interactive mode detected. Use --yes to confirm.{colors.END}"
            )
            return

        try:
            response = input(f"\n{colors.BOLD}Type 'DELETE' to confirm: {colors.END}").strip()
            if response != "DELETE":
                print(f"{colors.BLUE}[*] Operation cancelled.{colors.END}")
                return
        except (KeyboardInterrupt, EOFError):
            print(f"\n{colors.BLUE}[*] Operation cancelled.{colors.END}")
            return

    print(f"\n{colors.BLUE}[*] Clearing database...{colors.END}")

    try:
        api = BloodHoundAPI(url, token_id, token_key)
        api.clear_database(
            delete_ad=delete_ad,
            delete_azure=delete_azure,
            delete_sourceless=delete_sourceless,
            delete_ingest_history=delete_ingest_history,
            delete_quality_history=delete_quality_history,
        )
        print(f"{colors.GREEN}[+] Database cleared successfully!{colors.END}")

    except BloodHoundAPIError as e:
        print(f"{colors.FAIL}[!] API error: {e}{colors.END}")
        if e.response:
            print(f"    Response: {e.response}")
    except Exception as e:
        print(f"{colors.FAIL}[!] Error: {e}{colors.END}")
        if config.debug_mode:
            import traceback

            traceback.print_exc()


def do_ingest_history(args) -> None:
    """Show file ingest history from BloodHound CE API."""
    from hackles.api.client import BloodHoundAPI, BloodHoundAPIError
    from hackles.api.config import APIConfig

    api_config = APIConfig(args.api_config)
    if not api_config.has_credentials():
        print(f"{colors.FAIL}[!] No API credentials found. Run --auth first.{colors.END}")
        return

    url, token_id, token_key = api_config.get_credentials()

    try:
        api = BloodHoundAPI(url, token_id, token_key)
        result = api.get_file_upload_jobs()
        jobs = result.get("data", [])

        if not jobs:
            print(f"{colors.BLUE}[*] No ingest history found.{colors.END}")
            return

        # Handle different output formats
        if config.output_format == "json":
            import json

            print(json.dumps(jobs, indent=2, default=str))
            return

        if config.output_format == "csv":
            import csv
            import sys

            if jobs:
                # Get all possible keys from jobs
                fieldnames = ["id", "status", "start_time", "end_time", "status_message"]
                writer = csv.DictWriter(sys.stdout, fieldnames=fieldnames, extrasaction="ignore")
                writer.writeheader()
                for job in jobs:
                    writer.writerow(job)
            return

        # Table output
        print(f"\n{colors.BLUE}[*] Ingest History ({len(jobs)} job(s)):{colors.END}\n")

        table = PrettyTable()
        table.field_names = ["ID", "Status", "Start Time", "End Time", "Message"]
        table.align = "l"
        table.max_width["Message"] = 40

        for job in jobs:
            job_id = str(job.get("id", ""))[:8]  # Truncate long IDs
            status = job.get("status", "unknown")
            start_time = job.get("start_time", "")
            end_time = job.get("end_time", "")
            message = job.get("status_message", "")[:40] if job.get("status_message") else ""

            # Format timestamps if present
            if start_time and "T" in str(start_time):
                start_time = str(start_time).replace("T", " ").split(".")[0]
            if end_time and "T" in str(end_time):
                end_time = str(end_time).replace("T", " ").split(".")[0]

            # Color status
            if status in ("complete", "completed", "ingested"):
                status_display = f"{colors.GREEN}{status}{colors.END}"
            elif status in ("failed", "error"):
                status_display = f"{colors.FAIL}{status}{colors.END}"
            elif status in ("running", "processing"):
                status_display = f"{colors.BLUE}{status}{colors.END}"
            else:
                status_display = status

            table.add_row([job_id, status_display, start_time, end_time, message])

        print(table)

    except BloodHoundAPIError as e:
        print(f"{colors.FAIL}[!] API error: {e}{colors.END}")
        if e.response:
            print(f"    Response: {e.response}")
    except Exception as e:
        print(f"{colors.FAIL}[!] Error: {e}{colors.END}")
        if config.debug_mode:
            import traceback

            traceback.print_exc()


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
    global _html_output_path
    if args.json:
        config.output_format = "json"
        config.quiet_mode = True  # Suppress normal output
    elif args.csv:
        config.output_format = "csv"
        config.quiet_mode = True
    elif args.html:
        config.output_format = "html"
        _html_output_path = args.html
    else:
        config.output_format = "table"

    # Parse severity filter
    if args.severity:
        severity_names = [s.strip().upper() for s in args.severity.split(",")]
        valid_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        config.severity_filter = {s for s in severity_names if s in valid_severities}
        if not config.severity_filter:
            print(
                f"{colors.WARNING}[!] No valid severity levels provided. Valid: CRITICAL,HIGH,MEDIUM,LOW,INFO{colors.END}"
            )
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
    default_abuse_config = Path.home() / ".hackles" / "abuse.conf"
    if args.abuse_config:
        config.load_abuse_config(Path(args.abuse_config))
    elif default_abuse_config.exists():
        config.load_abuse_config(default_abuse_config)

    # CLI abuse vars override config file values
    if args.abuse_var:
        for var in args.abuse_var:
            if "=" in var:
                key, value = var.split("=", 1)
                config.abuse_vars[key.strip()] = value.strip()
            else:
                print(
                    f"{colors.WARNING}[!] Invalid --abuse-var format: {var} (expected KEY=VALUE){colors.END}"
                )

    # === BLOODHOUND CE API OPERATIONS (no Neo4j required) ===
    if args.auth:
        do_auth(args)
        return

    if args.ingest:
        do_ingest(args)
        return

    if args.clear_database:
        do_clear_database(args)
        return

    if args.ingest_history:
        do_ingest_history(args)
        return

    # Check for delete flags without --clear-database
    delete_flags = [
        args.delete_all,
        args.delete_ad,
        args.delete_azure,
        args.delete_sourceless,
        args.delete_ingest_history,
        args.delete_quality_history,
    ]
    if any(delete_flags):
        print(f"{colors.FAIL}[!] --delete-* flags require --clear-database{colors.END}")
        sys.exit(1)

    # Require password for Neo4j operations
    if not args.password:
        print(f"{colors.FAIL}[!] Neo4j password required (-p/--password){colors.END}")
        sys.exit(1)

    # Helper to check if we should print status messages
    def status_print(msg: str) -> None:
        """Print status message only in table output mode."""
        if config.output_format == "table":
            print(msg)

    if not config.quiet_mode:
        print_banner()

    status_print(f"\n{colors.BLUE}[*] Connecting to {args.bolt}...{colors.END}")
    bh = BloodHoundCE(args.bolt, args.username, args.password, args.debug)

    if not bh.connect():
        sys.exit(1)

    status_print(f"{colors.GREEN}[+] Connected successfully{colors.END}")

    # Handle ownership marking
    if args.own:
        for principal in args.own:
            if bh.mark_owned(principal):
                status_print(f"{colors.GREEN}[+] Marked as owned: {principal}{colors.END}")
            else:
                status_print(f"{colors.WARNING}[!] Principal not found: {principal}{colors.END}")

    if args.unown:
        if bh.unmark_owned(args.unown):
            status_print(f"{colors.GREEN}[+] Removed owned status: {args.unown}{colors.END}")
        else:
            status_print(f"{colors.WARNING}[!] Principal not found: {args.unown}{colors.END}")

    # Initialize owned cache
    init_owned_cache(bh)
    if config.owned_cache:
        status_print(
            f"{colors.BLUE}[*] Found {len(config.owned_cache)} owned principal(s){colors.END}"
        )

    try:
        # === CLEAR OWNED (early exit) ===
        if args.clear_owned:
            count = bh.clear_all_owned()
            status_print(
                f"{colors.GREEN}[+] Removed owned status from {count} principal(s){colors.END}"
            )
            init_owned_cache(bh)
            status_print(
                f"{colors.BLUE}[*] Owned cache now has {len(config.owned_cache)} principal(s){colors.END}"
            )
            return

        # === TIER ZERO MARKING ===
        if args.tier_zero:
            for principal in args.tier_zero:
                if bh.mark_tier_zero(principal):
                    status_print(f"{colors.GREEN}[+] Marked as Tier Zero: {principal}{colors.END}")
                else:
                    status_print(
                        f"{colors.WARNING}[!] Principal not found: {principal}{colors.END}"
                    )

        if args.untier_zero:
            if bh.unmark_tier_zero(args.untier_zero):
                status_print(
                    f"{colors.GREEN}[+] Removed Tier Zero status: {args.untier_zero}{colors.END}"
                )
            else:
                status_print(
                    f"{colors.WARNING}[!] Principal not found: {args.untier_zero}{colors.END}"
                )

        # Show tier zero and exit if no -a flag
        if (args.tier_zero or args.untier_zero) and not args.all:
            if config.output_format != "table":
                # Direct query for structured output
                domain_filter = "AND toUpper(n.domain) = toUpper($domain)" if args.domain else ""
                params = {"domain": args.domain} if args.domain else {}
                query = f"""
                MATCH (n)
                WHERE (n:Tag_Tier_Zero OR 'admin_tier_0' IN n.system_tags)
                {domain_filter}
                RETURN n.name AS name, labels(n)[0] AS type, n.enabled AS enabled
                ORDER BY labels(n)[0], n.name
                """
                results = bh.run_query(query, params)
                if output_results("Tier Zero Assets", results, ["name", "type", "enabled"]):
                    return
            get_high_value_targets(bh, args.domain, Severity.INFO)
            return

        # List domains only
        if args.list:
            domains = bh.get_domains()
            if domains:
                columns = ["name", "level", "objectid"]
                if output_results("Domains", domains, columns):
                    return
            # Table output
            list_domains(bh)
            return

        # === STATS (early exit) ===
        if args.stats:
            if config.output_format == "json":
                stats = collect_stats_data(bh, args.domain)
                print(json.dumps(stats, indent=2, default=str))
            elif config.output_format == "csv":
                stats = collect_stats_data(bh, args.domain)
                writer = csv.writer(sys.stdout)
                writer.writerow(["category", "metric", "value"])
                writer.writerow(["domain", "name", stats["domain"]])
                for key, val in stats["users"].items():
                    writer.writerow(["users", key, val])
                for key, val in stats["computers"].items():
                    writer.writerow(["computers", key, val])
                writer.writerow(["groups", "total", stats["groups"]])
                for key, val in stats["adcs"].items():
                    writer.writerow(["adcs", key, val])
                writer.writerow(["domain_controllers", "total", stats["domain_controllers"]])
                writer.writerow(["protected_users", "total", stats["protected_users"]])
                for key, val in stats["risk"].items():
                    writer.writerow(["risk", key, val])
            else:
                get_domain_stats(bh, args.domain, Severity.INFO)
            return

        # If only marking ownership (no -a flag), show owned principals and exit
        if (args.own or args.unown) and not args.all:
            get_owned_principals(bh, args.domain, Severity.INFO)
            return

        # === INVESTIGATE NODE (early exit) ===
        if args.investigate:
            if _has_wildcard(args.investigate):
                # Wildcard: show triage summary
                print_header(f"Investigation Triage: {args.investigate}")
                results = bh.investigate_nodes(args.investigate)
                if results:
                    print_subheader(f"Found {len(results)} node(s) - sorted by attack relevance")
                    rows = []
                    for r in results:
                        # Build flags column
                        flags = []
                        if r.get("admin"):
                            flags.append("Admin")
                        if r.get("unconstrained"):
                            flags.append("Uncon")
                        if r.get("laps") is False:
                            flags.append("NoLAPS")
                        flags_str = ", ".join(flags) if flags else "-"

                        rows.append(
                            [
                                r["name"],
                                r["type"],
                                r.get("enabled", ""),
                                flags_str,
                                r.get("outbound_edges", 0),
                                r.get("inbound_edges", 0),
                            ]
                        )
                    print_table(["Name", "Type", "Enabled", "Flags", "Outbound", "Inbound"], rows)
                    print(
                        f"\n    {colors.CYAN}Tip: Run --investigate on a specific node for full details{colors.END}"
                    )
                else:
                    print_warning(f"No nodes matching: {args.investigate}")
            else:
                # Single node: full investigation
                node_type_str = bh.get_node_type(args.investigate)
                if not node_type_str:
                    print_warning(f"Node not found: {args.investigate}")
                    return

                print_header(f"Investigating {node_type_str}: {args.investigate}")

                # Get node properties
                node_info = bh.get_node_info(args.investigate)
                if node_info:
                    print_subheader("Properties")
                    # Show key properties based on node type
                    props = []
                    if node_type_str == "User":
                        props = [
                            ["Enabled", node_info.get("enabled", "")],
                            ["Admin Count", node_info.get("admincount", False)],
                            ["Password Last Set", node_info.get("pwdlastset", "")],
                            ["Last Logon", node_info.get("lastlogon", "")],
                            ["Password Never Expires", node_info.get("pwdneverexpires", False)],
                            ["Has SPN", node_info.get("hasspn", False)],
                            ["DONT_REQ_PREAUTH", node_info.get("dontreqpreauth", False)],
                        ]
                        if node_info.get("description"):
                            props.append(["Description", node_info.get("description", "")[:60]])
                        if node_info.get("serviceprincipalnames"):
                            spns = node_info.get("serviceprincipalnames", [])
                            if spns:
                                props.append(
                                    ["SPNs", ", ".join(spns[:3]) + ("..." if len(spns) > 3 else "")]
                                )
                    elif node_type_str == "Computer":
                        props = [
                            ["Enabled", node_info.get("enabled", "")],
                            ["Operating System", node_info.get("operatingsystem", "")],
                            ["LAPS", node_info.get("haslaps", False)],
                            [
                                "Unconstrained Delegation",
                                node_info.get("unconstraineddelegation", False),
                            ],
                            ["Last Logon", node_info.get("lastlogon", "")],
                        ]
                        if node_info.get("description"):
                            props.append(["Description", node_info.get("description", "")[:60]])
                    elif node_type_str == "Group":
                        is_t0 = "admin_tier_0" in node_info.get(
                            "system_tags", []
                        ) or "Tag_Tier_Zero" in node_info.get("_labels", [])
                        props = [
                            ["Tier Zero", is_t0],
                            ["Admin Count", node_info.get("admincount", False)],
                        ]
                        if node_info.get("description"):
                            props.append(["Description", node_info.get("description", "")[:80]])
                    print_table(["Property", "Value"], props)

                # Outbound edges (attack paths FROM this node)
                edges_out = bh.get_edges_from(args.investigate)
                if edges_out:
                    print_subheader(f"Outbound Attack Edges ({len(edges_out)})")
                    # Highlight critical edges
                    critical_edges = [
                        "GenericAll",
                        "WriteDacl",
                        "WriteOwner",
                        "DCSync",
                        "AllExtendedRights",
                    ]
                    rows = []
                    for e in edges_out[:15]:
                        rel = e["relationship"]
                        if rel in critical_edges:
                            rel = f"{colors.FAIL}{rel}{colors.END}"
                        rows.append([rel, e["target"], e["target_type"]])
                    print_table(["Relationship", "Target", "Type"], rows)
                    if len(edges_out) > 15:
                        print(f"    {colors.GRAY}... and {len(edges_out) - 15} more{colors.END}")

                    # Show abuse templates for outbound edges if --abuse is set
                    if config.show_abuse:
                        from hackles.abuse.printer import print_abuse_info
                        from hackles.core.utils import extract_domain

                        # Get domain from node name
                        node_domain = extract_domain([{"name": args.investigate}])

                        # Group edges by relationship type to avoid duplicate abuse info
                        seen_relationships = set()
                        for e in edges_out[:5]:  # Limit to first 5 to avoid spam
                            rel = e["relationship"]
                            if rel in seen_relationships:
                                continue
                            seen_relationships.add(rel)

                            # Build result context for abuse template
                            result = {
                                "principal": args.investigate,  # The attacker
                                "target": e["target"],
                                "target_type": e["target_type"].lower(),
                            }
                            # Add group placeholder if target is a group
                            if e["target_type"].lower() == "group":
                                result["group"] = e["target"]

                            print_abuse_info(rel, [result], node_domain)

                # Inbound edges (who can attack this node)
                edges_in = bh.get_edges_to(args.investigate)
                if edges_in:
                    print_subheader(f"Inbound Attack Edges ({len(edges_in)})")
                    rows = []
                    for e in edges_in[:15]:
                        rows.append([e["source"], e["source_type"], e["relationship"]])
                    print_table(["Source", "Type", "Relationship"], rows)
                    if len(edges_in) > 15:
                        print(f"    {colors.GRAY}... and {len(edges_in) - 15} more{colors.END}")

                # Type-specific sections
                if node_type_str == "User":
                    # Group memberships
                    groups = bh.get_member_of(args.investigate)
                    if groups:
                        print_subheader(f"Group Memberships ({len(groups)})")
                        rows = [[g["group_name"], g["tier_zero"]] for g in groups[:10]]
                        print_table(["Group", "Tier Zero"], rows)
                        if len(groups) > 10:
                            print(f"    {colors.GRAY}... and {len(groups) - 10} more{colors.END}")

                    # Sessions (where is this user logged in)
                    sessions = bh.get_user_sessions(args.investigate)
                    if sessions:
                        print_subheader(f"Active Sessions ({len(sessions)})")
                        rows = [[s["computer"], s.get("os", "")] for s in sessions[:10]]
                        print_table(["Computer", "OS"], rows)

                    # Admin rights
                    admin_of = bh.get_admin_of(args.investigate)
                    if admin_of:
                        print_subheader(f"Admin Rights ({len(admin_of)})")
                        rows = [[a["computer"], a.get("os", "")] for a in admin_of[:10]]
                        print_table(["Computer", "OS"], rows)
                        if len(admin_of) > 10:
                            print(f"    {colors.GRAY}... and {len(admin_of) - 10} more{colors.END}")

                    # Path to DA
                    paths = bh.find_path_to_da(args.investigate)
                    if paths:
                        print_subheader(f"Path to Domain Admin ({len(paths)} path(s))")
                        for p in paths[:3]:
                            hops = p.get("path_length", 0)
                            path_str = " -> ".join(p.get("nodes", []))
                            print(f"    {colors.WARNING}[{hops} hops]{colors.END} {path_str}")

                elif node_type_str == "Computer":
                    # Sessions on this computer
                    sessions = bh.get_computer_sessions(args.investigate)
                    if sessions:
                        print_subheader(f"Active Sessions ({len(sessions)})")
                        rows = [
                            [s["user"], s.get("admin", ""), s.get("enabled", "")]
                            for s in sessions[:10]
                        ]
                        print_table(["User", "Admin", "Enabled"], rows)

                    # Local admins
                    admins = bh.get_admins_to(args.investigate)
                    if admins:
                        print_subheader(f"Local Admins ({len(admins)})")
                        rows = [
                            [a["principal"], a["type"], a.get("enabled", "")] for a in admins[:10]
                        ]
                        print_table(["Principal", "Type", "Enabled"], rows)
                        if len(admins) > 10:
                            print(f"    {colors.GRAY}... and {len(admins) - 10} more{colors.END}")

                    # Group memberships
                    groups = bh.get_member_of(args.investigate)
                    if groups:
                        print_subheader(f"Group Memberships ({len(groups)})")
                        rows = [[g["group_name"], g["tier_zero"]] for g in groups[:10]]
                        print_table(["Group", "Tier Zero"], rows)

                elif node_type_str == "Group":
                    # Members
                    members = bh.get_group_members(args.investigate)
                    if members:
                        print_subheader(f"Members ({len(members)})")
                        rows = [
                            [m["member"], m["type"], m.get("admin", ""), m.get("enabled", "")]
                            for m in members[:15]
                        ]
                        print_table(["Member", "Type", "Admin", "Enabled"], rows)
                        if len(members) > 15:
                            print(f"    {colors.GRAY}... and {len(members) - 15} more{colors.END}")

                    # Member of
                    parent_groups = bh.get_member_of(args.investigate)
                    if parent_groups:
                        print_subheader(f"Member Of ({len(parent_groups)})")
                        rows = [[g["group_name"], g["tier_zero"]] for g in parent_groups[:10]]
                        print_table(["Group", "Tier Zero"], rows)

                print()  # Final newline
            return

        # === NODE INFO (early exit) ===
        if args.info:
            result = bh.get_node_info(args.info)
            if _has_wildcard(args.info):
                # Wildcard: result is a list
                if result:
                    # Format for structured output
                    formatted = [
                        {
                            "name": n.get("name", ""),
                            "type": n.get("_type", ""),
                            "enabled": n.get("enabled", ""),
                            "domain": n.get("domain", ""),
                        }
                        for n in result
                    ]
                    if output_results(
                        f"Node Information: {args.info}",
                        formatted,
                        ["name", "type", "enabled", "domain"],
                    ):
                        return
                    # Table output
                    print_header(f"Node Information: {args.info}")
                    print_subheader(f"Found {len(result)} node(s)")
                    print_table(
                        ["Name", "Type", "Enabled", "Domain"],
                        [
                            [
                                n.get("name", ""),
                                n.get("_type", ""),
                                n.get("enabled", ""),
                                n.get("domain", ""),
                            ]
                            for n in result
                        ],
                    )
                else:
                    if config.output_format == "json":
                        print("[]")
                    elif config.output_format == "csv":
                        print("name,type,enabled,domain")
                    else:
                        print_header(f"Node Information: {args.info}")
                        print_warning(f"No nodes matching: {args.info}")
            else:
                # Exact match: result is single dict or None
                if result:
                    if config.output_format == "json":
                        print(json.dumps(result, indent=2, default=str))
                    elif config.output_format == "csv":
                        writer = csv.writer(sys.stdout)
                        writer.writerow(["property", "value"])
                        for k, v in result.items():
                            if not k.startswith("_"):
                                writer.writerow([k, v])
                    elif config.output_format == "html":
                        from hackles.display.report import generate_simple_html

                        data = [
                            {"property": k, "value": v}
                            for k, v in result.items()
                            if not k.startswith("_")
                        ]
                        if _html_output_path:
                            generate_simple_html(
                                f"Node: {args.info}", ["property", "value"], data, _html_output_path
                            )
                            print(f"HTML report saved to: {_html_output_path}")
                    else:
                        print_header(f"Node Information: {args.info}")
                        print_node_info(result)
                else:
                    if config.output_format == "json":
                        print("null")
                    elif config.output_format == "csv":
                        print("property,value")
                    else:
                        print_header(f"Node Information: {args.info}")
                        print_warning(f"Node not found: {args.info}")
            return

        # === NODE SEARCH (early exit) ===
        if args.search:
            results = bh.search_nodes(args.search)
            if results:
                if output_results(
                    f"Search Results: {args.search}", results, ["name", "type", "enabled", "domain"]
                ):
                    return
                # Table output
                print_header(f"Search Results: {args.search}")
                print_subheader(f"Found {len(results)} match(es)")
                print_table(
                    ["Name", "Type", "Enabled", "Domain"],
                    [[r["name"], r["type"], r["enabled"], r["domain"]] for r in results],
                )
            else:
                if config.output_format == "json":
                    print("[]")
                elif config.output_format == "csv":
                    print("name,type,enabled,domain")
                else:
                    print_header(f"Search Results: {args.search}")
                    print_warning(f"No nodes matching: {args.search}")
            return

        # === PATH FINDING (early exit) ===
        if args.path:
            source, target = args.path
            paths = bh.find_shortest_path(source, target)
            if paths:
                if config.output_format == "json":
                    print(json.dumps(paths, indent=2, default=str))
                    return
                elif config.output_format == "csv":
                    writer = csv.writer(sys.stdout)
                    writer.writerow(["hops", "path"])
                    for p in paths:
                        path_str = " -> ".join(p.get("nodes", []))
                        writer.writerow([p.get("path_length", 0), path_str])
                    return
                elif config.output_format == "html":
                    from hackles.display.report import generate_simple_html

                    data = [
                        {"hops": p.get("path_length", 0), "path": " -> ".join(p.get("nodes", []))}
                        for p in paths
                    ]
                    if _html_output_path:
                        generate_simple_html(
                            f"Path: {source} -> {target}", ["hops", "path"], data, _html_output_path
                        )
                        print(f"HTML report saved to: {_html_output_path}")
                    return
                # Table output
                print_header(f"Shortest Path: {source} -> {target}")
                for path in paths:
                    print_path(path)
            else:
                if config.output_format == "json":
                    print("[]")
                elif config.output_format == "csv":
                    print("hops,path")
                else:
                    print_header(f"Shortest Path: {source} -> {target}")
                    print_warning("No path found between nodes")
            return

        if args.path_to_da:
            paths = bh.find_path_to_da(args.path_to_da)
            if paths:
                if config.output_format == "json":
                    print(json.dumps(paths, indent=2, default=str))
                    return
                elif config.output_format == "csv":
                    writer = csv.writer(sys.stdout)
                    writer.writerow(["hops", "path"])
                    for p in paths:
                        path_str = " -> ".join(p.get("nodes", []))
                        writer.writerow([p.get("path_length", 0), path_str])
                    return
                elif config.output_format == "html":
                    from hackles.display.report import generate_simple_html

                    data = [
                        {"hops": p.get("path_length", 0), "path": " -> ".join(p.get("nodes", []))}
                        for p in paths
                    ]
                    if _html_output_path:
                        generate_simple_html(
                            f"Path to DA: {args.path_to_da}",
                            ["hops", "path"],
                            data,
                            _html_output_path,
                        )
                        print(f"HTML report saved to: {_html_output_path}")
                    return
                # Table output
                print_header(f"Shortest Path to Domain Admin: {args.path_to_da}")
                for path in paths:
                    print_path(path)
            else:
                if config.output_format == "json":
                    print("[]")
                elif config.output_format == "csv":
                    print("hops,path")
                else:
                    print_header(f"Shortest Path to Domain Admin: {args.path_to_da}")
                    print_warning("No path to Domain Admin found")
            return

        if args.path_to_dc:
            paths = bh.find_path_to_dc(args.path_to_dc)
            if paths:
                if config.output_format == "json":
                    print(json.dumps(paths, indent=2, default=str))
                    return
                elif config.output_format == "csv":
                    writer = csv.writer(sys.stdout)
                    writer.writerow(["hops", "path"])
                    for p in paths:
                        path_str = " -> ".join(p.get("nodes", []))
                        writer.writerow([p.get("path_length", 0), path_str])
                    return
                elif config.output_format == "html":
                    from hackles.display.report import generate_simple_html

                    data = [
                        {"hops": p.get("path_length", 0), "path": " -> ".join(p.get("nodes", []))}
                        for p in paths
                    ]
                    if _html_output_path:
                        generate_simple_html(
                            f"Path to DC: {args.path_to_dc}",
                            ["hops", "path"],
                            data,
                            _html_output_path,
                        )
                        print(f"HTML report saved to: {_html_output_path}")
                    return
                # Table output
                print_header(f"Shortest Path to Domain Controller: {args.path_to_dc}")
                for path in paths:
                    print_path(path)
            else:
                if config.output_format == "json":
                    print("[]")
                elif config.output_format == "csv":
                    print("hops,path")
                else:
                    print_header(f"Shortest Path to Domain Controller: {args.path_to_dc}")
                    print_warning("No path to Domain Controller found")
            return

        # === GROUP MEMBERS (early exit) ===
        if args.members:
            results = bh.get_group_members(args.members)
            if results:
                if _has_wildcard(args.members):
                    columns = ["group", "member", "type", "admin", "enabled"]
                else:
                    columns = ["member", "type", "admin", "enabled"]
                if output_results(f"Group Members: {args.members}", results, columns):
                    return
                # Table output
                print_header(f"Group Members: {args.members}")
                print_subheader(f"Found {len(results)} member(s)")
                if _has_wildcard(args.members):
                    print_table(
                        ["Group", "Member", "Type", "Admin", "Enabled"],
                        [
                            [r["group"], r["member"], r["type"], r["admin"], r["enabled"]]
                            for r in results
                        ],
                    )
                else:
                    print_table(
                        ["Member", "Type", "Admin", "Enabled"],
                        [[r["member"], r["type"], r["admin"], r["enabled"]] for r in results],
                    )
            else:
                if config.output_format == "json":
                    print("[]")
                elif config.output_format == "csv":
                    print("member,type,admin,enabled")
                else:
                    print_header(f"Group Members: {args.members}")
                    print_warning(f"Group not found or has no members: {args.members}")
            return

        # === MEMBER OF (early exit) ===
        if args.memberof:
            results = bh.get_member_of(args.memberof)
            if results:
                if _has_wildcard(args.memberof):
                    columns = ["principal", "group_name", "tier_zero", "description"]
                else:
                    columns = ["group_name", "tier_zero", "description"]
                if output_results(f"Group Memberships: {args.memberof}", results, columns):
                    return
                # Table output
                print_header(f"Group Memberships: {args.memberof}")
                print_subheader(f"Found {len(results)} membership(s)")
                if _has_wildcard(args.memberof):
                    print_table(
                        ["Principal", "Group", "Tier Zero", "Description"],
                        [
                            [r["principal"], r["group_name"], r["tier_zero"], r["description"]]
                            for r in results
                        ],
                    )
                else:
                    print_table(
                        ["Group", "Tier Zero", "Description"],
                        [[r["group_name"], r["tier_zero"], r["description"]] for r in results],
                    )
            else:
                if config.output_format == "json":
                    print("[]")
                elif config.output_format == "csv":
                    print("group_name,tier_zero,description")
                else:
                    print_header(f"Group Memberships: {args.memberof}")
                    print_warning(
                        f"Principal not found or has no group memberships: {args.memberof}"
                    )
            return

        # === ADMIN TO COMPUTER (early exit) ===
        if args.adminto:
            results = bh.get_admins_to(args.adminto)
            if results:
                if _has_wildcard(args.adminto):
                    columns = ["computer", "principal", "type", "enabled"]
                else:
                    columns = ["principal", "type", "enabled"]
                if output_results(f"Admins to: {args.adminto}", results, columns):
                    return
                # Table output
                print_header(f"Admins to: {args.adminto}")
                print_subheader(f"Found {len(results)} admin(s)")
                if _has_wildcard(args.adminto):
                    print_table(
                        ["Computer", "Principal", "Type", "Enabled"],
                        [[r["computer"], r["principal"], r["type"], r["enabled"]] for r in results],
                    )
                else:
                    print_table(
                        ["Principal", "Type", "Enabled"],
                        [[r["principal"], r["type"], r["enabled"]] for r in results],
                    )
            else:
                if config.output_format == "json":
                    print("[]")
                elif config.output_format == "csv":
                    print("principal,type,enabled")
                else:
                    print_header(f"Admins to: {args.adminto}")
                    print_warning(f"Computer not found or has no admins: {args.adminto}")
            return

        # === ADMIN OF (early exit) ===
        if args.adminof:
            results = bh.get_admin_of(args.adminof)
            if results:
                if _has_wildcard(args.adminof):
                    columns = ["principal", "computer", "os", "enabled"]
                else:
                    columns = ["computer", "os", "enabled"]
                if output_results(f"Admin Rights: {args.adminof}", results, columns):
                    return
                # Table output
                print_header(f"Admin Rights: {args.adminof}")
                print_subheader(f"Found {len(results)} admin right(s)")
                if _has_wildcard(args.adminof):
                    print_table(
                        ["Principal", "Computer", "Operating System", "Enabled"],
                        [[r["principal"], r["computer"], r["os"], r["enabled"]] for r in results],
                    )
                else:
                    print_table(
                        ["Computer", "Operating System", "Enabled"],
                        [[r["computer"], r["os"], r["enabled"]] for r in results],
                    )
            else:
                if config.output_format == "json":
                    print("[]")
                elif config.output_format == "csv":
                    print("computer,os,enabled")
                else:
                    print_header(f"Admin Rights: {args.adminof}")
                    print_warning(f"Principal not found or has no admin rights: {args.adminof}")
            return

        # === SESSIONS ON COMPUTER (early exit) ===
        if args.sessions:
            results = bh.get_computer_sessions(args.sessions)
            if results:
                if _has_wildcard(args.sessions):
                    columns = ["computer", "user", "admin", "enabled"]
                else:
                    columns = ["user", "admin", "enabled"]
                if output_results(f"Sessions on: {args.sessions}", results, columns):
                    return
                # Table output
                print_header(f"Sessions on: {args.sessions}")
                print_subheader(f"Found {len(results)} session(s)")
                if _has_wildcard(args.sessions):
                    print_table(
                        ["Computer", "User", "Admin", "Enabled"],
                        [[r["computer"], r["user"], r["admin"], r["enabled"]] for r in results],
                    )
                else:
                    print_table(
                        ["User", "Admin", "Enabled"],
                        [[r["user"], r["admin"], r["enabled"]] for r in results],
                    )
            else:
                if config.output_format == "json":
                    print("[]")
                elif config.output_format == "csv":
                    print("user,admin,enabled")
                else:
                    print_header(f"Sessions on: {args.sessions}")
                    print_warning(f"Computer not found or has no sessions: {args.sessions}")
            return

        # === EDGES FROM (early exit) ===
        if args.edges_from:
            results = bh.get_edges_from(args.edges_from)
            if results:
                if _has_wildcard(args.edges_from):
                    columns = ["source", "relationship", "target", "target_type"]
                else:
                    columns = ["relationship", "target", "target_type"]
                if output_results(f"Outbound Edges: {args.edges_from}", results, columns):
                    return
                # Table output
                print_header(f"Outbound Edges: {args.edges_from}")
                print_subheader(f"Found {len(results)} outbound edge(s)")
                if _has_wildcard(args.edges_from):
                    print_table(
                        ["Source", "Relationship", "Target", "Target Type"],
                        [
                            [r["source"], r["relationship"], r["target"], r["target_type"]]
                            for r in results
                        ],
                    )
                else:
                    print_table(
                        ["Relationship", "Target", "Target Type"],
                        [[r["relationship"], r["target"], r["target_type"]] for r in results],
                    )
            else:
                if config.output_format == "json":
                    print("[]")
                elif config.output_format == "csv":
                    print("relationship,target,target_type")
                else:
                    print_header(f"Outbound Edges: {args.edges_from}")
                    print_warning(
                        f"Principal not found or has no outbound edges: {args.edges_from}"
                    )
            return

        # === EDGES TO (early exit) ===
        if args.edges_to:
            results = bh.get_edges_to(args.edges_to)
            if results:
                if _has_wildcard(args.edges_to):
                    columns = ["target", "source", "source_type", "relationship"]
                else:
                    columns = ["source", "source_type", "relationship"]
                if output_results(f"Inbound Edges: {args.edges_to}", results, columns):
                    return
                # Table output
                print_header(f"Inbound Edges: {args.edges_to}")
                print_subheader(f"Found {len(results)} inbound edge(s)")
                if _has_wildcard(args.edges_to):
                    print_table(
                        ["Target", "Source", "Source Type", "Relationship"],
                        [
                            [r["target"], r["source"], r["source_type"], r["relationship"]]
                            for r in results
                        ],
                    )
                else:
                    print_table(
                        ["Source", "Source Type", "Relationship"],
                        [[r["source"], r["source_type"], r["relationship"]] for r in results],
                    )
            else:
                if config.output_format == "json":
                    print("[]")
                elif config.output_format == "csv":
                    print("source,source_type,relationship")
                else:
                    print_header(f"Inbound Edges: {args.edges_to}")
                    print_warning(f"Principal not found or has no inbound edges: {args.edges_to}")
            return

        # === QUICK FILTERS (standalone, always exit) ===
        if args.kerberoastable:
            if config.output_format != "table":
                # Direct query for structured output
                domain_filter = "AND toUpper(u.domain) = toUpper($domain)" if args.domain else ""
                params = {"domain": args.domain} if args.domain else {}
                query = f"""
                MATCH (u:User {{hasspn: true}})
                WHERE NOT u.name STARTS WITH 'KRBTGT' {domain_filter}
                RETURN u.name AS name, u.enabled AS enabled, u.admincount AS admin,
                       u.serviceprincipalnames AS spns
                ORDER BY u.admincount DESC
                """
                results = bh.run_query(query, params)
                if output_results(
                    "Kerberoastable Users", results, ["name", "enabled", "admin", "spns"]
                ):
                    return
            get_kerberoastable(bh, args.domain, Severity.HIGH)
            return

        if args.asrep:
            if config.output_format != "table":
                domain_filter = "AND toUpper(u.domain) = toUpper($domain)" if args.domain else ""
                params = {"domain": args.domain} if args.domain else {}
                query = f"""
                MATCH (u:User {{dontreqpreauth: true}})
                WHERE u.enabled = true {domain_filter}
                RETURN u.name AS name, u.enabled AS enabled, u.admincount AS admin
                ORDER BY u.admincount DESC
                """
                results = bh.run_query(query, params)
                if output_results("AS-REP Roastable Users", results, ["name", "enabled", "admin"]):
                    return
            get_asrep_roastable(bh, args.domain, Severity.HIGH)
            return

        if args.unconstrained:
            if config.output_format != "table":
                domain_filter = "AND toUpper(n.domain) = toUpper($domain)" if args.domain else ""
                params = {"domain": args.domain} if args.domain else {}
                query = f"""
                MATCH (n)
                WHERE n.unconstraineddelegation = true
                AND NOT n.objectid ENDS WITH '-516' {domain_filter}
                RETURN n.name AS name, labels(n)[0] AS type, n.enabled AS enabled
                ORDER BY labels(n)[0]
                """
                results = bh.run_query(query, params)
                if output_results("Unconstrained Delegation", results, ["name", "type", "enabled"]):
                    return
            get_unconstrained_delegation(bh, args.domain, Severity.HIGH)
            return

        if args.no_laps:
            if config.output_format != "table":
                domain_filter = "AND toUpper(c.domain) = toUpper($domain)" if args.domain else ""
                params = {"domain": args.domain} if args.domain else {}
                query = f"""
                MATCH (c:Computer)
                WHERE (c.haslaps IS NULL OR c.haslaps = false)
                AND c.enabled = true {domain_filter}
                RETURN c.name AS name, c.operatingsystem AS os, c.enabled AS enabled
                ORDER BY c.name
                """
                results = bh.run_query(query, params)
                if output_results("Computers Without LAPS", results, ["name", "os", "enabled"]):
                    return
            get_computers_without_laps(bh, args.domain, Severity.MEDIUM)
            return

        if args.computers:
            results = bh.get_all_computers(args.domain)
            if results:
                columns = ["name", "os", "enabled", "laps", "unconstrained"]
                if output_results("All Domain Computers", results, columns):
                    return
                # Table output
                print_header("All Domain Computers", Severity.INFO, len(results))
                table = PrettyTable()
                table.field_names = ["Computer", "OS", "Enabled", "LAPS", "Unconstrained"]
                table.align = "l"
                for r in results:
                    table.add_row(
                        [
                            r["name"],
                            r["os"] or "Unknown",
                            "Yes" if r["enabled"] else "No",
                            "Yes" if r["laps"] else "No",
                            "Yes" if r["unconstrained"] else "No",
                        ]
                    )
                print(table)
                print(f"\n    Total: {len(results)} computer(s)")
            else:
                if config.output_format == "json":
                    print("[]")
                elif config.output_format == "csv":
                    print("name,os,enabled,laps,unconstrained")
                else:
                    print_warning("No computers found")
            return

        if args.users:
            results = bh.get_all_users(args.domain)
            if results:
                columns = ["name", "enabled", "admin", "spn", "asrep", "neverexpires"]
                if output_results("All Domain Users", results, columns):
                    return
                # Table output
                print_header("All Domain Users", Severity.INFO, len(results))
                table = PrettyTable()
                table.field_names = ["User", "Enabled", "Admin", "SPN", "AS-REP", "PwdNeverExpires"]
                table.align = "l"
                for r in results:
                    table.add_row(
                        [
                            r["name"],
                            "Yes" if r["enabled"] else "No",
                            "Yes" if r["admin"] else "No",
                            "Yes" if r["spn"] else "No",
                            "Yes" if r["asrep"] else "No",
                            "Yes" if r["neverexpires"] else "No",
                        ]
                    )
                print(table)
                print(f"\n    Total: {len(results)} user(s)")
            else:
                if config.output_format == "json":
                    print("[]")
                elif config.output_format == "csv":
                    print("name,enabled,admin,spn,asrep,neverexpires")
                else:
                    print_warning("No users found")
            return

        if args.spns:
            results = bh.get_all_spns(args.domain)
            if results:
                columns = ["account", "spn", "enabled", "admin"]
                if output_results("All Service Principal Names", results, columns):
                    return
                # Table output
                print_header("All Service Principal Names", Severity.INFO, len(results))
                table = PrettyTable()
                table.field_names = ["Account", "SPN", "Enabled", "Admin"]
                table.align = "l"
                for r in results:
                    table.add_row(
                        [
                            r["account"],
                            r["spn"],
                            "Yes" if r["enabled"] else "No",
                            "Yes" if r["admin"] else "No",
                        ]
                    )
                print(table)
                print(f"\n    Total: {len(results)} SPN(s)")
            else:
                if config.output_format == "json":
                    print("[]")
                elif config.output_format == "csv":
                    print("account,spn,enabled,admin")
                else:
                    print_warning("No SPNs found")
            return

        if args.quick_wins:
            results = bh.get_quick_wins(args.domain)

            # Handle structured output formats
            if config.output_format == "json":
                print(json.dumps(results, indent=2, default=str))
                return
            elif config.output_format == "csv":
                writer = csv.writer(sys.stdout)
                writer.writerow(["category", "principal", "detail", "severity"])
                for r in results.get("short_paths_to_da", []):
                    path_str = " -> ".join(r.get("nodes", []))
                    writer.writerow(["short_path_to_da", r["principal"], path_str, "CRITICAL"])
                for r in results.get("kerberoastable_admins", []):
                    writer.writerow(
                        ["kerberoastable_admin", r["account"], r.get("spn", ""), "HIGH"]
                    )
                for r in results.get("asrep_roastable", []):
                    writer.writerow(
                        ["asrep_roastable", r["account"], f"admin={r.get('admin', False)}", "HIGH"]
                    )
                for r in results.get("direct_acl_abuse", []):
                    writer.writerow(
                        [
                            "direct_acl_abuse",
                            r["principal"],
                            f"{r['permission']} -> {r['target']}",
                            "MEDIUM",
                        ]
                    )
                return
            elif config.output_format == "html":
                # Flatten results for HTML table
                from hackles.display.report import generate_simple_html

                flat_data = []
                for r in results.get("short_paths_to_da", []):
                    path_str = " -> ".join(r.get("nodes", []))
                    flat_data.append(
                        {
                            "category": "Direct Path to DA",
                            "principal": r["principal"],
                            "detail": path_str,
                            "severity": "CRITICAL",
                        }
                    )
                for r in results.get("kerberoastable_admins", []):
                    flat_data.append(
                        {
                            "category": "Kerberoastable Admin",
                            "principal": r["account"],
                            "detail": r.get("spn", ""),
                            "severity": "HIGH",
                        }
                    )
                for r in results.get("asrep_roastable", []):
                    flat_data.append(
                        {
                            "category": "AS-REP Roastable",
                            "principal": r["account"],
                            "detail": f"admin={r.get('admin', False)}",
                            "severity": "HIGH",
                        }
                    )
                for r in results.get("direct_acl_abuse", []):
                    flat_data.append(
                        {
                            "category": "Direct ACL Abuse",
                            "principal": r["principal"],
                            "detail": f"{r['permission']} -> {r['target']}",
                            "severity": "MEDIUM",
                        }
                    )
                if _html_output_path:
                    generate_simple_html(
                        "Quick Wins Summary",
                        ["category", "principal", "detail", "severity"],
                        flat_data,
                        _html_output_path,
                    )
                    print(f"HTML report saved to: {_html_output_path}")
                return

            # Table output
            print(f"\n{colors.BOLD}{'='*70}")
            print(f"{'QUICK WINS SUMMARY':^70}")
            print(f"{'='*70}{colors.END}\n")

            # Short paths to DA
            if results["short_paths_to_da"]:
                print(
                    f"{colors.FAIL}[CRITICAL] Direct Paths to Domain Admins (1-2 hops){colors.END}"
                )
                table = PrettyTable()
                table.field_names = ["Principal", "Hops", "Path"]
                table.align = "l"
                for r in results["short_paths_to_da"]:
                    # Build path string: -[Rel1]-> Node1 -[Rel2]-> Node2 ...
                    nodes = r["nodes"]
                    rels = r["path"]
                    path_parts = []
                    for i, rel in enumerate(rels):
                        path_parts.append(f"-[{rel}]-> {nodes[i + 1]}")
                    path_str = " ".join(path_parts)
                    table.add_row([r["principal"], r["hops"], path_str])
                print(table)
                print()
            else:
                print(
                    f"{colors.GREEN}[+] No direct paths (1-2 hops) to Domain Admins{colors.END}\n"
                )

            # Kerberoastable admins
            if results["kerberoastable_admins"]:
                print(
                    f"{colors.FAIL}[HIGH] Kerberoastable Admins (crack for instant privilege){colors.END}"
                )
                table = PrettyTable()
                table.field_names = ["Account", "SPN", "Password Age (days)", "Privilege"]
                table.align = "l"
                for r in results["kerberoastable_admins"]:
                    table.add_row(
                        [
                            r["account"],
                            r["spn"] or "Multiple",
                            r["password_age_days"] or "Unknown",
                            r["privilege"],
                        ]
                    )
                print(table)
                print()
            else:
                print(f"{colors.GREEN}[+] No Kerberoastable admin accounts{colors.END}\n")

            # AS-REP roastable
            if results["asrep_roastable"]:
                print(f"{colors.WARNING}[HIGH] AS-REP Roastable (no pre-auth required){colors.END}")
                table = PrettyTable()
                table.field_names = ["Account", "Admin"]
                table.align = "l"
                for r in results["asrep_roastable"]:
                    table.add_row([r["account"], "Yes" if r["admin"] else "No"])
                print(table)
                print()
            else:
                print(f"{colors.GREEN}[+] No AS-REP roastable accounts{colors.END}\n")

            # Direct ACL abuse
            if results["direct_acl_abuse"]:
                print(
                    f"{colors.WARNING}[MEDIUM] Direct ACL Abuse to High Value Targets{colors.END}"
                )
                table = PrettyTable()
                table.field_names = ["Principal", "Permission", "Target"]
                table.align = "l"
                for r in results["direct_acl_abuse"]:
                    table.add_row([r["principal"], r["permission"], r["target"]])
                print(table)
                print()
            else:
                print(
                    f"{colors.GREEN}[+] No direct ACL abuse paths to high-value targets{colors.END}\n"
                )

            # Summary
            total = (
                len(results["short_paths_to_da"])
                + len(results["kerberoastable_admins"])
                + len(results["asrep_roastable"])
                + len(results["direct_acl_abuse"])
            )
            if total > 0:
                print(f"{colors.BOLD}Total quick wins found: {total}{colors.END}")
            else:
                print(
                    f"{colors.GREEN}No obvious quick wins found - deeper analysis required{colors.END}"
                )
            return

        # === SECURITY AUDIT ===
        if args.audit:
            results = bh.get_audit_results(args.domain)

            # Handle structured output formats
            if config.output_format == "json":
                print(json.dumps(results, indent=2, default=str))
                return
            elif config.output_format == "csv":
                writer = csv.writer(sys.stdout)
                writer.writerow(["category", "finding", "detail", "severity"])
                for r in results.get("kerberoastable_admins", []):
                    writer.writerow(
                        ["kerberoastable_admin", r["name"], r.get("displayname", ""), "HIGH"]
                    )
                for r in results.get("asrep_roastable", []):
                    writer.writerow(
                        ["asrep_roastable", r["name"], f"admin={r.get('admin', False)}", "HIGH"]
                    )
                for r in results.get("unconstrained_delegation", []):
                    writer.writerow(
                        ["unconstrained_delegation", r["name"], r.get("os", ""), "HIGH"]
                    )
                for r in results.get("unsupported_os", []):
                    writer.writerow(["unsupported_os", r["name"], r.get("os", ""), "MEDIUM"])
                writer.writerow(
                    ["no_laps", f"{results.get('no_laps_count', 0)} computers", "", "MEDIUM"]
                )
                for r in results.get("guest_enabled", []):
                    writer.writerow(["guest_enabled", r["name"], r.get("domain", ""), "HIGH"])
                for r in results.get("pwd_never_expires_admins", []):
                    writer.writerow(["pwd_never_expires_admin", r["name"], "", "MEDIUM"])
                writer.writerow(
                    ["users_path_to_da", f"{results.get('users_path_to_da', 0)} users", "", "HIGH"]
                )
                return
            elif config.output_format == "html":
                from hackles.display.report import generate_simple_html

                flat_data = []
                for r in results.get("kerberoastable_admins", []):
                    flat_data.append(
                        {
                            "category": "Kerberoastable Admin",
                            "finding": r["name"],
                            "detail": r.get("displayname", ""),
                            "severity": "HIGH",
                        }
                    )
                for r in results.get("asrep_roastable", []):
                    flat_data.append(
                        {
                            "category": "AS-REP Roastable",
                            "finding": r["name"],
                            "detail": f"admin={r.get('admin', False)}",
                            "severity": "HIGH",
                        }
                    )
                for r in results.get("unconstrained_delegation", []):
                    flat_data.append(
                        {
                            "category": "Unconstrained Delegation",
                            "finding": r["name"],
                            "detail": r.get("os", ""),
                            "severity": "HIGH",
                        }
                    )
                for r in results.get("unsupported_os", []):
                    flat_data.append(
                        {
                            "category": "Unsupported OS",
                            "finding": r["name"],
                            "detail": r.get("os", ""),
                            "severity": "MEDIUM",
                        }
                    )
                if results.get("no_laps_count", 0) > 0:
                    flat_data.append(
                        {
                            "category": "No LAPS",
                            "finding": f"{results['no_laps_count']} computers",
                            "detail": "",
                            "severity": "MEDIUM",
                        }
                    )
                for r in results.get("guest_enabled", []):
                    flat_data.append(
                        {
                            "category": "Guest Enabled",
                            "finding": r["name"],
                            "detail": r.get("domain", ""),
                            "severity": "HIGH",
                        }
                    )
                for r in results.get("pwd_never_expires_admins", []):
                    flat_data.append(
                        {
                            "category": "Admin Pwd Never Expires",
                            "finding": r["name"],
                            "detail": "",
                            "severity": "MEDIUM",
                        }
                    )
                if results.get("users_path_to_da", 0) > 0:
                    flat_data.append(
                        {
                            "category": "Path to DA",
                            "finding": f"{results['users_path_to_da']} users",
                            "detail": "",
                            "severity": "HIGH",
                        }
                    )
                if _html_output_path:
                    generate_simple_html(
                        "Security Audit Report",
                        ["category", "finding", "detail", "severity"],
                        flat_data,
                        _html_output_path,
                    )
                    print(f"HTML report saved to: {_html_output_path}")
                return

            # Table output
            print(f"\n{colors.BOLD}{'='*70}")
            print(f"{'SECURITY AUDIT REPORT':^70}")
            print(f"{'='*70}{colors.END}\n")

            # Kerberoastable Admins
            if results["kerberoastable_admins"]:
                print(
                    f"{colors.FAIL}[HIGH] Kerberoastable Admin Accounts ({len(results['kerberoastable_admins'])}){colors.END}"
                )
                table = PrettyTable()
                table.field_names = ["Name", "Display Name"]
                table.align = "l"
                for r in results["kerberoastable_admins"]:
                    table.add_row([r["name"], r.get("displayname", "") or ""])
                print(table)
                print()
            else:
                print(f"{colors.GREEN}[+] No Kerberoastable admin accounts{colors.END}\n")

            # AS-REP Roastable
            if results["asrep_roastable"]:
                print(
                    f"{colors.FAIL}[HIGH] AS-REP Roastable Users ({len(results['asrep_roastable'])}){colors.END}"
                )
                table = PrettyTable()
                table.field_names = ["Name", "Admin"]
                table.align = "l"
                for r in results["asrep_roastable"]:
                    table.add_row([r["name"], "Yes" if r.get("admin") else "No"])
                print(table)
                print()
            else:
                print(f"{colors.GREEN}[+] No AS-REP roastable accounts{colors.END}\n")

            # Unconstrained Delegation
            if results["unconstrained_delegation"]:
                print(
                    f"{colors.FAIL}[HIGH] Unconstrained Delegation (non-DC) ({len(results['unconstrained_delegation'])}){colors.END}"
                )
                table = PrettyTable()
                table.field_names = ["Computer", "Operating System"]
                table.align = "l"
                for r in results["unconstrained_delegation"]:
                    table.add_row([r["name"], r.get("os", "") or ""])
                print(table)
                print()
            else:
                print(
                    f"{colors.GREEN}[+] No non-DC systems with unconstrained delegation{colors.END}\n"
                )

            # Unsupported OS
            if results["unsupported_os"]:
                print(
                    f"{colors.WARNING}[MEDIUM] Unsupported Operating Systems ({len(results['unsupported_os'])}){colors.END}"
                )
                table = PrettyTable()
                table.field_names = ["Computer", "Operating System"]
                table.align = "l"
                for r in results["unsupported_os"]:
                    table.add_row([r["name"], r.get("os", "") or ""])
                print(table)
                print()
            else:
                print(f"{colors.GREEN}[+] No unsupported operating systems{colors.END}\n")

            # Computers without LAPS
            no_laps = results.get("no_laps_count", 0)
            if no_laps > 0:
                print(f"{colors.WARNING}[MEDIUM] Computers without LAPS: {no_laps}{colors.END}\n")
            else:
                print(f"{colors.GREEN}[+] All enabled computers have LAPS{colors.END}\n")

            # Guest Accounts Enabled
            if results["guest_enabled"]:
                print(
                    f"{colors.FAIL}[HIGH] Guest Accounts Enabled ({len(results['guest_enabled'])}){colors.END}"
                )
                table = PrettyTable()
                table.field_names = ["Name", "Domain"]
                table.align = "l"
                for r in results["guest_enabled"]:
                    table.add_row([r["name"], r.get("domain", "") or ""])
                print(table)
                print()
            else:
                print(f"{colors.GREEN}[+] No enabled guest accounts{colors.END}\n")

            # Admin Password Never Expires
            if results["pwd_never_expires_admins"]:
                print(
                    f"{colors.WARNING}[MEDIUM] Admin Password Never Expires ({len(results['pwd_never_expires_admins'])}){colors.END}"
                )
                table = PrettyTable()
                table.field_names = ["Name"]
                table.align = "l"
                for r in results["pwd_never_expires_admins"]:
                    table.add_row([r["name"]])
                print(table)
                print()
            else:
                print(
                    f"{colors.GREEN}[+] No admin accounts with password never expires{colors.END}\n"
                )

            # Users with Path to DA
            path_count = results.get("users_path_to_da", 0)
            if path_count > 0:
                print(
                    f"{colors.FAIL}[HIGH] Users with Path to Domain Admins: {path_count}{colors.END}\n"
                )
            else:
                print(f"{colors.GREEN}[+] No users with direct path to Domain Admins{colors.END}\n")

            # Summary
            print(f"\n{colors.BOLD}Audit Summary:{colors.END}")
            print(f"  Kerberoastable Admins:      {len(results.get('kerberoastable_admins', []))}")
            print(f"  AS-REP Roastable:           {len(results.get('asrep_roastable', []))}")
            print(
                f"  Unconstrained Delegation:   {len(results.get('unconstrained_delegation', []))}"
            )
            print(f"  Unsupported OS:             {len(results.get('unsupported_os', []))}")
            print(f"  Computers without LAPS:     {results.get('no_laps_count', 0)}")
            print(f"  Guest Accounts Enabled:     {len(results.get('guest_enabled', []))}")
            print(
                f"  Admin Pwd Never Expires:    {len(results.get('pwd_never_expires_admins', []))}"
            )
            print(f"  Users with Path to DA:      {results.get('users_path_to_da', 0)}")
            return

        # Validate domain if specified
        domain = args.domain
        if domain:
            domains = bh.get_domains()
            domain_names = [d["name"].upper() for d in domains]
            if domain.upper() not in domain_names:
                status_print(
                    f"{colors.FAIL}[!] Domain '{domain}' not found in database{colors.END}"
                )
                status_print(f"    Available domains: {', '.join(d['name'] for d in domains)}")
                sys.exit(1)
            status_print(f"{colors.BLUE}[*] Filtering by domain: {domain}{colors.END}")

        # Load custom queries if specified
        custom_queries = []
        if args.custom:
            for path in args.custom:
                try:
                    loaded = load_custom_queries(path)
                    custom_queries.extend(loaded)
                    p = Path(path)
                    if p.is_dir():
                        status_print(
                            f"{colors.GREEN}[+] Loaded {len(loaded)} custom query(ies) from {path}/{colors.END}"
                        )
                    else:
                        status_print(
                            f"{colors.GREEN}[+] Loaded custom query: {loaded[0][0]}{colors.END}"
                        )
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
            status_print(
                f"{colors.BLUE}[*] Running all {len(selected_queries)} queries...{colors.END}"
            )
        elif selected_categories:
            # Run queries from selected categories
            registry = get_query_registry()
            selected_queries = [
                (name, func, sev)
                for name, func, cat, _, sev in registry
                if cat in selected_categories
            ]
            # Add custom queries if specified
            selected_queries.extend([(name, func, sev) for name, func, _, _, sev in custom_queries])
            cat_str = ", ".join(selected_categories)
            status_print(
                f"{colors.BLUE}[*] Running {len(selected_queries)} queries from: {cat_str}{colors.END}"
            )
        elif custom_queries:
            # Custom queries only
            selected_queries = [(name, func, sev) for name, func, _, _, sev in custom_queries]
            status_print(
                f"{colors.BLUE}[*] Running {len(selected_queries)} custom queries...{colors.END}"
            )
        else:
            # No queries selected - show help
            status_print(
                f"{colors.WARNING}[!] No queries selected. Use -a for all, or specify categories:{colors.END}"
            )
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
            status_print(
                f"{colors.WARNING}[!] No queries matched the selected categories{colors.END}"
            )
            return

        # Apply severity filter
        if config.severity_filter:
            filtered_queries = [
                (name, func, sev)
                for name, func, sev in selected_queries
                if sev.label in config.severity_filter
            ]
            skipped = len(selected_queries) - len(filtered_queries)
            if skipped > 0:
                status_print(
                    f"{colors.BLUE}[*] Filtered to {len(filtered_queries)} queries (skipped {skipped} by severity){colors.END}"
                )
            selected_queries = filtered_queries

        if not selected_queries:
            status_print(
                f"{colors.WARNING}[!] No queries match the severity filter: {', '.join(config.severity_filter)}{colors.END}"
            )
            return

        if config.output_format == "table":
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
                if config.debug_mode and config.output_format == "table":
                    print(f"    {colors.CYAN}[{elapsed:.2f}s]{colors.END}")

                # For structured output, retrieve accumulated results from the query
                if config.output_format != "table":
                    # Get accumulated results (handles queries with multiple sub-queries)
                    results = bh.accumulated_results.copy() if bh.accumulated_results else []
                    return count, results, elapsed
                else:
                    return count, [], elapsed
            except Exception as e:
                elapsed = time.time() - query_start
                if config.output_format == "table":
                    print(f"{colors.FAIL}[!] Error running '{name}': {e}{colors.END}")
                    if config.debug_mode:
                        import traceback

                        traceback.print_exc()
                return 0, [], elapsed

        if config.show_progress and config.output_format == "table":
            try:
                from rich.progress import (
                    BarColumn,
                    Progress,
                    SpinnerColumn,
                    TaskProgressColumn,
                    TextColumn,
                )

                with Progress(
                    SpinnerColumn(),
                    TextColumn("[cyan]{task.description}"),
                    BarColumn(),
                    TaskProgressColumn(),
                    transient=True,
                ) as progress:
                    task = progress.add_task("Running queries...", total=len(selected_queries))
                    for name, func, severity in selected_queries:
                        progress.update(task, description=f"[cyan]{name[:50]}")
                        result_count, results, elapsed = run_query(name, func, severity)
                        query_timings.append((name, elapsed, result_count))
                        if result_count > 0 and severity != Severity.INFO:
                            severity_counts[severity] += 1
                        all_results.append(
                            {
                                "query": name,
                                "severity": severity.label,
                                "count": result_count,
                                "results": results,
                            }
                        )
                        progress.update(task, advance=1)
            except ImportError:
                # Rich not installed, fall back to normal execution
                for name, func, severity in selected_queries:
                    result_count, results, elapsed = run_query(name, func, severity)
                    query_timings.append((name, elapsed, result_count))
                    if result_count > 0 and severity != Severity.INFO:
                        severity_counts[severity] += 1
                    all_results.append(
                        {
                            "query": name,
                            "severity": severity.label,
                            "count": result_count,
                            "results": results,
                        }
                    )
        else:
            for name, func, severity in selected_queries:
                result_count, results, elapsed = run_query(name, func, severity)
                query_timings.append((name, elapsed, result_count))
                if result_count > 0 and severity != Severity.INFO:
                    severity_counts[severity] += 1
                all_results.append(
                    {
                        "query": name,
                        "severity": severity.label,
                        "count": result_count,
                        "results": results,
                    }
                )

        elapsed = time.time() - start_time

        # Output results based on format
        if config.output_format == "json":
            output_json(all_results)
        elif config.output_format == "csv":
            output_csv(all_results)
        elif config.output_format == "html":
            from hackles.display.report import generate_html_report

            generate_html_report(all_results, args.html)
            print(f"{colors.GREEN}[+] HTML report saved to: {args.html}{colors.END}")
            print_severity_summary(severity_counts)
            print(f"\n{colors.GREEN}[+] Analysis completed in {elapsed:.2f}s{colors.END}")
            print(f"    Ran {len(selected_queries)} queries")
        else:
            # Table output - already printed during execution
            print_severity_summary(severity_counts)
            print(f"\n{colors.GREEN}[+] Analysis completed in {elapsed:.2f}s{colors.END}")
            print(f"    Ran {len(selected_queries)} queries")

        # Show timing summary in debug mode
        if config.debug_mode and query_timings and config.output_format == "table":
            print(f"\n{colors.CYAN}[*] Query Timing Summary (slowest first){colors.END}")
            sorted_timings = sorted(query_timings, key=lambda x: -x[1])[:10]
            for name, timing, count in sorted_timings:
                print(f"    {timing:.2f}s - {name} ({count} results)")

    finally:
        bh.close()


if __name__ == "__main__":
    main()
