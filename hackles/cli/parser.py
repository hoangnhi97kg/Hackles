"""Argparse definitions for Hackles CLI"""
import argparse
from hackles.cli.formatter import ColoredHelpFormatter


def create_parser() -> argparse.ArgumentParser:
    """Create and configure the argument parser.

    Returns:
        Configured ArgumentParser instance
    """
    parser = argparse.ArgumentParser(
        description="Extract quick wins from BloodHound Community Edition",
        formatter_class=ColoredHelpFormatter
    )
    conn_group = parser.add_argument_group('Connection')
    conn_group.add_argument('-b', '--bolt', default='bolt://127.0.0.1:7687',
                           help='Neo4j Bolt URL (default: bolt://127.0.0.1:7687)')
    conn_group.add_argument('-u', '--username', default='neo4j',
                           help='Neo4j username (default: neo4j)')
    conn_group.add_argument('-p', '--password', required=True,
                           help='Neo4j password')
    query_group = parser.add_argument_group('Query Options')
    query_group.add_argument('-d', '--domain',
                            help='Filter by domain (case-insensitive)')
    query_group.add_argument('-l', '--list', action='store_true',
                            help='List domains and exit')
    query_group.add_argument('-a', '--all', action='store_true',
                            help='Run all queries without interactive selection')
    query_group.add_argument('-q', '--quiet', action='store_true',
                            help='Hide banner and zero-result queries')
    query_group.add_argument('--abuse', action='store_true',
                            help='Show attack commands and exploitation templates')
    query_group.add_argument('--abuse-var', action='append', metavar='KEY=VALUE',
                            help='Set abuse template variable (e.g., DC_IP=192.168.1.10)')
    query_group.add_argument('--abuse-config', metavar='FILE',
                            help='Load abuse variables from config file')
    query_group.add_argument('--debug', action='store_true',
                            help='Show query execution details')
    query_group.add_argument('-c', '--custom', action='append',
                            help='Load custom Cypher queries from file or directory')
    query_group.add_argument('--severity', metavar='LEVELS',
                            help='Filter by severity (comma-separated: CRITICAL,HIGH,MEDIUM,LOW,INFO)')
    query_group.add_argument('--stats', action='store_true',
                            help='Show domain statistics and exit')
    query_group.add_argument('--stale-days', type=int, default=90, metavar='N',
                            help='Days threshold for stale accounts (default: 90)')
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument('--json', action='store_true',
                             help='Output results as JSON')
    output_group.add_argument('--csv', action='store_true',
                             help='Output results as CSV')
    output_group.add_argument('--html', metavar='FILE',
                             help='Generate HTML report to specified file')
    output_group.add_argument('--no-color', action='store_true',
                             help='Disable colored output')
    output_group.add_argument('--progress', action='store_true',
                             help='Show progress bar during execution')
    owned_group = parser.add_argument_group('Owned Management')
    owned_group.add_argument('-o', '--own', action='append', metavar='PRINCIPAL',
                            help='Mark principal as owned')
    owned_group.add_argument('--unown', metavar='PRINCIPAL',
                            help='Remove owned status from principal')
    owned_group.add_argument('--clear-owned', action='store_true',
                            help='Remove owned status from ALL principals')
    owned_group.add_argument('--from-owned', metavar='PRINCIPAL',
                            help='Filter owned queries to specific principal')
    tier_group = parser.add_argument_group('Tier Zero Management')
    tier_group.add_argument('--tier-zero', action='append', metavar='PRINCIPAL',
                           help='Mark principal as Tier Zero')
    tier_group.add_argument('--untier-zero', metavar='PRINCIPAL',
                           help='Remove Tier Zero status from principal')
    path_group = parser.add_argument_group('Path Finding')
    path_group.add_argument('--path', nargs=2, metavar=('SOURCE', 'TARGET'),
                           help='Find shortest paths between two nodes')
    path_group.add_argument('--path-to-da', metavar='PRINCIPAL',
                           help='Find paths from principal to Domain Admins')
    path_group.add_argument('--path-to-dc', metavar='PRINCIPAL',
                           help='Find paths from principal to Domain Controllers')
    path_group.add_argument('--max-path-depth', type=int, default=5, metavar='N',
                           help='Maximum hops in path queries (default: 5)')
    path_group.add_argument('--max-paths', type=int, default=25, metavar='N',
                           help='Maximum paths to return (default: 25)')
    node_group = parser.add_argument_group('Node Operations')
    node_group.add_argument('--info', metavar='PRINCIPAL',
                           help='Show all properties and labels for a node')
    node_group.add_argument('--search', metavar='TERM',
                           help='Search nodes by name (* wildcard supported)')
    group_group = parser.add_argument_group('Group & Membership')
    group_group.add_argument('--members', metavar='GROUP',
                            help='List all members of a group (recursive)')
    group_group.add_argument('--memberof', metavar='PRINCIPAL',
                            help='List all groups a principal belongs to')
    admin_group = parser.add_argument_group('Admin Rights')
    admin_group.add_argument('--adminto', metavar='COMPUTER',
                            help='List principals with admin rights to a computer')
    admin_group.add_argument('--adminof', metavar='PRINCIPAL',
                            help='List computers a principal has admin rights to')
    admin_group.add_argument('--sessions', metavar='COMPUTER',
                            help='List active sessions on a computer')
    edge_group = parser.add_argument_group('Edge Exploration')
    edge_group.add_argument('--edges-from', metavar='PRINCIPAL',
                           help='List outbound attack edges from a principal')
    edge_group.add_argument('--edges-to', metavar='PRINCIPAL',
                           help='List inbound attack edges to a principal')
    filter_group = parser.add_argument_group('Quick Filters')
    filter_group.add_argument('--kerberoastable', action='store_true',
                             help='List all Kerberoastable users')
    filter_group.add_argument('--asrep', action='store_true',
                             help='List all AS-REP Roastable users')
    filter_group.add_argument('--unconstrained', action='store_true',
                             help='List all unconstrained delegation principals')
    filter_group.add_argument('--no-laps', action='store_true',
                             help='List all computers without LAPS')

    # Query categories (can combine multiple)
    cat_group = parser.add_argument_group('Query Categories (combine with -a for all, or select specific)')
    cat_group.add_argument('--acl', action='store_true',
                          help='Run ACL Abuse queries')
    cat_group.add_argument('--adcs', action='store_true',
                          help='Run ADCS/Certificate queries')
    cat_group.add_argument('--attack-paths', action='store_true',
                          help='Run Attack Path queries')
    cat_group.add_argument('--azure', action='store_true',
                          help='Run Azure/Hybrid queries')
    cat_group.add_argument('--basic', action='store_true',
                          help='Run Basic Info/Domain queries')
    cat_group.add_argument('--groups', action='store_true',
                          help='Run Dangerous Groups queries')
    cat_group.add_argument('--delegation', action='store_true',
                          help='Run Delegation queries')
    cat_group.add_argument('--exchange', action='store_true',
                          help='Run Exchange queries')
    cat_group.add_argument('--lateral', action='store_true',
                          help='Run Lateral Movement queries')
    cat_group.add_argument('--misc', action='store_true',
                          help='Run Miscellaneous queries')
    cat_group.add_argument('--owned-queries', action='store_true',
                          help='Run Owned principal queries')
    cat_group.add_argument('--privesc', action='store_true',
                          help='Run Privilege Escalation queries')
    cat_group.add_argument('--hygiene', action='store_true',
                          help='Run Security Hygiene queries')

    return parser
