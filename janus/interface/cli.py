# janus/interface/cli.py
"""
Janus CLI - Beautiful command-line interface using Typer and Rich.
Now with CVE lookup, Shadow API detection, and GraphQL attacks.
"""

import typer
from typing import Optional
from pathlib import Path
import json
import sys
import os

# Add parent to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import print as rprint

from janus.core.engine import JanusEngine
from janus.core.database import JanusDatabase
from janus.recon.cve_lookup import CVELookup
from janus.recon.shadow import ShadowAPIDetector
from janus.attack.graphql import GraphQLAttacker
from janus.attack.bfla import BFLAScanner
from janus.attack.race_condition import RaceConditionTester
from janus.analysis.pii_scanner import PIIScanner

app = typer.Typer(
    name="janus",
    help="🔱 Janus - BOLA/IDOR Vulnerability Scanner with Local Intelligence",
    add_completion=False
)
console = Console()

BANNER = """
[bold red]
       ██╗ █████╗ ███╗   ██╗██╗   ██╗███████╗
       ██║██╔══██╗████╗  ██║██║   ██║██╔════╝
       ██║███████║██╔██╗ ██║██║   ██║███████╗
  ██   ██║██╔══██║██║╚██╗██║██║   ██║╚════██║
  ╚█████╔╝██║  ██║██║ ╚████║╚██████╔╝███████║
   ╚════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚══════╝
[/bold red]
[dim]BOLA Detection with Local Intelligence - No AI APIs Required[/dim]
"""


def print_banner():
    console.print(BANNER)


@app.command()
def scan(
    victim_token: str = typer.Option(..., "--victim", "-v", help="Token of the victim user (learned)"),
    attacker_token: str = typer.Option(..., "--attacker", "-a", help="Token of the attacker"),
    host: str = typer.Option("http://localhost:5000", "--host", "-h", help="Target API base URL"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file for JSON report"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Minimal output"),
):
    """
    🔥 Run a BOLA attack scan against the target API.
    
    Uses learned traffic patterns to detect authorization vulnerabilities.
    """
    if not quiet:
        print_banner()
    
    console.print(f"\n[bold cyan]Target:[/bold cyan] {host}")
    console.print(f"[bold cyan]Victim Token:[/bold cyan] {victim_token[:20]}...")
    console.print(f"[bold cyan]Attacker Token:[/bold cyan] {attacker_token[:20]}...\n")
    
    # Initialize engine
    engine = JanusEngine()
    
    # Run scan with progress
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        progress.add_task(description="Scanning endpoints...", total=None)
        report = engine.launch_attack(victim_token, attacker_token, host)
    
    # Display results
    console.print("\n")
    
    # Summary panel
    summary_text = f"""
[bold]Scan ID:[/bold] {report.scan_id}
[bold]Duration:[/bold] {report.start_time} → {report.end_time}
[bold]Total Endpoints:[/bold] {report.total_endpoints}
    """
    console.print(Panel(summary_text, title="[bold blue]Scan Summary[/bold blue]", border_style="blue"))
    
    # Results table
    table = Table(title="🔍 Scan Results", show_header=True, header_style="bold magenta")
    table.add_column("Endpoint", style="cyan", max_width=50)
    table.add_column("Method", justify="center")
    table.add_column("Status", justify="center")
    table.add_column("Confidence", justify="right")
    table.add_column("Severity", justify="center")
    
    for finding in report.findings:
        # Color-code status
        if finding.status == "VULNERABLE":
            status_str = "[bold red]🚨 VULNERABLE[/bold red]"
            severity_str = f"[red]{finding.severity}[/red]"
        elif finding.status == "BLOCKED":
            status_str = "[green]✓ BLOCKED[/green]"
            severity_str = f"[dim]{finding.severity}[/dim]"
        elif finding.status == "FALSE_POSITIVE":
            status_str = "[yellow]⚠ FALSE_POS[/yellow]"
            severity_str = f"[yellow]{finding.severity}[/yellow]"
        else:
            status_str = f"[dim]{finding.status}[/dim]"
            severity_str = f"[dim]{finding.severity}[/dim]"
        
        table.add_row(
            finding.endpoint,
            finding.method,
            status_str,
            f"{finding.confidence:.0%}",
            severity_str
        )
    
    console.print(table)
    
    # Vulnerabilities found
    if report.vulnerabilities_found > 0:
        console.print(f"\n[bold red]🚨 {report.vulnerabilities_found} VULNERABILITIES FOUND![/bold red]")
        for f in report.findings:
            if f.status == "VULNERABLE":
                console.print(f"  [red]•[/red] {f.endpoint}")
                console.print(f"    [dim]{f.evidence}[/dim]")
    else:
        console.print("\n[bold green]✓ No vulnerabilities detected[/bold green]")
    
    # Save report
    output_path = output or Path("janus_report.json")
    engine.save_report(report, str(output_path))
    console.print(f"\n[dim]Report saved to {output_path}[/dim]")


@app.command()
def tokens():
    """
    📋 List all learned tokens from the database.
    """
    print_banner()
    
    db = JanusDatabase()
    tokens = db.get_all_tokens()
    
    if not tokens:
        console.print("[yellow]No tokens learned yet. Run the proxy to capture traffic.[/yellow]")
        return
    
    table = Table(title="Learned Tokens", show_header=True, header_style="bold cyan")
    table.add_column("#", justify="right", style="dim")
    table.add_column("Token", style="cyan")
    table.add_column("Resources", justify="right")
    
    for i, token in enumerate(tokens):
        learnings = db.get_learnings(token)
        table.add_row(str(i), token[:40] + "..." if len(token) > 40 else token, str(len(learnings)))
    
    console.print(table)


@app.command()
def clear(
    token: Optional[str] = typer.Option(None, "--token", "-t", help="Clear specific token"),
    all_data: bool = typer.Option(False, "--all", help="Clear all learned data"),
):
    """
    🗑️ Clear learned data from the database.
    """
    db = JanusDatabase()
    
    if all_data:
        if typer.confirm("Are you sure you want to clear ALL learned data?"):
            db.clear_all()
            console.print("[green]All data cleared.[/green]")
    elif token:
        db.clear_token(token)
        console.print(f"[green]Cleared data for token: {token[:20]}...[/green]")
    else:
        console.print("[yellow]Specify --token or --all[/yellow]")


@app.command()
def info():
    """
    ℹ️ Show Janus configuration and status.
    """
    print_banner()
    
    db = JanusDatabase()
    
    info_table = Table(show_header=False, box=None)
    info_table.add_column("Key", style="bold cyan")
    info_table.add_column("Value")
    
    info_table.add_row("Storage Backend", db.backend_name.upper())
    info_table.add_row("Learned Tokens", str(len(db.get_all_tokens())))
    info_table.add_row("Version", "1.0.0")
    
    console.print(Panel(info_table, title="[bold]Janus Status[/bold]", border_style="blue"))


@app.command()
def proxy(
    target: str = typer.Option("http://localhost:5000", "--target", "-t", help="Target API to proxy"),
    port: int = typer.Option(8080, "--port", "-p", help="Proxy listen port"),
):
    """
    🌐 Start the learning proxy (requires mitmproxy).
    """
    print_banner()
    
    console.print(f"[bold cyan]Starting proxy...[/bold cyan]")
    console.print(f"  Target: {target}")
    console.print(f"  Listen: http://localhost:{port}")
    console.print(f"\n[dim]Send requests through the proxy to learn user-resource ownership.[/dim]")
    console.print(f"[dim]Example: curl -x http://localhost:{port} -H 'Authorization: token' {target}/api/orders/123[/dim]\n")
    
    # Find mitmdump
    import shutil
    import subprocess
    
    mitmdump_path = shutil.which("mitmdump")
    if not mitmdump_path:
        # Try common locations
        possible_paths = [
            os.path.expanduser("~/.local/bin/mitmdump"),
            "/usr/local/bin/mitmdump",
            os.path.join(os.environ.get("APPDATA", ""), "Python", "Python312", "Scripts", "mitmdump.exe"),
            os.path.join(os.environ.get("APPDATA", ""), "Python", "Python313", "Scripts", "mitmdump.exe"),
        ]
        for path in possible_paths:
            if os.path.exists(path):
                mitmdump_path = path
                break
    
    if not mitmdump_path:
        console.print("[red]Error: mitmdump not found. Install with: pip install mitmproxy[/red]")
        raise typer.Exit(1)
    
    proxy_script = os.path.join(os.path.dirname(os.path.dirname(__file__)), "core", "proxy.py")
    
    cmd = [
        mitmdump_path,
        "-s", proxy_script,
        "--mode", f"reverse:{target}",
        "-p", str(port),
    ]
    
    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        console.print("\n[yellow]Proxy stopped.[/yellow]")


@app.command()
def cve(
    url: str = typer.Option(..., "--url", "-u", help="Target URL to scan for CVEs"),
    tech: Optional[str] = typer.Option(None, "--tech", "-t", help="Technology name to check (e.g., nginx, Django)"),
    version: Optional[str] = typer.Option(None, "--version", "-v", help="Specific version to check"),
):
    """
    🔍 Check for known CVEs in the target's technology stack.
    
    Queries NIST NVD and CISA KEV for vulnerabilities.
    """
    print_banner()
    
    lookup = CVELookup()
    
    if tech:
        # Direct tech/version lookup
        console.print(f"[cyan]Checking CVEs for {tech} {version or ''}...[/cyan]")
        cves = lookup.check_cve(tech, version)
    else:
        # Auto-detect from URL
        console.print(f"[cyan]Scanning {url} for technology fingerprints...[/cyan]")
        tech_detected, cves = lookup.scan_target(url)
        
        if tech_detected:
            table = Table(title="Detected Technologies", show_header=True)
            table.add_column("Technology", style="cyan")
            table.add_column("Version")
            table.add_column("Source")
            
            for t in tech_detected:
                table.add_row(t.name, t.version or "unknown", t.source)
            
            console.print(table)
    
    if not cves:
        console.print("\n[green]✓ No HIGH/CRITICAL CVEs found[/green]")
        return
    
    # Display CVEs
    console.print(f"\n[bold red]⚠ Found {len(cves)} HIGH/CRITICAL CVEs:[/bold red]\n")
    
    for cve_item in cves[:10]:  # Top 10
        severity_color = "red" if cve_item.severity == "CRITICAL" else "yellow"
        exploited = " [bold red]⚡ EXPLOITED IN WILD[/bold red]" if cve_item.exploited_in_wild else ""
        
        console.print(f"[{severity_color}]{cve_item.cve_id}[/{severity_color}] (CVSS: {cve_item.cvss_score}){exploited}")
        console.print(f"  [dim]{cve_item.description[:150]}...[/dim]")
        if cve_item.references:
            console.print(f"  [blue]→ {cve_item.references[0]}[/blue]")
        console.print()


@app.command()
def shadow(
    spec: Optional[str] = typer.Option(None, "--spec", "-s", help="Path to OpenAPI/Swagger spec file"),
):
    """
    👻 Detect shadow (undocumented) API endpoints.
    
    Compares learned traffic against OpenAPI specification.
    """
    print_banner()
    
    detector = ShadowAPIDetector()
    
    # Load OpenAPI spec if provided
    if spec:
        if not detector.load_openapi_spec(spec):
            console.print("[red]Failed to load OpenAPI spec[/red]")
            raise typer.Exit(1)
    else:
        console.print("[yellow]No OpenAPI spec provided. Will flag all observed endpoints.[/yellow]")
    
    # Load observed endpoints from database
    db = JanusDatabase()
    detector.load_from_database(db)
    
    if not detector.observed_endpoints:
        console.print("[yellow]No endpoints observed. Run the proxy first to capture traffic.[/yellow]")
        return
    
    console.print(f"[cyan]Analyzing {len(detector.observed_endpoints)} observed endpoints...[/cyan]\n")
    
    # Detect shadow APIs
    shadow_apis = detector.detect_shadow_apis()
    
    if not shadow_apis:
        console.print("[green]✓ All observed endpoints are documented[/green]")
        return
    
    # Display results
    table = Table(title="🔦 Shadow APIs Detected", show_header=True)
    table.add_column("Risk", justify="center")
    table.add_column("Method", justify="center")
    table.add_column("Endpoint", style="cyan")
    table.add_column("Reason")
    
    for api in shadow_apis:
        risk_color = {"CRITICAL": "red", "HIGH": "yellow", "MEDIUM": "blue", "LOW": "dim"}.get(api.risk_level, "white")
        table.add_row(
            f"[{risk_color}]{api.risk_level}[/{risk_color}]",
            api.method,
            api.endpoint,
            api.reason[:50]
        )
    
    console.print(table)
    console.print(f"\n[bold]Found {len(shadow_apis)} undocumented endpoints[/bold]")


@app.command()
def graphql(
    url: str = typer.Option(..., "--url", "-u", help="GraphQL endpoint URL"),
    token: Optional[str] = typer.Option(None, "--token", "-t", help="Authorization token"),
    full: bool = typer.Option(True, "--full/--quick", help="Full scan or quick introspection only"),
):
    """
    💥 Attack a GraphQL endpoint for vulnerabilities.
    
    Tests: Introspection, Depth Limit DoS, Batching, Field Suggestions.
    """
    print_banner()
    
    console.print(f"[cyan]Attacking GraphQL endpoint: {url}[/cyan]\n")
    
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    
    attacker = GraphQLAttacker()
    results = attacker.scan_graphql(url, headers, full_scan=full)
    
    # Display results
    table = Table(title="GraphQL Attack Results", show_header=True)
    table.add_column("Attack", style="cyan")
    table.add_column("Vulnerable?", justify="center")
    table.add_column("Severity", justify="center")
    table.add_column("Evidence")
    
    for result in results:
        vuln_str = "[red]YES[/red]" if result.vulnerable else "[green]NO[/green]"
        sev_color = {"CRITICAL": "red", "HIGH": "yellow", "MEDIUM": "blue"}.get(result.severity, "dim")
        
        table.add_row(
            result.attack_type,
            vuln_str,
            f"[{sev_color}]{result.severity}[/{sev_color}]",
            result.evidence[:60] + "..." if len(result.evidence) > 60 else result.evidence
        )
    
    console.print(table)
    
    # Recommendations
    vulnerable = [r for r in results if r.vulnerable]
    if vulnerable:
        console.print(f"\n[bold red]⚠ {len(vulnerable)} GraphQL vulnerabilities found![/bold red]")
        for r in vulnerable:
            if r.recommendation:
                console.print(f"  [yellow]→ {r.recommendation}[/yellow]")


@app.command()
def report(
    format: str = typer.Option("html", "--format", "-f", help="Report format (html/json)"),
    input_file: Path = typer.Option("janus_report.json", "--input", "-i", help="Input JSON report"),
    output_file: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file path"),
):
    """
    📊 Generate an HTML report from scan results.
    """
    from janus.core.reporting import HTMLReportGenerator
    
    if not input_file.exists():
        console.print(f"[red]Report file not found: {input_file}[/red]")
        raise typer.Exit(1)
    
    with open(input_file, 'r') as f:
        scan_report = json.load(f)
    
    if format == "html":
        generator = HTMLReportGenerator()
        html = generator.from_scan_report(scan_report)
        
        output = output_file or Path("janus_report.html")
        generator.save_report(html, str(output))
        console.print(f"[green]✓ HTML report saved to {output}[/green]")
    else:
        console.print("[yellow]Format not supported yet[/yellow]")


# =============================================================================
# PROFESSIONAL SECURITY MODULES (Phase 5)
# =============================================================================

@app.command()
def bfla(
    host: str = typer.Option("http://localhost:5000", "--host", "-h", help="Target API URL"),
    low_token: str = typer.Option(..., "--low", "-l", help="Low privilege user token"),
    high_token: str = typer.Option(None, "--high", help="High privilege token (optional)"),
    endpoints: str = typer.Option(None, "--endpoints", "-e", help="Comma-separated endpoints to test"),
):
    """
    🔓 Test for Broken Function Level Authorization (Vertical Escalation).
    """
    print_banner()
    
    scanner = BFLAScanner()
    
    if endpoints:
        endpoint_list = [e.strip() for e in endpoints.split(',')]
    else:
        # Default admin endpoints to test
        endpoint_list = [
            '/api/admin/users',
            '/api/admin/config',
            '/api/admin/export',
            '/api/admin/dashboard',
            '/api/admin/users/1/delete',
            '/api/admin/settings',
            '/api/users/export',
            '/api/config',
        ]
    
    console.print(f"[cyan]Testing {len(endpoint_list)} potential admin endpoints...[/cyan]")
    
    results = scanner.scan_endpoints(
        base_url=host,
        endpoints=endpoint_list,
        low_priv_token=low_token,
        high_priv_token=high_token
    )
    
    # Display results
    vuln_count = sum(1 for r in results if r.vulnerable)
    
    table = Table(title="BFLA Scan Results")
    table.add_column("Endpoint", style="cyan")
    table.add_column("Status", style="bold")
    table.add_column("Severity")
    table.add_column("Evidence")
    
    for r in results:
        status_style = "red" if r.vulnerable else "green"
        table.add_row(
            f"{r.method} {r.endpoint}",
            "VULNERABLE" if r.vulnerable else "SECURE",
            r.severity,
            r.evidence[:60] + "..." if len(r.evidence) > 60 else r.evidence
        )
    
    console.print(table)
    
    if vuln_count > 0:
        console.print(f"\n[bold red]🚨 {vuln_count} BFLA VULNERABILITIES FOUND![/bold red]")
    else:
        console.print(f"\n[green]✓ No BFLA vulnerabilities detected[/green]")


@app.command()
def pii(
    url: str = typer.Option(..., "--url", "-u", help="URL to scan for PII"),
    token: str = typer.Option(None, "--token", "-t", help="Authorization token"),
):
    """
    🔍 Scan API responses for PII and sensitive data leaks.
    """
    print_banner()
    
    import requests
    
    headers = {}
    if token:
        headers['Authorization'] = token
    
    console.print(f"[cyan]Scanning {url} for sensitive data...[/cyan]")
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        body = response.json()
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)
    
    scanner = PIIScanner(strict_mode=True)
    result = scanner.scan_response(body, url)
    
    if result.findings:
        console.print(f"\n[bold red]🚨 Found {len(result.findings)} sensitive data exposures![/bold red]")
        
        table = Table(title="PII/Secrets Detected")
        table.add_column("Field", style="cyan")
        table.add_column("Type", style="yellow")
        table.add_column("Severity", style="bold")
        table.add_column("Compliance")
        
        for f in result.findings:
            sev_style = "red" if f.severity == "CRITICAL" else "yellow" if f.severity == "HIGH" else "white"
            table.add_row(
                f.field_path,
                f.data_type,
                f"[{sev_style}]{f.severity}[/{sev_style}]",
                ", ".join(f.compliance_impact)
            )
        
        console.print(table)
        console.print(f"\n[yellow]Compliance Violations: {', '.join(result.compliance_violations)}[/yellow]")
        console.print(f"[yellow]Risk Score: {result.risk_score}/10[/yellow]")
    else:
        console.print(f"\n[green]✓ No sensitive data detected[/green]")


@app.command()
def race(
    url: str = typer.Option(..., "--url", "-u", help="Endpoint URL to test"),
    token: str = typer.Option(..., "--token", "-t", help="Authorization token"),
    method: str = typer.Option("POST", "--method", "-m", help="HTTP method"),
    body: str = typer.Option("{}", "--body", "-b", help="JSON body"),
    threads: int = typer.Option(10, "--threads", "-n", help="Number of simultaneous requests"),
):
    """
    ⚡ Test for Race Condition vulnerabilities.
    """
    print_banner()
    
    console.print(f"[cyan]Testing race condition with {threads} simultaneous requests...[/cyan]")
    
    try:
        body_dict = json.loads(body)
    except:
        body_dict = {}
    
    tester = RaceConditionTester()
    result = tester.test_race_condition(
        endpoint=url,
        method=method,
        body=body_dict,
        token=token,
        threads=threads
    )
    
    if result.vulnerable:
        console.print(f"\n[bold red]🚨 RACE CONDITION VULNERABLE![/bold red]")
        console.print(f"[red]Severity: {result.severity}[/red]")
    else:
        console.print(f"\n[green]✓ No race condition detected[/green]")
    
    console.print(f"\n[dim]Timing spread: {result.timing_spread_ms}ms[/dim]")
    console.print(f"[dim]Successful requests: {result.successful_requests}/{result.requests_sent}[/dim]")
    console.print(f"\n[yellow]Evidence: {result.evidence}[/yellow]")
    
    if result.recommendation:
        console.print(f"\n[cyan]Recommendation:[/cyan]\n{result.recommendation}")


# =============================================================================
# PHASE 6: STEALTH & CI/CD MODULES
# =============================================================================

@app.command()
def sarif(
    input_file: Path = typer.Option("janus_report.json", "--input", "-i", help="Input JSON report"),
    output_file: Path = typer.Option("janus_sarif.json", "--output", "-o", help="Output SARIF file"),
    fail_on: str = typer.Option("error", "--fail-on", "-f", help="Exit 1 on: error, warning, note"),
):
    """
    📊 Export scan results to SARIF format for GitHub Security tab.
    
    Use in CI/CD pipelines. Returns exit code 1 if vulnerabilities found.
    """
    print_banner()
    
    from janus.reporting.sarif import SARIFReporter, get_exit_code
    
    if not input_file.exists():
        console.print(f"[red]Report file not found: {input_file}[/red]")
        raise typer.Exit(1)
    
    with open(input_file, 'r') as f:
        scan_report = json.load(f)
    
    reporter = SARIFReporter()
    reporter.from_scan_report(scan_report)
    reporter.save(str(output_file))
    
    sarif_report = reporter.generate()
    
    # Count findings
    finding_count = len(reporter.results)
    
    console.print(f"[green]✓ SARIF report saved to {output_file}[/green]")
    console.print(f"[dim]Findings: {finding_count}[/dim]")
    
    # Determine exit code for CI/CD
    exit_code = get_exit_code(sarif_report, fail_on)
    
    if exit_code != 0:
        console.print(f"[red]❌ CI/CD: Failing build due to security findings[/red]")
        raise typer.Exit(exit_code)
    else:
        console.print(f"[green]✓ CI/CD: No blocking vulnerabilities found[/green]")


@app.command()
def stealth_test():
    """
    👻 Test stealth mode configuration (WAF evasion).
    """
    print_banner()
    
    from janus.core.stealth import GhostWalker, StealthConfig
    
    console.print("[cyan]Testing Ghost-Walker WAF Evasion Module...[/cyan]\n")
    
    config = StealthConfig(enabled=True, min_delay=0.5, max_delay=2.0)
    ghost = GhostWalker(config)
    
    # Show sample headers
    headers = ghost.get_stealth_headers("https://example.com")
    
    table = Table(title="Stealth Headers Sample")
    table.add_column("Header", style="cyan")
    table.add_column("Value", style="dim")
    
    for key, value in headers.items():
        table.add_row(key, value[:60] + "..." if len(value) > 60 else value)
    
    console.print(table)
    
    # Test Tor if available
    console.print("\n[cyan]Checking Tor availability...[/cyan]")
    if ghost.check_tor():
        console.print("[green]✓ Tor is available and working![/green]")
    else:
        console.print("[yellow]⚠ Tor not available. Install Tor or start the service.[/yellow]")
    
    console.print(f"\n[dim]Jitter range: {config.min_delay}s - {config.max_delay}s[/dim]")
    console.print("[green]✓ Stealth mode configured and ready[/green]")


@app.command()
def team(
    action: str = typer.Argument("status", help="Action: status, findings, loot"),
    redis_url: str = typer.Option("redis://localhost:6379", "--redis", "-r", help="Redis URL"),
    team_id: str = typer.Option("default", "--team", "-t", help="Team ID"),
):
    """
    🐝 Hive-Mind team collaboration.
    
    Actions: status, findings, loot
    """
    print_banner()
    
    from janus.core.hivemind import HiveMind
    
    hive = HiveMind(redis_url=redis_url, team_id=team_id)
    connected = hive.connect()
    
    if action == "status":
        stats = hive.get_team_stats()
        
        console.print(f"\n[cyan]Team Status: {team_id}[/cyan]")
        console.print(f"  Connected: {'✓ Yes' if stats['connected'] else '✗ Local mode'}")
        console.print(f"  Your ID: {stats['user']}")
        console.print(f"  Active Users: {stats['active_users']}")
        console.print(f"  Total Findings: {stats['total_findings']}")
        console.print(f"  Loot Items: {stats['total_loot']}")
        
    elif action == "findings":
        findings = hive.get_findings(limit=20)
        
        if findings:
            table = Table(title="Recent Team Findings")
            table.add_column("User", style="cyan")
            table.add_column("Type", style="yellow")
            table.add_column("Endpoint", style="dim")
            table.add_column("Severity")
            
            for f in findings:
                table.add_row(f.user, f.finding_type, f.endpoint[:40], f.severity)
            
            console.print(table)
        else:
            console.print("[dim]No findings yet[/dim]")
            
    elif action == "loot":
        loot = hive.get_loot()
        
        if loot:
            table = Table(title="Shared Loot Box")
            table.add_column("Found By", style="cyan")
            table.add_column("Type", style="yellow")
            table.add_column("Value (Redacted)", style="red")
            table.add_column("Source", style="dim")
            
            for l in loot:
                redacted = l.redacted_dict()
                table.add_row(l.found_by, l.loot_type, redacted['value'], l.source_endpoint[:30])
            
            console.print(table)
        else:
            console.print("[dim]No loot collected yet[/dim]")
    
    hive.disconnect()


@app.command()
def ci_scan(
    victim_token: str = typer.Option(..., "--victim", "-v", help="Victim token"),
    attacker_token: str = typer.Option(..., "--attacker", "-a", help="Attacker token"),
    host: str = typer.Option(..., "--host", "-h", help="Target API URL"),
    sarif_output: Path = typer.Option("results.sarif", "--sarif", "-s", help="SARIF output file"),
    fail_on: str = typer.Option("error", "--fail-on", "-f", help="Fail on: error, warning"),
):
    """
    🔧 CI/CD Pipeline scan - Returns exit code 1 on vulnerabilities.
    
    Use in GitHub Actions or Jenkins for automated security testing.
    """
    from janus.reporting.sarif import SARIFReporter, get_exit_code
    
    # Run the scan silently
    engine = JanusEngine()
    report = engine.launch_attack(victim_token, attacker_token, host)
    
    # Convert to SARIF
    reporter = SARIFReporter()
    reporter.from_scan_report(report.to_dict())
    reporter.save(str(sarif_output))
    
    sarif_report = reporter.generate()
    
    # Count issues
    vuln_count = report.vulnerabilities_found
    
    if vuln_count > 0:
        print(f"JANUS: Found {vuln_count} vulnerabilities")
        print(f"SARIF report saved to: {sarif_output}")
        exit_code = get_exit_code(sarif_report, fail_on)
        raise typer.Exit(exit_code)
    else:
        print("JANUS: No vulnerabilities found")
        raise typer.Exit(0)


def main():
    app()


if __name__ == "__main__":
    main()

