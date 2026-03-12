from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

from exe_triage.models import AnalysisResult

console = Console()

LEVEL_COLORS = {
    "low": "green",
    "medium": "yellow",
    "high": "red",
    "critical": "bold red",
}


def render(result: AnalysisResult) -> None:
    """Render analysis result to terminal using rich."""
    level_color = LEVEL_COLORS.get(result.risk_score.level, "white")

    # Header panel
    header_text = Text()
    header_text.append("exe-triage v1.0", style="bold cyan")
    header_text.append("  |  ", style="dim")
    header_text.append(result.file_name, style="bold white")
    console.print(Panel(header_text, box=box.ROUNDED))

    # File info table
    info_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    info_table.add_column("Key", style="dim", width=14)
    info_table.add_column("Value", style="white")

    file_size_mb = result.file_size / (1024 * 1024)
    info_table.add_row("SHA-256", result.sha256[:16] + "..." + result.sha256[-8:] if len(result.sha256) > 24 else result.sha256)
    info_table.add_row("Size", f"{file_size_mb:.2f} MB" if file_size_mb >= 0.01 else f"{result.file_size} bytes")
    info_table.add_row("Type", f"{result.file_type} / {result.architecture}")
    if result.compile_timestamp:
        info_table.add_row("Compiled", result.compile_timestamp)
    info_table.add_row("Technology", f"{result.technology.detected} ({result.technology.confidence})")
    sig_status = "PRESENT" if result.signature.signed else "ABSENT"
    sig_style = "green" if result.signature.signed else "yellow"
    sig_text = Text(sig_status, style=sig_style)
    if result.signature.publisher:
        sig_text.append(f" — {result.signature.publisher}", style="dim")
    info_table.add_row("Signature", sig_text)

    console.print(info_table)

    # Risk score panel
    risk_text = Text()
    risk_text.append("RISK: ", style="bold")
    risk_text.append(result.risk_score.level.upper(), style=level_color)
    risk_text.append(f"  |  Score: {result.risk_score.total}", style="bold white")
    console.print(Panel(risk_text, box=box.ROUNDED))

    # Findings table
    if result.findings:
        findings_table = Table(title="Findings", box=box.SIMPLE, show_header=True)
        findings_table.add_column("Weight", style="bold", width=8, justify="right")
        findings_table.add_column("Category", style="cyan", width=22)
        findings_table.add_column("Description", style="white")
        findings_table.add_column("Evidence", style="dim")

        for finding in sorted(result.findings, key=lambda f: f.weight, reverse=True):
            cat_color = "red" if finding.category in ("process_injection", "obfuscation", "remote_download") else "yellow"
            findings_table.add_row(
                f"[{finding.weight}]",
                Text(finding.category, style=cat_color),
                finding.description,
                finding.evidence[:60] + "..." if len(finding.evidence) > 60 else finding.evidence,
            )
        console.print(findings_table)

    # IOCs summary
    ioc_parts = []
    if result.iocs.urls:
        ioc_parts.append(f"{len(result.iocs.urls)} URL(s)")
    if result.iocs.ips:
        ioc_parts.append(f"{len(result.iocs.ips)} IP(s)")
    if result.iocs.domains:
        ioc_parts.append(f"{len(result.iocs.domains)} domain(s)")
    if result.iocs.file_paths:
        ioc_parts.append(f"{len(result.iocs.file_paths)} path(s)")
    if result.iocs.registry_keys:
        ioc_parts.append(f"{len(result.iocs.registry_keys)} registry key(s)")
    if result.iocs.process_names:
        ioc_parts.append(f"{len(result.iocs.process_names)} process(es)")

    if ioc_parts:
        console.print(f"\n[bold]IOCs:[/bold] {', '.join(ioc_parts)}")

    # Recommendations
    if result.recommendations:
        console.print("\n[bold]Recommendations:[/bold]")
        for rec in result.recommendations:
            bullet_style = "bold red" if "Do not execute" in rec or "isolated" in rec.lower() else "yellow"
            console.print(f"  [dim]•[/dim] [{bullet_style}]{rec}[/{bullet_style}]")

    # Errors
    if result.errors:
        console.print(f"\n[dim]Analysis warnings ({len(result.errors)}):[/dim]")
        for err in result.errors:
            console.print(f"  [dim]! {err}[/dim]")
