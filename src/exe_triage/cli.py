import sys
import click
from pathlib import Path

from exe_triage.analyzers.file_validator import ValidationError
from exe_triage.analyzers.pe_analyzer import PEAnalysisError
from exe_triage import analyzer
from exe_triage.reporting import terminal_reporter, json_reporter


@click.group()
def cli() -> None:
    """exe-triage — Local static triage tool for Windows PE executables."""
    pass


@cli.command()
@click.argument("file", type=click.Path(exists=False))
@click.option("--json", "output_json", is_flag=True, help="Export result as JSON")
@click.option("--output", "-o", type=click.Path(), default=None, help="Save output to file")
@click.option("--verbose", "-v", is_flag=True, help="Show additional details")
def analyze(file: str, output_json: bool, output: str | None, verbose: bool) -> None:
    """Analyze a PE executable file for risk indicators."""
    try:
        result = analyzer.analyze(file)
    except ValidationError as e:
        click.echo(f"[ERROR] {e}", err=True)
        sys.exit(1)
    except PEAnalysisError as e:
        click.echo(f"[ERROR] Failed to parse PE: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"[ERROR] Unexpected error: {e}", err=True)
        sys.exit(1)

    if output_json:
        json_output = json_reporter.render(result)
        if output:
            Path(output).write_text(json_output, encoding="utf-8")
            click.echo(f"Report saved to: {output}")
        else:
            click.echo(json_output)
    else:
        terminal_reporter.render(result)
        if output:
            # Also save JSON when --output is specified without --json
            import json as json_mod
            from exe_triage.reporting import json_reporter as jr
            json_output = jr.render(result)
            Path(output).write_text(json_output, encoding="utf-8")
            click.echo(f"\nJSON report saved to: {output}")
