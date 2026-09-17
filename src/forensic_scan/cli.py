"""The command line.

Two invocations matter, and the defaults are tuned for them:

``forensic-scan --diff origin/main``
    Pull-request review. Only changed files, exit non-zero on anything at HIGH
    or above. This is the mode that has to be quiet enough to leave switched on.

``forensic-scan ./``
    Auditing an unfamiliar dependency. Everything, ranked, nothing hidden.
"""

from __future__ import annotations

import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.markdown import Markdown
from rich.table import Table

from . import __version__
from .config import build_ruleset, find_baseline
from .models import Severity
from .report import RENDERERS
from .rules.schema import load_builtin_rules
from .scanner import ScanConfig, Scanner, ScanResult
from .scoring.baseline import DEFAULT_BASELINE_NAME, Baseline
from .scoring.score import exit_code_for

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

app = typer.Typer(
    name="forensic-scan",
    help="Forensic scanner for hidden logic, obfuscation and smuggled payloads.",
    add_completion=False,
    no_args_is_help=True,
)
console = Console(stderr=True)
SUBCOMMANDS = {"scan", "baseline", "rules", "version", "prefetch"}


def _parse_fail_on(value: str) -> Severity | None:
    if value.lower() in {"none", "never", "off"}:
        return None
    try:
        return Severity.parse(value)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc


@app.command()
def scan(
    path: Path = typer.Argument(Path("."), help="Directory or file to scan."),
    diff: str | None = typer.Option(
        None,
        "--diff",
        "-d",
        help="Scan only files changed against this git ref (e.g. origin/main).",
    ),
    output_format: str = typer.Option(
        "markdown", "--format", "-f", help="markdown, json or sarif."
    ),
    output: Path | None = typer.Option(
        None, "--output", "-o", help="Write the report here instead of stdout."
    ),
    fail_on: str = typer.Option(
        "HIGH",
        "--fail-on",
        help="Exit non-zero at this severity or above. Use 'none' to never fail.",
    ),
    rules: Path | None = typer.Option(
        None, "--rules", "-r", help="Additional rule file, merged over the built-ins."
    ),
    baseline: Path | None = typer.Option(
        None, "--baseline", "-b", help=f"Baseline file (default: {DEFAULT_BASELINE_NAME})."
    ),
    no_baseline: bool = typer.Option(
        False, "--no-baseline", help="Report findings even if the baseline accepts them."
    ),
    exclude: list[str] = typer.Option([], "--exclude", "-e", help="Glob to skip. Repeatable."),
    include_vendored: bool = typer.Option(
        False,
        "--include-vendored",
        help="Scan node_modules, vendor and friends. Use when auditing a dependency.",
    ),
    no_gitignore: bool = typer.Option(
        False, "--no-gitignore", help="Scan files that .gitignore excludes."
    ),
    no_suppress: bool = typer.Option(
        False, "--no-suppress", help="Do not hold back findings in generated or minified files."
    ),
    jobs: int | None = typer.Option(
        None,
        "--jobs",
        "-j",
        help="Worker processes. Defaults to the core count (max 8); 1 forces sequential.",
    ),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress progress output."),
) -> None:
    """Scan a repository for concealment, obfuscation and smuggled payloads."""
    if output_format not in RENDERERS:
        raise typer.BadParameter(
            f"unknown format {output_format!r}; expected one of: {', '.join(sorted(RENDERERS))}"
        )
    if not path.exists():
        console.print(f"[red]error:[/red] no such path: {path}")
        raise typer.Exit(EXIT_ERROR)

    root = path.resolve() if path.is_dir() else path.resolve().parent
    threshold = _parse_fail_on(fail_on)

    try:
        ruleset = build_ruleset(root, extra=rules)
    except ValueError as exc:
        console.print(f"[red]rule error:[/red] {exc}")
        raise typer.Exit(EXIT_ERROR) from exc

    baseline_path = None if no_baseline else (baseline or find_baseline(root))

    config = ScanConfig(
        root=path.resolve(),
        diff_ref=diff,
        excludes=list(exclude),
        include_vendored=include_vendored,
        respect_gitignore=not no_gitignore,
        ruleset=ruleset,
        baseline_path=baseline_path,
        suppress=not no_suppress,
        fail_on=threshold,
        jobs=jobs,
    )

    try:
        result = Scanner().scan(config)
    except RuntimeError as exc:  # git failures in diff mode
        console.print(f"[red]error:[/red] {exc}")
        raise typer.Exit(EXIT_ERROR) from exc

    result.root = root
    rendered = RENDERERS[output_format](result)

    if output is not None:
        output.write_text(rendered, encoding="utf-8")
        if not quiet:
            console.print(f"Report written to [bold]{output}[/bold]")
    elif output_format == "markdown" and sys.stdout.isatty():
        Console().print(Markdown(rendered))
    else:
        sys.stdout.write(rendered)

    if not quiet:
        _print_summary(result)

    if result.unavailable_languages:
        # An incomplete scan must never be mistaken for a clean one. Exit 2 is
        # "could not do the job", which is a different answer from "found
        # nothing" and has to look different to a CI pipeline.
        console.print(
            f"[red]error:[/red] scan incomplete -- {result.files_unanalyzed} source "
            f"file(s) were not analysed because a grammar could not be loaded "
            f"({', '.join(sorted(result.unavailable_languages))}). "
            "Run 'forensic-scan prefetch' while online."
        )
        raise typer.Exit(EXIT_ERROR)

    raise typer.Exit(exit_code_for(result.findings, threshold))


baseline_app = typer.Typer(help="Manage the accepted-findings baseline.")
app.add_typer(baseline_app, name="baseline")


@baseline_app.command("write")
def baseline_write(
    path: Path = typer.Argument(Path("."), help="Directory to scan."),
    output: Path | None = typer.Option(
        None, "--output", "-o", help=f"Where to write (default: {DEFAULT_BASELINE_NAME})."
    ),
) -> None:
    """Accept every current finding, so that only new ones are reported."""
    root = path.resolve()
    destination = output or root / DEFAULT_BASELINE_NAME
    result = Scanner().scan(ScanConfig(root=root, ruleset=build_ruleset(root), baseline_path=None))
    Baseline.from_findings(result.findings).save(destination, root=root)
    console.print(
        f"Accepted [bold]{len(result.findings)}[/bold] finding(s) into {destination}.\n"
        "Only findings absent from this file will be reported from now on."
    )


rules_app = typer.Typer(help="Inspect the rules the scanner will apply.")
app.add_typer(rules_app, name="rules")


@rules_app.command("list")
def rules_list(
    path: Path = typer.Argument(Path("."), help="Repository, for project rule overrides."),
) -> None:
    """List every rule that would be applied, including project overrides."""
    ruleset = build_ruleset(path.resolve())
    table = Table(title=f"{len(ruleset.enabled_rules)} active rules")
    table.add_column("ID", style="bold")
    table.add_column("Severity")
    table.add_column("Name")
    table.add_column("Signals", overflow="fold")
    for rule in sorted(ruleset.rules, key=lambda r: r.id):
        if not rule.enabled:
            continue
        table.add_row(
            rule.id,
            rule.severity.name,
            rule.name,
            ", ".join(kind.value for kind in rule.match.signal),
        )
    Console().print(table)
    Console().print(
        "\n[dim]FOR-010 (build-time payload extraction chain) is emitted in code: "
        "it correlates signals across files, which the rule schema does not express.[/dim]"
    )


@rules_app.command("validate")
def rules_validate(
    path: Path = typer.Argument(..., help="Rule file to validate."),
) -> None:
    """Check a rule file for errors without running a scan."""
    from .rules.schema import load_ruleset

    try:
        ruleset = load_ruleset(path)
    except ValueError as exc:
        console.print(f"[red]invalid:[/red] {exc}")
        raise typer.Exit(EXIT_ERROR) from exc
    console.print(f"[green]valid:[/green] {len(ruleset.rules)} rule(s) in {path}")


@app.command()
def prefetch(
    languages: list[str] = typer.Argument(
        None, help="Languages to fetch. Defaults to every language the scanner supports."
    ),
) -> None:
    """Download and cache the tree-sitter grammars for offline use.

    Grammars are fetched on first use, so an air-gapped runner or a blocked
    proxy would otherwise leave the scanner unable to parse anything. Run this
    once while online; the container image has it baked in already.
    """
    from tree_sitter_language_pack import cache_dir

    from .parser.registry import SUPPORTED_LANGUAGES, ParserRegistry

    wanted = sorted(languages) if languages else sorted(SUPPORTED_LANGUAGES)
    registry = ParserRegistry()
    out = Console()

    failed: list[str] = []
    for language in wanted:
        if registry.ensure(language):
            out.print(f"[green]ok[/green]      {language}")
        else:
            failed.append(language)
            out.print(
                f"[red]failed[/red]  {language}: "
                f"{registry.grammar_errors.get(language, 'unknown error')}"
            )

    out.print(f"\nCache: {cache_dir()}")
    if failed:
        raise typer.Exit(EXIT_ERROR)


@app.command()
def version() -> None:
    """Print the version."""
    builtin = load_builtin_rules()
    Console().print(f"forensic-scan {__version__} ({len(builtin.rules)} built-in rules)")


def _print_summary(result: ScanResult) -> None:
    style = {
        "CLEAN": "green",
        "INFO": "dim",
        "LOW": "cyan",
        "MEDIUM": "yellow",
        "HIGH": "red",
        "CRITICAL": "bold red",
    }.get(result.score.band, "white")
    console.print(
        f"\n[{style}]{result.score}[/{style}]  "
        f"{len(result.findings)} finding(s) across {result.files_analyzed} file(s) "
        f"in {result.duration_seconds:.2f}s"
    )
    if result.suppressed:
        console.print(
            f"[dim]{len(result.suppressed)} suppressed (generated/vendored/minified)[/dim]"
        )
    if result.baselined:
        console.print(f"[dim]{len(result.baselined)} accepted by baseline[/dim]")
    for error in result.errors[:5]:
        console.print(f"[yellow]warning:[/yellow] {error}")


def main() -> None:
    """Entry point.

    ``forensic-scan ./`` is the invocation the documentation promises, so a bare
    path is treated as an implicit ``scan``.
    """
    argv = sys.argv[1:]
    first = next((a for a in argv if not a.startswith("-")), None)
    if argv and first is not None and first not in SUBCOMMANDS:
        sys.argv.insert(1, "scan")
    elif argv and first is None and any(a in {"--version", "-V"} for a in argv):
        sys.argv = [sys.argv[0], "version"]
    app()


if __name__ == "__main__":  # pragma: no cover
    main()
