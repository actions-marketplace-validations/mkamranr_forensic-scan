"""The human-readable forensic report.

Written for someone deciding whether to merge a pull request in the next two
minutes. That shapes every choice here: the verdict comes first, findings are
ordered worst-first, and each one answers "what is it, where, and what do I do"
before it shows any evidence.

Taint traces are numbered because the numbered form is what makes an obfuscated
payload legible -- "literal, then decode, then execute" is an argument, while
three separate line references are a puzzle.
"""

from __future__ import annotations

from ..models import Finding, Severity
from ..scanner import ScanResult
from .common import relative

_SEVERITY_ICON = {
    Severity.CRITICAL: "🚨",
    Severity.HIGH: "⚠️",
    Severity.MEDIUM: "◆",
    Severity.LOW: "·",
    Severity.INFO: "·",
}

_LANGUAGE_BY_SUFFIX = {
    ".py": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "tsx",
    ".jsx": "javascript",
    ".c": "c",
    ".h": "c",
    ".json": "json",
    ".yml": "yaml",
    ".yaml": "yaml",
}


def render_markdown(result: ScanResult) -> str:
    lines: list[str] = ["# 🔍 Forensic AST & Obfuscation Report", ""]

    if result.unavailable_languages:
        # First thing on the page. A reader who skims must not take an
        # incomplete scan for a clean one.
        detail = ", ".join(
            f"`{lang}` ({reason})" for lang, reason in sorted(result.unavailable_languages.items())
        )
        lines.extend(
            [
                "> ## ⛔ This scan is incomplete",
                ">",
                f"> {result.files_unanalyzed} source file(s) were **not analysed**: the "
                f"tree-sitter grammar could not be loaded for {detail}.",
                ">",
                "> Grammars are downloaded on first use. Run `forensic-scan prefetch` "
                "while online, or use the container image, which ships them. "
                "**Treat the findings below as partial.**",
                "",
            ]
        )

    lines.extend(_summary(result))

    if result.errors:
        lines.extend(["", "## Scan errors", ""])
        lines.extend(f"- `{error}`" for error in result.errors)

    if not result.findings:
        lines.extend(
            [
                "",
                "## Result",
                "",
                "**No anomalies flagged.** Nothing in the analysed files matched a "
                "forensic rule at or above the reporting threshold.",
                "",
                _limitations(),
            ]
        )
        return "\n".join(lines) + "\n"

    for severity in sorted(Severity, reverse=True):
        group = [f for f in result.findings if f.severity is severity]
        if not group:
            continue
        icon = _SEVERITY_ICON[severity]
        lines.extend(["", f"## {icon} {severity.name} findings ({len(group)})", ""])
        for finding in group:
            lines.extend(_finding_block(finding, result))

    lines.extend(["", _limitations()])
    return "\n".join(lines) + "\n"


def _summary(result: ScanResult) -> list[str]:
    counts = result.score.counts
    parts = [
        f"**Files analysed:** {result.files_analyzed}",
        f"**Anomalies flagged:** {len(result.findings)}",
        f"**Forensic risk score:** {result.score}",
    ]
    lines = [" | ".join(parts), ""]

    if result.diff_ref:
        lines.append(f"Scoped to files changed against `{result.diff_ref}`.")
    if counts:
        breakdown = ", ".join(
            f"{count} {severity.name.lower()}"
            for severity, count in sorted(counts.items(), key=lambda kv: -kv[0].value)
        )
        lines.append(f"Breakdown: {breakdown}.")
    notes = []
    if result.suppressed:
        notes.append(
            f"{len(result.suppressed)} finding(s) suppressed in generated, minified "
            "or vendored files"
        )
    if result.baselined:
        notes.append(f"{len(result.baselined)} finding(s) accepted by the baseline")
    if notes:
        lines.append(f"_{'; '.join(notes)}._")
    if result.duration_seconds:
        lines.append(f"_Completed in {result.duration_seconds:.2f}s._")
    return lines


def _finding_block(finding: Finding, result: ScanResult) -> list[str]:
    location = relative(finding.location.path, result.root)
    if finding.location.line:
        location = f"{location}:{finding.location.line}"

    lines = [
        f"### {finding.rule_id}: {finding.name}",
        "",
        f"- **Severity:** {finding.severity.name}",
        f"- **Location:** `{location}`",
        f"- **What was found:** {finding.detail}",
    ]
    if finding.remediation:
        lines.append(f"- **What to do:** {finding.remediation}")

    if finding.trace:
        lines.extend(["", "**Trace:**", ""])
        for index, step in enumerate(finding.trace, start=1):
            where = relative(step.location.path, result.root)
            if step.location.line:
                where = f"{where}:{step.location.line}"
            lines.append(f"{index}. `{where}` — {step.description}")
            if step.snippet:
                lines.append(f"   ```\n   {step.snippet}\n   ```")

    snippet = finding.location.snippet
    if snippet and not finding.trace:
        language = _LANGUAGE_BY_SUFFIX.get(finding.location.path.suffix.lower(), "")
        lines.extend(["", f"```{language}", snippet, "```"])

    lines.extend(["", "---", ""])
    return lines


def _limitations() -> str:
    return (
        "> **Reading this report.** Every finding is an *anomaly*, not a verdict. "
        "This scanner measures concealment, so a true positive can still be "
        "legitimate code that happens to look concealed. Data flow analysis is "
        "intra-procedural and single-file, and C macros are not expanded — "
        "absence of findings is not evidence of absence."
    )
