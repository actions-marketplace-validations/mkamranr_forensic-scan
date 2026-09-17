"""Machine-readable output, for pipelines that do their own triage."""

from __future__ import annotations

import json

from ..models import Finding
from ..scanner import ScanResult
from .common import relative

JSON_SCHEMA_VERSION = 1


def render_json(result: ScanResult) -> str:
    document = {
        "version": JSON_SCHEMA_VERSION,
        "tool": "forensic-scan",
        "summary": {
            "files_analyzed": result.files_analyzed,
            "files_parsed": result.files_parsed,
            "findings": len(result.findings),
            "suppressed": len(result.suppressed),
            "baselined": len(result.baselined),
            "risk_score": result.score.value,
            "risk_band": result.score.band,
            "counts": {s.name: c for s, c in result.score.counts.items()},
            "duration_seconds": round(result.duration_seconds, 3),
            "diff_ref": result.diff_ref,
            "complete": not result.unavailable_languages,
            "files_unanalyzed": result.files_unanalyzed,
            "unavailable_languages": result.unavailable_languages,
        },
        "findings": [_finding(f, result) for f in result.findings],
        "errors": result.errors,
        "skipped": [
            {"path": relative(s.path, result.root), "reason": s.reason.value, "detail": s.detail}
            for s in result.skipped
        ],
    }
    return json.dumps(document, indent=2, sort_keys=False)


def _finding(finding: Finding, result: ScanResult) -> dict[str, object]:
    return {
        "rule": finding.rule_id,
        "name": finding.name,
        "severity": finding.severity.name,
        "path": relative(finding.location.path, result.root),
        "line": finding.location.line,
        "end_line": finding.location.end_line,
        "column": finding.location.column,
        "snippet": finding.location.snippet,
        "detail": finding.detail,
        "remediation": finding.remediation,
        "fingerprint": finding.fingerprint,
        "metadata": dict(finding.metadata),
        "trace": [
            {
                "path": relative(step.location.path, result.root),
                "line": step.location.line,
                "description": step.description,
                "snippet": step.snippet,
            }
            for step in finding.trace
        ],
        "signals": [
            {
                "kind": signal.kind.value,
                "path": relative(signal.location.path, result.root),
                "line": signal.location.line,
                "features": signal.features,
                "metadata": signal.metadata,
                "confidence": signal.confidence,
            }
            for signal in finding.signals
        ],
    }
