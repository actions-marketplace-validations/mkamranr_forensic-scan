"""SARIF 2.1.0 -- how findings reach the GitHub Security tab.

SARIF is what makes the scanner usable rather than merely available: uploaded
from a workflow, findings become inline pull-request annotations on the exact
lines involved, and GitHub tracks them across commits by fingerprint.

Two details carry real weight:

``partialFingerprints`` lets GitHub recognise a finding as the same one across
commits, so a reviewer is not re-notified about something already triaged. Ours
is line-independent for the same reason the baseline's is.

``codeFlows`` renders a taint trace as a navigable sequence in the UI. A payload
that is decoded on one line and executed on another is far more convincing when
the reader can step through it.
"""

from __future__ import annotations

import json

from .. import __version__
from ..models import Finding, Location, Severity
from ..scanner import ScanResult
from .common import relative

SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)
INFORMATION_URI = "https://github.com/mkamranr/forensic-scan"

_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "7.5",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "3.0",
    Severity.INFO: "1.0",
}


def render_sarif(result: ScanResult) -> str:
    rules, rule_index = _rule_declarations(result)
    document = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "forensic-scan",
                        "version": __version__,
                        "semanticVersion": __version__,
                        "informationUri": INFORMATION_URI,
                        "rules": rules,
                    }
                },
                "results": [_result_entry(f, result, rule_index) for f in result.findings],
                "columnKind": "utf16CodeUnits",
            }
        ],
    }
    return json.dumps(document, indent=2)


def _rule_declarations(result: ScanResult) -> tuple[list[dict[str, object]], dict[str, int]]:
    """One declaration per rule that actually fired, in first-seen order."""
    declarations: list[dict[str, object]] = []
    index: dict[str, int] = {}
    for finding in result.findings:
        if finding.rule_id in index:
            continue
        index[finding.rule_id] = len(declarations)
        declarations.append(
            {
                "id": finding.rule_id,
                "name": _camel(finding.name),
                "shortDescription": {"text": finding.name},
                "fullDescription": {"text": finding.detail},
                "help": {
                    "text": finding.remediation or finding.detail,
                    "markdown": f"**{finding.name}**\n\n{finding.remediation or finding.detail}",
                },
                "defaultConfiguration": {"level": _LEVEL[finding.severity]},
                "properties": {
                    "tags": ["security", "obfuscation", "supply-chain"],
                    "problem.severity": _LEVEL[finding.severity],
                    "security-severity": _SECURITY_SEVERITY[finding.severity],
                },
            }
        )
    return declarations, index


def _result_entry(
    finding: Finding, result: ScanResult, rule_index: dict[str, int]
) -> dict[str, object]:
    entry: dict[str, object] = {
        "ruleId": finding.rule_id,
        "ruleIndex": rule_index[finding.rule_id],
        "level": _LEVEL[finding.severity],
        "message": {"text": f"{finding.name}: {finding.detail}"},
        "locations": [_location(finding.location, result)],
        "partialFingerprints": {"forensicScan/v1": finding.fingerprint},
    }
    if finding.trace:
        entry["codeFlows"] = [
            {
                "threadFlows": [
                    {
                        "locations": [
                            {
                                "location": {
                                    **_location(step.location, result),
                                    "message": {"text": step.description},
                                }
                            }
                            for step in finding.trace
                        ]
                    }
                ]
            }
        ]
    return entry


def _location(location: Location, result: ScanResult) -> dict[str, object]:
    physical: dict[str, object] = {
        "artifactLocation": {
            "uri": relative(location.path, result.root),
            "uriBaseId": "%SRCROOT%",
        }
    }
    if location.line:
        region: dict[str, object] = {"startLine": location.line}
        if location.end_line and location.end_line >= location.line:
            region["endLine"] = location.end_line
        if location.column:
            region["startColumn"] = location.column
        if location.snippet:
            region["snippet"] = {"text": location.snippet}
        physical["region"] = region
    return {"physicalLocation": physical}


def _camel(name: str) -> str:
    return "".join(part.capitalize() for part in name.replace("-", " ").split() if part)
