"""Accepting a repository's existing state.

Nobody adopts a scanner that opens with four hundred findings about code they
did not write and cannot change today. A baseline records what is already there
so that only *new* anomalies fire -- which is also the honest framing, since the
question a maintainer actually has is "did this pull request introduce
something", not "is this codebase perfect".

Fingerprints deliberately exclude line numbers. Adding an import at the top of a
file must not silently un-accept every finding below it. Changing the flagged
code itself must.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..models import Finding

BASELINE_VERSION = 1
DEFAULT_BASELINE_NAME = ".forensic-baseline.json"

_NOTE = (
    "Findings accepted for this repository. forensic-scan reports only findings "
    "absent from this file. Delete an entry to have it reported again; "
    "regenerate with 'forensic-scan baseline write'."
)


@dataclass(frozen=True)
class BaselineEntry:
    """One accepted finding, recorded legibly enough to review in a diff."""

    rule: str
    path: Path
    severity: str
    summary: str

    @classmethod
    def from_finding(cls, finding: Finding) -> BaselineEntry:
        return cls(
            rule=finding.rule_id,
            path=finding.location.path,
            severity=finding.severity.name,
            summary=finding.name,
        )

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> BaselineEntry:
        return cls(
            rule=str(data.get("rule", "")),
            path=Path(str(data.get("path", ""))),
            severity=str(data.get("severity", "")),
            summary=str(data.get("summary", "")),
        )

    def to_json(self, root: Path) -> dict[str, str]:
        return {
            "rule": self.rule,
            "path": _relative(self.path, root),
            "severity": self.severity,
            "summary": self.summary,
        }


@dataclass
class Baseline:
    entries: dict[str, BaselineEntry] = field(default_factory=dict)

    @property
    def is_empty(self) -> bool:
        return not self.entries

    def contains(self, finding: Finding) -> bool:
        return finding.fingerprint in self.entries

    def partition(self, findings: list[Finding]) -> tuple[list[Finding], list[Finding]]:
        """Split into newly-appeared findings and already-accepted ones."""
        new = [f for f in findings if not self.contains(f)]
        accepted = [f for f in findings if self.contains(f)]
        return new, accepted

    @classmethod
    def from_findings(cls, findings: list[Finding]) -> Baseline:
        return cls(entries={f.fingerprint: BaselineEntry.from_finding(f) for f in findings})

    @classmethod
    def load(cls, path: Path) -> Baseline:
        if not path.is_file():
            return cls()
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            raise ValueError(f"could not read baseline {path}: {exc}") from exc
        if not isinstance(data, dict) or not isinstance(data.get("findings"), dict):
            raise ValueError(f"{path} is not a forensic-scan baseline file")
        return cls(
            entries={
                fingerprint: BaselineEntry.from_json(entry)
                for fingerprint, entry in data["findings"].items()
                if isinstance(entry, dict)
            }
        )

    def save(self, path: Path, root: Path) -> None:
        document = {
            "version": BASELINE_VERSION,
            "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "note": _NOTE,
            "findings": {
                fingerprint: entry.to_json(root)
                for fingerprint, entry in sorted(self.entries.items())
            },
        }
        path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")


def _relative(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()
