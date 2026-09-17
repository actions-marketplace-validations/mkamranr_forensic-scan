"""Aggregating findings into one number a maintainer can act on.

Two properties matter more than the exact arithmetic.

*Severity must dominate volume.* Fifty low-severity naming observations must not
outrank one executable smuggled into a test fixture. A linear sum gets this
wrong, so the total saturates: each additional finding of a given severity moves
the score less than the last.

*The band is not the number.* The number expresses how much there is to look at;
the band expresses how bad the worst of it is. Reporting "MEDIUM (71/100)" is
more useful than either alone -- a lot of moderate noise, nothing alarming.
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass, field

from ..models import Finding, Severity

SEVERITY_WEIGHTS: dict[Severity, float] = {
    Severity.CRITICAL: 40.0,
    Severity.HIGH: 15.0,
    Severity.MEDIUM: 5.0,
    Severity.LOW: 1.5,
    Severity.INFO: 0.0,
}

SATURATION_CONSTANT = 29.0
"""Chosen so that one CRITICAL finding lands near 75 and two near 94.

The curve is ``100 * (1 - exp(-total / k))``: strictly increasing, so more
findings always score higher, but with diminishing returns so a long tail of
minor observations cannot manufacture a crisis."""


@dataclass(frozen=True)
class RiskScore:
    value: int
    band: str
    counts: dict[Severity, int] = field(default_factory=dict)

    def __str__(self) -> str:
        return f"{self.band} ({self.value}/100)"


def score_findings(findings: list[Finding]) -> RiskScore:
    if not findings:
        return RiskScore(value=0, band="CLEAN", counts={})

    total = sum(SEVERITY_WEIGHTS[f.severity] * _confidence(f) for f in findings)
    value = round(100 * (1 - math.exp(-total / SATURATION_CONSTANT)))
    worst = max(f.severity for f in findings)
    return RiskScore(
        value=value,
        band=worst.name,
        counts=dict(Counter(f.severity for f in findings)),
    )


def exit_code_for(findings: list[Finding], fail_on: Severity | None) -> int:
    """``1`` if anything reaches ``fail_on``, else ``0``.

    ``2`` is reserved for scan errors and is returned by the CLI, not here.
    """
    if fail_on is None:
        return 0
    return 1 if any(f.severity >= fail_on for f in findings) else 0


def _confidence(finding: Finding) -> float:
    raw = finding.metadata.get("confidence", 1.0)
    return float(raw) if isinstance(raw, (int, float)) else 1.0
