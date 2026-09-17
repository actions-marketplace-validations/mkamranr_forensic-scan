"""Measure and print the detection and false-positive rates.

Run by CI so the published numbers in the README are the measured ones, and so
a change that moves either rate is visible in the pull request that caused it.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from forensic_scan.models import Severity  # noqa: E402
from forensic_scan.rules.schema import load_builtin_rules  # noqa: E402
from forensic_scan.scanner import ScanConfig, Scanner  # noqa: E402

REPORTABLE = Severity.MEDIUM


def scan(path: Path):
    return Scanner().scan(
        ScanConfig(root=path, ruleset=load_builtin_rules(), baseline_path=None, fail_on=None)
    )


def samples(root: Path) -> list[Path]:
    return sorted(p for p in root.iterdir() if p.is_dir())


def main() -> int:
    malicious = samples(ROOT / "corpus" / "malicious")
    benign = samples(ROOT / "corpus" / "benign")

    detected, missed = [], []
    for sample in malicious:
        result = scan(sample)
        best = max((f.severity for f in result.findings), default=Severity.INFO)
        (detected if best >= Severity.HIGH else missed).append((sample.name, best.name))

    clean, tripped = [], []
    for sample in benign:
        result = scan(sample)
        offenders = [f for f in result.findings if f.severity >= REPORTABLE]
        (tripped if offenders else clean).append(
            (sample.name, [f"{f.rule_id}/{f.severity.name}" for f in offenders])
        )

    detection = len(detected) / len(malicious) if malicious else 0.0
    false_positive = len(tripped) / len(benign) if benign else 0.0

    print("## forensic-scan corpus benchmark\n")
    print(
        f"- **Detection rate:** {detection:.0%} ({len(detected)}/{len(malicious)} samples "
        f"flagged at HIGH or above)"
    )
    print(
        f"- **False-positive rate:** {false_positive:.0%} ({len(tripped)}/{len(benign)} benign "
        f"samples producing a finding at MEDIUM or above)\n"
    )

    print("| Malicious sample | Highest severity |")
    print("|---|---|")
    for name, severity in sorted(detected + missed):
        print(f"| `{name}` | {severity} |")

    print("\n| Benign sample | Reportable findings |")
    print("|---|---|")
    for name, offenders in sorted(clean + tripped):
        print(f"| `{name}` | {', '.join(offenders) if offenders else 'none'} |")

    return 0 if not missed and not tripped else 1


if __name__ == "__main__":
    raise SystemExit(main())
