"""Detection and false-positive rates, enforced as a release gate.

Two numbers decide whether this tool is worth installing, and neither is the
one scanners usually publish. Detection rate is easy to inflate -- flag
everything and it reaches 100%. The false-positive rate on a corpus of
deliberately hard *benign* samples is the honest half, and it is measured here
against constructs chosen because they trip a naive implementation: minified
bundles, generated protobuf, embedded certificates, CRC tables, and a setup.py
that really does shell out to pkg-config.

Both numbers go in the README. If a change to a detector moves either one, this
suite says so before a release does.
"""

import re
from pathlib import Path

import pytest

from forensic_scan.models import Severity
from forensic_scan.rules.schema import load_builtin_rules
from forensic_scan.scanner import ScanConfig, Scanner

CORPUS = Path(__file__).resolve().parents[2] / "corpus"
MALICIOUS = CORPUS / "malicious"
BENIGN = CORPUS / "benign"

MIN_DETECTION_RATE = 0.90
MAX_FALSE_POSITIVE_RATE = 0.05

REPORTABLE = Severity.MEDIUM
"""Severity at which a finding on benign code counts against us.

LOW and INFO findings are observations a reader may want and never block a
build -- the default `--fail-on` is HIGH. Counting them as false positives
would make the metric meaningless in the pessimistic direction, and ignoring
MEDIUM would make it dishonest in the optimistic one.
"""

_EXPECTED_RE = re.compile(r"FOR-\d{3}")


def _samples(root: Path) -> list[Path]:
    return sorted(p for p in root.iterdir() if p.is_dir())


def _scan(path: Path):
    return Scanner().scan(
        ScanConfig(root=path, ruleset=load_builtin_rules(), baseline_path=None, fail_on=None)
    )


def _expected_rules(sample: Path) -> set[str]:
    marker = sample / "EXPECTED.md"
    if not marker.is_file():
        return set()
    first_line = marker.read_text(encoding="utf-8").splitlines()[0]
    return set(_EXPECTED_RE.findall(first_line))


class TestCorpusIntegrity:
    def test_the_malicious_corpus_is_populated(self):
        assert len(_samples(MALICIOUS)) >= 5

    def test_the_benign_corpus_is_populated(self):
        assert len(_samples(BENIGN)) >= 5

    def test_every_malicious_sample_declares_what_should_fire(self):
        for sample in _samples(MALICIOUS):
            assert _expected_rules(sample), f"{sample.name} has no EXPECTED.md"

    def test_no_sample_contains_a_real_executable(self):
        """A detection corpus that shipped live payloads would make this
        repository a distribution vector for the thing it exists to stop.

        The one ELF header present is 8 bytes of identification followed by
        random padding -- enough to be identified, far too little to run.
        """
        for path in MALICIOUS.rglob("*"):
            if not path.is_file():
                continue
            data = path.read_bytes()
            if data.startswith(b"\x7fELF"):
                assert len(data) < 8192, f"{path} is large enough to be a real binary"


@pytest.mark.parametrize("sample", _samples(MALICIOUS), ids=lambda p: p.name)
class TestMaliciousCorpus:
    def test_the_sample_is_detected(self, sample):
        result = _scan(sample)
        serious = [f for f in result.findings if f.severity >= Severity.HIGH]
        assert serious, (
            f"{sample.name} produced no finding at HIGH or above; "
            f"got {[(f.rule_id, f.severity.name) for f in result.findings]}"
        )

    def test_the_expected_rules_fire(self, sample):
        """`EXPECTED.md` names alternatives; at least one must be present."""
        expected = _expected_rules(sample)
        fired = {f.rule_id for f in _scan(sample).findings}
        assert expected & fired, f"{sample.name}: expected any of {expected}, got {fired}"


@pytest.mark.parametrize("sample", _samples(BENIGN), ids=lambda p: p.name)
class TestBenignCorpus:
    def test_the_sample_produces_no_reportable_finding(self, sample):
        result = _scan(sample)
        offending = [f for f in result.findings if f.severity >= REPORTABLE]
        assert not offending, f"{sample.name} false-positived: " + "; ".join(
            f"{f.rule_id} {f.severity.name} at {f.location} -- {f.detail}" for f in offending
        )

    def test_the_sample_never_fails_a_default_ci_run(self, sample):
        result = _scan(sample)
        assert not [f for f in result.findings if f.severity >= Severity.HIGH]


class TestRates:
    """The two published numbers."""

    def test_detection_rate_meets_the_gate(self):
        samples = _samples(MALICIOUS)
        detected = [
            s for s in samples if any(f.severity >= Severity.HIGH for f in _scan(s).findings)
        ]
        rate = len(detected) / len(samples)
        assert rate >= MIN_DETECTION_RATE, f"detection rate {rate:.0%} below gate"

    def test_false_positive_rate_meets_the_gate(self):
        samples = _samples(BENIGN)
        tripped = [s for s in samples if any(f.severity >= REPORTABLE for f in _scan(s).findings)]
        rate = len(tripped) / len(samples)
        assert rate <= MAX_FALSE_POSITIVE_RATE, f"false-positive rate {rate:.0%} above gate"

    def test_scanning_the_scanner_itself_is_clean(self):
        """The tool must not flag its own source. It contains every dangerous
        function name there is, in a table, as strings."""
        source = Path(__file__).resolve().parents[2] / "src"
        findings = [f for f in _scan(source).findings if f.severity >= Severity.HIGH]
        assert not findings, [(f.rule_id, str(f.location)) for f in findings]
