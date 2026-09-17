"""Tests for the shared vocabulary every engine and reporter depends on."""

from pathlib import Path

import pytest

from forensic_scan.models import (
    Finding,
    Location,
    Severity,
    Signal,
    SignalKind,
    TraceStep,
)


class TestSeverity:
    def test_orders_from_info_to_critical(self):
        assert Severity.INFO < Severity.LOW < Severity.MEDIUM
        assert Severity.MEDIUM < Severity.HIGH < Severity.CRITICAL

    def test_parses_case_insensitively_from_config(self):
        assert Severity.parse("critical") is Severity.CRITICAL
        assert Severity.parse("HIGH") is Severity.HIGH

    def test_rejects_unknown_severity(self):
        with pytest.raises(ValueError, match="unknown severity"):
            Severity.parse("catastrophic")

    def test_sorts_descending_for_report_ordering(self):
        got = sorted([Severity.LOW, Severity.CRITICAL, Severity.MEDIUM], reverse=True)
        assert got == [Severity.CRITICAL, Severity.MEDIUM, Severity.LOW]


class TestLocation:
    def test_renders_path_and_line_for_terminal_links(self):
        loc = Location(path=Path("src/a.py"), line=12)
        assert str(loc) == "src/a.py:12"

    def test_renders_path_alone_when_whole_file_is_the_subject(self):
        assert str(Location(path=Path("assets/blob.dat"))) == "assets/blob.dat"


class TestSignal:
    def test_exposes_numeric_features_for_correlation(self):
        sig = Signal(
            kind=SignalKind.HIGH_ENTROPY_STRING,
            location=Location(path=Path("a.js"), line=3),
            features={"entropy": 5.84, "length": 512},
        )
        assert sig.feature("entropy") == pytest.approx(5.84)

    def test_missing_feature_returns_default_rather_than_raising(self):
        sig = Signal(kind=SignalKind.MAGIC_MISMATCH, location=Location(path=Path("x.png")))
        assert sig.feature("entropy", default=0.0) == 0.0

    def test_metadata_carries_non_numeric_context(self):
        sig = Signal(
            kind=SignalKind.DYNAMIC_EXEC_SINK,
            location=Location(path=Path("a.py"), line=1),
            metadata={"sink": "eval"},
        )
        assert sig.metadata["sink"] == "eval"


class TestFinding:
    def _finding(self, **kw):
        defaults = {
            "rule_id": "FOR-001",
            "name": "High Entropy String Blob with Dynamic Execution",
            "severity": Severity.CRITICAL,
            "location": Location(path=Path("scripts/postinstall.js"), line=14),
            "detail": "payload reaches Function()",
            "remediation": "remove dynamic evaluation",
        }
        defaults.update(kw)
        return Finding(**defaults)

    def test_fingerprint_is_stable_across_identical_findings(self):
        assert self._finding().fingerprint == self._finding().fingerprint

    def test_fingerprint_survives_line_number_drift(self):
        """Unrelated edits above a finding must not invalidate a baseline entry."""
        a = self._finding(location=Location(path=Path("a.js"), line=14, snippet="eval(x)"))
        b = self._finding(location=Location(path=Path("a.js"), line=99, snippet="eval(x)"))
        assert a.fingerprint == b.fingerprint

    def test_fingerprint_differs_when_the_rule_differs(self):
        assert self._finding().fingerprint != self._finding(rule_id="FOR-002").fingerprint

    def test_fingerprint_differs_when_the_file_differs(self):
        other = self._finding(location=Location(path=Path("other.js"), line=14))
        assert self._finding().fingerprint != other.fingerprint

    def test_carries_the_signals_that_produced_it(self):
        sig = Signal(kind=SignalKind.DYNAMIC_EXEC_SINK, location=Location(path=Path("a.js")))
        assert self._finding(signals=[sig]).signals == [sig]

    def test_trace_records_an_ordered_taint_path(self):
        trace = [
            TraceStep(location=Location(path=Path("a.js"), line=1), description="literal"),
            TraceStep(location=Location(path=Path("a.js"), line=2), description="decode"),
        ]
        f = self._finding(trace=trace)
        assert [s.description for s in f.trace] == ["literal", "decode"]
