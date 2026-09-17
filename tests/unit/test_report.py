"""Tests for the three output formats."""

import json
from pathlib import Path

import pytest

from forensic_scan.models import Finding, Location, Severity, Signal, SignalKind, TraceStep
from forensic_scan.report.json_ import render_json
from forensic_scan.report.markdown import render_markdown
from forensic_scan.report.sarif import SARIF_SCHEMA, render_sarif
from forensic_scan.scanner import ScanResult
from forensic_scan.scoring.score import score_findings

ROOT = Path("/repo")


def _finding(**kw):
    defaults = {
        "rule_id": "FOR-001",
        "name": "High-entropy payload reaches dynamic execution",
        "severity": Severity.CRITICAL,
        "location": Location(
            path=ROOT / "scripts/postinstall.js",
            line=14,
            snippet="new Function(decoded)();",
        ),
        "detail": "A 512-character base64 literal flows into Function.",
        "remediation": "Remove the dynamic evaluation and inspect the payload.",
    }
    defaults.update(kw)
    return Finding(**defaults)


def _result(findings=None, **kw):
    findings = findings if findings is not None else [_finding()]
    result = ScanResult(root=ROOT, findings=findings, files_analyzed=128)
    result.score = score_findings(findings)
    for key, value in kw.items():
        setattr(result, key, value)
    return result


class TestMarkdown:
    def test_reports_the_headline_counts(self):
        out = render_markdown(_result())
        assert "128" in out
        assert "CRITICAL" in out

    def test_includes_the_rule_id_and_name(self):
        out = render_markdown(_result())
        assert "FOR-001" in out
        assert "High-entropy payload reaches dynamic execution" in out

    def test_includes_the_file_and_line(self):
        assert "scripts/postinstall.js:14" in render_markdown(_result())

    def test_paths_are_relative_to_the_repository(self):
        assert "/repo/scripts" not in render_markdown(_result())

    def test_includes_remediation_advice(self):
        assert "Remove the dynamic evaluation" in render_markdown(_result())

    def test_renders_a_taint_trace_as_numbered_steps(self):
        finding = _finding(
            trace=[
                TraceStep(Location(ROOT / "a.js", 1), "string literal"),
                TraceStep(Location(ROOT / "a.js", 3), "decoded via Buffer.from"),
                TraceStep(Location(ROOT / "a.js", 4), "reaches Function()"),
            ]
        )
        out = render_markdown(_result([finding]))
        assert "1." in out and "decoded via Buffer.from" in out

    def test_renders_a_code_snippet(self):
        assert "new Function(decoded)();" in render_markdown(_result())

    def test_a_clean_scan_says_so_plainly(self):
        out = render_markdown(_result([]))
        assert "No anomalies" in out or "no anomalies" in out.lower()

    def test_groups_findings_by_severity_worst_first(self):
        out = render_markdown(
            _result(
                [
                    _finding(severity=Severity.LOW, rule_id="FOR-020"),
                    _finding(severity=Severity.CRITICAL, rule_id="FOR-002"),
                ]
            )
        )
        assert out.index("FOR-002") < out.index("FOR-020")

    def test_reports_suppressed_counts_without_listing_them(self):
        out = render_markdown(_result([], suppressed=[_finding(), _finding()]))
        assert "2" in out and "suppress" in out.lower()

    def test_mentions_diff_mode_when_scoping_to_a_ref(self):
        assert "origin/main" in render_markdown(_result(diff_ref="origin/main"))

    def test_scan_errors_are_surfaced_not_swallowed(self):
        out = render_markdown(_result([], errors=["a.py: boom"]))
        assert "boom" in out


class TestJson:
    def test_is_valid_json(self):
        json.loads(render_json(_result()))

    def test_includes_a_schema_version(self):
        assert json.loads(render_json(_result()))["version"] == 1

    def test_includes_every_finding(self):
        data = json.loads(render_json(_result([_finding(), _finding(rule_id="FOR-002")])))
        assert len(data["findings"]) == 2

    def test_each_finding_carries_its_fingerprint(self):
        data = json.loads(render_json(_result()))
        assert len(data["findings"][0]["fingerprint"]) == 16

    def test_severity_is_a_readable_name(self):
        data = json.loads(render_json(_result()))
        assert data["findings"][0]["severity"] == "CRITICAL"

    def test_includes_the_summary_block(self):
        data = json.loads(render_json(_result()))
        assert data["summary"]["files_analyzed"] == 128
        assert data["summary"]["risk_score"] >= 70
        assert data["summary"]["risk_band"] == "CRITICAL"

    def test_paths_are_relative(self):
        data = json.loads(render_json(_result()))
        assert data["findings"][0]["path"] == "scripts/postinstall.js"

    def test_serialises_the_trace(self):
        finding = _finding(trace=[TraceStep(Location(ROOT / "a.js", 1), "literal")])
        data = json.loads(render_json(_result([finding])))
        assert data["findings"][0]["trace"][0]["description"] == "literal"

    def test_serialises_supporting_signal_features(self):
        finding = _finding(
            signals=[
                Signal(
                    kind=SignalKind.TAINT_FLOW,
                    location=Location(ROOT / "a.js", 1),
                    features={"source_entropy": 5.84},
                )
            ]
        )
        data = json.loads(render_json(_result([finding])))
        assert data["findings"][0]["signals"][0]["features"]["source_entropy"] == 5.84


class TestSarif:
    def _sarif(self, result=None):
        return json.loads(render_sarif(result or _result()))

    def test_declares_the_sarif_version_and_schema(self):
        data = self._sarif()
        assert data["version"] == "2.1.0"
        assert data["$schema"] == SARIF_SCHEMA

    def test_names_the_tool(self):
        assert self._sarif()["runs"][0]["tool"]["driver"]["name"] == "forensic-scan"

    def test_declares_each_triggered_rule_once(self):
        result = _result([_finding(), _finding(), _finding(rule_id="FOR-002")])
        rules = self._sarif(result)["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 2

    def test_results_reference_their_rule_by_index(self):
        result = _result([_finding(rule_id="FOR-002"), _finding(rule_id="FOR-001")])
        run = self._sarif(result)["runs"][0]
        for finding in run["results"]:
            declared = run["tool"]["driver"]["rules"][finding["ruleIndex"]]["id"]
            assert declared == finding["ruleId"]

    @pytest.mark.parametrize(
        "severity,level",
        [
            (Severity.CRITICAL, "error"),
            (Severity.HIGH, "error"),
            (Severity.MEDIUM, "warning"),
            (Severity.LOW, "note"),
            (Severity.INFO, "note"),
        ],
    )
    def test_maps_severity_onto_sarif_levels(self, severity, level):
        data = self._sarif(_result([_finding(severity=severity)]))
        assert data["runs"][0]["results"][0]["level"] == level

    def test_locations_use_repository_relative_uris(self):
        location = self._sarif()["runs"][0]["results"][0]["locations"][0]
        assert location["physicalLocation"]["artifactLocation"]["uri"] == "scripts/postinstall.js"

    def test_regions_are_one_indexed_lines(self):
        region = self._sarif()["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
            "region"
        ]
        assert region["startLine"] == 14

    def test_carries_a_partial_fingerprint_for_result_matching(self):
        result = self._sarif()["runs"][0]["results"][0]
        assert result["partialFingerprints"]["forensicScan/v1"]

    def test_a_trace_becomes_a_code_flow(self):
        finding = _finding(
            trace=[
                TraceStep(Location(ROOT / "a.js", 1), "literal"),
                TraceStep(Location(ROOT / "a.js", 4), "reaches Function()"),
            ]
        )
        data = self._sarif(_result([finding]))
        locations = data["runs"][0]["results"][0]["codeFlows"][0]["threadFlows"][0]["locations"]
        assert len(locations) == 2

    def test_a_finding_without_a_trace_has_no_code_flow(self):
        assert "codeFlows" not in self._sarif()["runs"][0]["results"][0]

    def test_a_clean_scan_produces_an_empty_results_array(self):
        data = self._sarif(_result([]))
        assert data["runs"][0]["results"] == []

    def test_a_finding_with_no_line_still_produces_a_valid_location(self):
        finding = _finding(location=Location(path=ROOT / "tests/blob.dat"))
        region = self._sarif(_result([finding]))["runs"][0]["results"][0]["locations"][0]
        assert region["physicalLocation"]["artifactLocation"]["uri"] == "tests/blob.dat"
