"""End-to-end tests of the scan pipeline and the CLI."""

import json
import subprocess

import pytest
from typer.testing import CliRunner

from forensic_scan.cli import app
from forensic_scan.models import Severity
from forensic_scan.scanner import ScanConfig, Scanner
from forensic_scan.scoring.baseline import DEFAULT_BASELINE_NAME

runner = CliRunner()

PAYLOAD_JS = b"""const raw = "Y29uc29sZS5sb2coJ2luZXJ0IHNhbXBsZSAtLSBub3RoaW5nIGhhcHBlbnMgaGVyZScpOw==";
function boot() {
  const decoded = Buffer.from(raw, 'base64').toString('utf8');
  new Function(decoded)();
}
boot();
"""

CLEAN_PY = b'''"""Ordinary module."""


def add(a, b):
    return a + b


def describe(values):
    return {"count": len(values), "total": sum(values)}
'''


@pytest.fixture
def repo(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "util.py").write_bytes(CLEAN_PY)
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "postinstall.js").write_bytes(PAYLOAD_JS)
    return tmp_path


@pytest.fixture
def git_repo(repo):
    def git(*args):
        subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)

    git("init", "-q", "-b", "main")
    git("config", "user.email", "t@example.com")
    git("config", "user.name", "Test")
    git("add", "src")
    git("commit", "-qm", "clean baseline")
    return repo, git


class TestScanPipeline:
    def test_finds_the_planted_payload(self, repo):
        result = Scanner().scan(ScanConfig(root=repo))
        assert any(f.severity >= Severity.HIGH for f in result.findings)

    def test_reports_how_many_files_it_looked_at(self, repo):
        assert Scanner().scan(ScanConfig(root=repo)).files_analyzed == 2

    def test_a_clean_tree_produces_nothing(self, tmp_path):
        (tmp_path / "a.py").write_bytes(CLEAN_PY)
        result = Scanner().scan(ScanConfig(root=tmp_path))
        assert result.findings == []
        assert result.score.band == "CLEAN"

    def test_an_unreadable_file_does_not_end_the_scan(self, repo):
        broken = repo / "src" / "broken.py"
        broken.write_bytes(b"def f(:\n  ???\n")
        result = Scanner().scan(ScanConfig(root=repo))
        assert result.files_analyzed == 3

    def test_the_risk_score_reflects_what_was_found(self, repo):
        assert Scanner().scan(ScanConfig(root=repo)).score.value > 0


class TestDiffMode:
    def test_scans_only_changed_files(self, git_repo):
        repo, _ = git_repo
        result = Scanner().scan(ScanConfig(root=repo, diff_ref="HEAD"))
        assert result.files_analyzed == 1

    def test_still_finds_the_payload_in_the_changed_file(self, git_repo):
        repo, _ = git_repo
        result = Scanner().scan(ScanConfig(root=repo, diff_ref="HEAD"))
        assert any(f.severity >= Severity.HIGH for f in result.findings)

    def test_a_diff_with_no_changes_finds_nothing(self, git_repo):
        repo, git = git_repo
        git("add", "-A")
        git("commit", "-qm", "everything")
        result = Scanner().scan(ScanConfig(root=repo, diff_ref="HEAD"))
        assert result.findings == []

    def test_an_unknown_ref_is_a_clear_error(self, git_repo):
        repo, _ = git_repo
        with pytest.raises(RuntimeError, match="nope"):
            Scanner().scan(ScanConfig(root=repo, diff_ref="nope"))


class TestBaselineRoundTrip:
    def test_a_written_baseline_silences_existing_findings(self, repo, tmp_path):
        baseline = tmp_path / "baseline.json"
        first = Scanner().scan(ScanConfig(root=repo))
        assert first.findings

        from forensic_scan.scoring.baseline import Baseline

        Baseline.from_findings(first.findings).save(baseline, root=repo)
        second = Scanner().scan(ScanConfig(root=repo, baseline_path=baseline))
        assert second.findings == []
        assert len(second.baselined) == len(first.findings)

    def test_a_new_payload_still_fires_through_a_baseline(self, repo, tmp_path):
        from forensic_scan.scoring.baseline import Baseline

        baseline = tmp_path / "baseline.json"
        first = Scanner().scan(ScanConfig(root=repo))
        Baseline.from_findings(first.findings).save(baseline, root=repo)

        (repo / "scripts" / "extra.js").write_bytes(PAYLOAD_JS)
        second = Scanner().scan(ScanConfig(root=repo, baseline_path=baseline))
        assert any(f.location.path.name == "extra.js" for f in second.findings)


class TestCli:
    def test_scanning_a_clean_tree_exits_zero(self, tmp_path):
        (tmp_path / "a.py").write_bytes(CLEAN_PY)
        assert runner.invoke(app, ["scan", str(tmp_path)]).exit_code == 0

    def test_findings_exit_one(self, repo):
        assert runner.invoke(app, ["scan", str(repo)]).exit_code == 1

    def test_fail_on_none_exits_zero_despite_findings(self, repo):
        assert runner.invoke(app, ["scan", str(repo), "--fail-on", "none"]).exit_code == 0

    def test_fail_on_critical_ignores_high_findings(self, tmp_path):
        (tmp_path / "Makefile").write_bytes(b"all:\n\tsh build.sh\n")
        assert runner.invoke(app, ["scan", str(tmp_path), "--fail-on", "CRITICAL"]).exit_code == 0

    def test_a_missing_path_exits_two(self):
        assert runner.invoke(app, ["scan", "/no/such/place"]).exit_code == 2

    def test_an_unknown_format_is_rejected(self, repo):
        result = runner.invoke(app, ["scan", str(repo), "--format", "xml"])
        assert result.exit_code != 0

    def test_json_output_parses(self, repo):
        result = runner.invoke(app, ["scan", str(repo), "--format", "json", "-q"])
        assert json.loads(result.stdout)["summary"]["findings"] > 0

    def test_sarif_output_parses_and_declares_its_version(self, repo):
        result = runner.invoke(app, ["scan", str(repo), "--format", "sarif", "-q"])
        assert json.loads(result.stdout)["version"] == "2.1.0"

    def test_writes_to_a_file_when_asked(self, repo, tmp_path):
        out = tmp_path / "report.md"
        runner.invoke(app, ["scan", str(repo), "-o", str(out)])
        assert "FOR-" in out.read_text()

    def test_excludes_are_honoured(self, repo):
        result = runner.invoke(
            app, ["scan", str(repo), "--exclude", "scripts/**", "--format", "json", "-q"]
        )
        assert json.loads(result.stdout)["summary"]["findings"] == 0

    def test_baseline_write_creates_the_file(self, repo):
        result = runner.invoke(app, ["baseline", "write", str(repo)])
        assert result.exit_code == 0
        assert (repo / DEFAULT_BASELINE_NAME).is_file()

    def test_a_written_baseline_is_picked_up_automatically(self, repo):
        runner.invoke(app, ["baseline", "write", str(repo)])
        result = runner.invoke(app, ["scan", str(repo), "--format", "json", "-q"])
        assert json.loads(result.stdout)["summary"]["findings"] == 0

    def test_no_baseline_overrides_an_existing_one(self, repo):
        runner.invoke(app, ["baseline", "write", str(repo)])
        result = runner.invoke(app, ["scan", str(repo), "--no-baseline", "--format", "json", "-q"])
        assert json.loads(result.stdout)["summary"]["findings"] > 0

    def test_rules_list_runs(self):
        result = runner.invoke(app, ["rules", "list"])
        assert result.exit_code == 0 and "FOR-001" in result.stdout

    def test_rules_validate_accepts_a_good_file(self, tmp_path):
        rules = tmp_path / "r.yml"
        rules.write_text(
            'version: "1.0"\nrules:\n  - id: FOR-900\n    name: T\n'
            "    severity: LOW\n    remediation: x\n    match: {signal: decode_call}\n"
        )
        assert runner.invoke(app, ["rules", "validate", str(rules)]).exit_code == 0

    def test_rules_validate_rejects_a_bad_file(self, tmp_path):
        rules = tmp_path / "r.yml"
        rules.write_text('version: "1.0"\nrules:\n  - id: X\n    match: {signal: nope}\n')
        assert runner.invoke(app, ["rules", "validate", str(rules)]).exit_code == 2

    def test_version_prints(self):
        result = runner.invoke(app, ["version"])
        assert "forensic-scan" in result.stdout


class TestProjectRuleOverrides:
    def test_a_project_can_disable_a_builtin_rule(self, repo):
        (repo / ".forensic-rules.yml").write_text(
            'version: "1.0"\n'
            "rules:\n"
            "  - id: FOR-001\n"
            "    name: High-entropy payload reaches dynamic execution\n"
            "    severity: CRITICAL\n"
            "    remediation: x\n"
            "    enabled: false\n"
            "    match: {signal: taint_flow}\n"
        )
        result = runner.invoke(app, ["scan", str(repo), "--format", "json", "-q"])
        assert "FOR-001" not in {f["rule"] for f in json.loads(result.stdout)["findings"]}

    def test_a_project_can_retune_a_builtin_severity(self, repo):
        (repo / ".forensic-rules.yml").write_text(
            'version: "1.0"\n'
            "rules:\n"
            "  - id: FOR-001\n"
            "    name: Retuned\n"
            "    severity: LOW\n"
            "    remediation: x\n"
            "    match: {signal: taint_flow}\n"
        )
        result = runner.invoke(app, ["scan", str(repo), "--format", "json", "-q"])
        findings = {f["rule"]: f["severity"] for f in json.loads(result.stdout)["findings"]}
        assert findings.get("FOR-001") == "LOW"

    def test_a_broken_project_rule_file_exits_two(self, repo):
        (repo / ".forensic-rules.yml").write_text("version: 1.0\nrules: [{id: X}]\n")
        assert runner.invoke(app, ["scan", str(repo)]).exit_code == 2


class TestParallelism:
    """Worker count must be a performance knob and nothing else."""

    @pytest.fixture
    def wide_repo(self, tmp_path):
        """Enough files to cross the threshold where the pool is used."""
        for i in range(80):
            (tmp_path / f"mod_{i:03d}.py").write_bytes(CLEAN_PY)
        (tmp_path / "scripts").mkdir()
        (tmp_path / "scripts" / "postinstall.js").write_bytes(PAYLOAD_JS)
        return tmp_path

    def test_parallel_and_sequential_agree_exactly(self, wide_repo):
        sequential = Scanner().scan(ScanConfig(root=wide_repo, jobs=1))
        parallel = Scanner().scan(ScanConfig(root=wide_repo, jobs=4))
        assert [f.fingerprint for f in sequential.findings] == [
            f.fingerprint for f in parallel.findings
        ]

    def test_file_counts_agree(self, wide_repo):
        sequential = Scanner().scan(ScanConfig(root=wide_repo, jobs=1))
        parallel = Scanner().scan(ScanConfig(root=wide_repo, jobs=4))
        assert sequential.files_analyzed == parallel.files_analyzed
        assert sequential.files_parsed == parallel.files_parsed

    def test_risk_scores_agree(self, wide_repo):
        sequential = Scanner().scan(ScanConfig(root=wide_repo, jobs=1))
        parallel = Scanner().scan(ScanConfig(root=wide_repo, jobs=4))
        assert sequential.score.value == parallel.score.value

    def test_suppression_survives_the_process_boundary(self, tmp_path):
        """The verdict is computed in the worker, so it has to travel back."""
        for i in range(80):
            (tmp_path / f"mod_{i:03d}.py").write_bytes(CLEAN_PY)
        vendored = tmp_path / "node_modules" / "pkg"
        vendored.mkdir(parents=True)
        (vendored / "index.js").write_bytes(PAYLOAD_JS)
        result = Scanner().scan(ScanConfig(root=tmp_path, jobs=4, include_vendored=True))
        assert result.suppressed
        assert not [f for f in result.findings if "node_modules" in str(f.location.path)]

    def test_a_small_scan_stays_sequential_and_still_works(self, repo):
        """Below the threshold the pool is skipped; results must not differ."""
        result = Scanner().scan(ScanConfig(root=repo, jobs=8))
        assert any(f.severity >= Severity.HIGH for f in result.findings)
