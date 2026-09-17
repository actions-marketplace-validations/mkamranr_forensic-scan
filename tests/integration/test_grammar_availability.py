"""An unparseable scan must never look like a clean one.

`tree-sitter-language-pack` fetches grammars on first use and caches them. In an
air-gapped runner, behind a blocked proxy, or in an unwarmed container, that
fetch fails -- and an earlier version of this scanner swallowed the error,
parsed nothing, and reported no findings. A security tool that announces safety
it never established is worse than one that crashes.

These tests pin the loud-failure contract.
"""

import pytest
from typer.testing import CliRunner

from forensic_scan.cli import app
from forensic_scan.parser.registry import ParserRegistry
from forensic_scan.scanner import ScanConfig, Scanner

runner = CliRunner()

PAYLOAD = b'import base64\nB = "%s"\nexec(base64.b64decode(B))\n' % (b"QUJD" * 20)


@pytest.fixture
def repo(tmp_path):
    (tmp_path / "mod.py").write_bytes(PAYLOAD)
    return tmp_path


class _OfflineRegistry(ParserRegistry):
    """A registry whose grammar downloads always fail, as they do offline."""

    def _language(self, language: str):
        self.grammar_errors[language] = "DownloadError: failed to fetch manifest"
        return None

    def _parser(self, language: str):
        self.grammar_errors[language] = "DownloadError: failed to fetch manifest"
        return None


class TestUnavailableGrammar:
    def test_the_scan_reports_the_language_as_unavailable(self, repo):
        result = Scanner(registry=_OfflineRegistry()).scan(ScanConfig(root=repo, jobs=1))
        assert "python" in result.unavailable_languages

    def test_the_scan_counts_the_files_it_could_not_analyse(self, repo):
        result = Scanner(registry=_OfflineRegistry()).scan(ScanConfig(root=repo, jobs=1))
        assert result.files_unanalyzed == 1

    def test_the_error_names_the_remedy(self, repo):
        result = Scanner(registry=_OfflineRegistry()).scan(ScanConfig(root=repo, jobs=1))
        assert any("prefetch" in e for e in result.errors)

    def test_the_markdown_report_leads_with_the_warning(self, repo):
        from forensic_scan.report.markdown import render_markdown

        result = Scanner(registry=_OfflineRegistry()).scan(ScanConfig(root=repo, jobs=1))
        rendered = render_markdown(result)
        assert "incomplete" in rendered.lower()
        # Before the summary, not buried under it.
        assert rendered.index("incomplete") < rendered.index("Files analysed")

    def test_the_json_report_marks_the_scan_incomplete(self, repo):
        import json

        from forensic_scan.report.json_ import render_json

        result = Scanner(registry=_OfflineRegistry()).scan(ScanConfig(root=repo, jobs=1))
        summary = json.loads(render_json(result))["summary"]
        assert summary["complete"] is False
        assert summary["files_unanalyzed"] == 1

    def test_a_complete_scan_is_marked_complete(self, repo):
        import json

        from forensic_scan.report.json_ import render_json

        result = Scanner().scan(ScanConfig(root=repo, jobs=1))
        assert json.loads(render_json(result))["summary"]["complete"] is True

    def test_binary_asset_analysis_still_runs_without_a_grammar(self, tmp_path):
        """Grammar loss must degrade the scan, not end it."""
        (tmp_path / "x.py").write_bytes(PAYLOAD)
        (tmp_path / "logo.png").write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 64)
        result = Scanner(registry=_OfflineRegistry()).scan(ScanConfig(root=tmp_path, jobs=1))
        assert any(f.rule_id == "FOR-002" for f in result.findings)


class TestPrefetchCommand:
    def test_prefetch_reports_each_language(self):
        result = runner.invoke(app, ["prefetch"])
        assert result.exit_code == 0
        assert "python" in result.stdout

    def test_prefetch_names_the_cache_location(self):
        assert "Cache:" in runner.invoke(app, ["prefetch"]).stdout

    def test_prefetch_accepts_a_language_list(self):
        assert runner.invoke(app, ["prefetch", "python"]).exit_code == 0


class TestRegistryContract:
    def test_ensure_succeeds_for_a_supported_language(self):
        assert ParserRegistry().ensure("python") is True

    def test_ensure_rejects_an_unsupported_language(self):
        assert ParserRegistry().ensure("cobol") is False

    def test_a_load_failure_is_recorded_with_its_reason(self):
        registry = _OfflineRegistry()
        assert registry.ensure("python") is False
        assert "DownloadError" in registry.grammar_errors["python"]

    def test_an_unsupported_language_is_not_recorded_as_an_error(self):
        """Absence of a grammar we never claimed is not a scan integrity problem."""
        registry = ParserRegistry()
        registry.ensure("cobol")
        assert "cobol" not in registry.grammar_errors
