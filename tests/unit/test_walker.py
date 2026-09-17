"""Tests for file discovery: which files a scan actually looks at."""

import subprocess
from pathlib import Path

import pytest

from forensic_scan.discovery.walker import (
    DEFAULT_MAX_FILE_SIZE,
    SkipReason,
    changed_files,
    walk,
)


def _mk(root: Path, rel: str, content: bytes = b"x\n") -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(content)
    return p


def _rels(root: Path, results) -> set[str]:
    return {r.path.relative_to(root).as_posix() for r in results}


class TestWalk:
    def test_yields_ordinary_files(self, tmp_path):
        _mk(tmp_path, "a.py")
        _mk(tmp_path, "src/b.js")
        assert _rels(tmp_path, walk(tmp_path).files) == {"a.py", "src/b.js"}

    def test_results_are_deterministically_ordered(self, tmp_path):
        for name in ("z.py", "a.py", "m/b.py"):
            _mk(tmp_path, name)
        first = [r.path for r in walk(tmp_path).files]
        assert first == sorted(first)

    def test_skips_the_git_directory(self, tmp_path):
        _mk(tmp_path, ".git/config")
        _mk(tmp_path, "a.py")
        assert _rels(tmp_path, walk(tmp_path).files) == {"a.py"}

    def test_skips_caches_and_virtualenvs(self, tmp_path):
        for junk in ("__pycache__/x.pyc", ".venv/lib/y.py", ".mypy_cache/z.json"):
            _mk(tmp_path, junk)
        _mk(tmp_path, "a.py")
        assert _rels(tmp_path, walk(tmp_path).files) == {"a.py"}

    def test_excludes_vendored_trees_by_default(self, tmp_path):
        _mk(tmp_path, "node_modules/pkg/index.js")
        _mk(tmp_path, "a.py")
        assert _rels(tmp_path, walk(tmp_path).files) == {"a.py"}

    def test_includes_vendored_trees_on_request(self, tmp_path):
        """Auditing a dependency means node_modules IS the target."""
        _mk(tmp_path, "node_modules/pkg/index.js")
        got = _rels(tmp_path, walk(tmp_path, include_vendored=True).files)
        assert "node_modules/pkg/index.js" in got

    def test_honours_gitignore(self, tmp_path):
        _mk(tmp_path, ".gitignore", b"ignored/\n*.log\n")
        _mk(tmp_path, "ignored/secret.py")
        _mk(tmp_path, "debug.log")
        _mk(tmp_path, "a.py")
        assert _rels(tmp_path, walk(tmp_path).files) == {"a.py", ".gitignore"}

    def test_gitignore_can_be_disabled_for_full_audits(self, tmp_path):
        _mk(tmp_path, ".gitignore", b"hidden.py\n")
        _mk(tmp_path, "hidden.py")
        got = _rels(tmp_path, walk(tmp_path, respect_gitignore=False).files)
        assert "hidden.py" in got

    def test_nested_gitignore_applies_to_its_subtree(self, tmp_path):
        _mk(tmp_path, "pkg/.gitignore", b"*.gen.js\n")
        _mk(tmp_path, "pkg/a.gen.js")
        _mk(tmp_path, "other/b.gen.js")
        got = _rels(tmp_path, walk(tmp_path).files)
        assert "pkg/a.gen.js" not in got
        assert "other/b.gen.js" in got

    def test_extra_excludes_are_applied(self, tmp_path):
        _mk(tmp_path, "docs/x.py")
        _mk(tmp_path, "a.py")
        got = _rels(tmp_path, walk(tmp_path, excludes=["docs/**"]).files)
        assert got == {"a.py"}

    def test_records_oversized_files_as_skipped_rather_than_dropping_them(self, tmp_path):
        _mk(tmp_path, "huge.bin", b"\x00" * 2048)
        result = walk(tmp_path, max_file_size=1024)
        assert result.files == []
        assert [s.reason for s in result.skipped] == [SkipReason.TOO_LARGE]

    def test_does_not_follow_symlinks(self, tmp_path):
        outside = tmp_path.parent / "outside_target"
        outside.mkdir(exist_ok=True)
        (outside / "evil.py").write_bytes(b"x\n")
        (tmp_path / "link").symlink_to(outside, target_is_directory=True)
        _mk(tmp_path, "a.py")
        result = walk(tmp_path)
        assert _rels(tmp_path, result.files) == {"a.py"}
        assert any(s.reason is SkipReason.SYMLINK for s in result.skipped)

    def test_a_single_file_root_scans_just_that_file(self, tmp_path):
        p = _mk(tmp_path, "a.py")
        assert [r.path for r in walk(p).files] == [p]

    def test_classifies_each_file_it_yields(self, tmp_path):
        _mk(tmp_path, "setup.py", b"from setuptools import setup\n")
        (found,) = walk(tmp_path).files
        assert found.language == "python" and found.is_build

    def test_default_size_cap_is_generous_enough_for_real_fixtures(self):
        assert DEFAULT_MAX_FILE_SIZE >= 10 * 1024 * 1024


class TestChangedFiles:
    @pytest.fixture
    def repo(self, tmp_path):
        def git(*args):
            subprocess.run(["git", *args], cwd=tmp_path, check=True, capture_output=True, text=True)

        git("init", "-q", "-b", "main")
        git("config", "user.email", "t@example.com")
        git("config", "user.name", "Test")
        _mk(tmp_path, "base.py", b"print(1)\n")
        git("add", "-A")
        git("commit", "-qm", "base")
        return tmp_path, git

    def test_lists_files_changed_since_a_ref(self, repo):
        root, git = repo
        _mk(root, "added.py", b"print(2)\n")
        git("add", "-A")
        git("commit", "-qm", "second")
        assert changed_files(root, "HEAD~1") == [root / "added.py"]

    def test_includes_uncommitted_work(self, repo):
        """A maintainer running the scanner locally has not committed yet."""
        root, _ = repo
        _mk(root, "wip.py", b"print(3)\n")
        assert root / "wip.py" in changed_files(root, "HEAD")

    def test_omits_files_deleted_in_the_range(self, repo):
        root, git = repo
        (root / "base.py").unlink()
        git("add", "-A")
        git("commit", "-qm", "delete")
        assert changed_files(root, "HEAD~1") == []

    def test_raises_a_clear_error_outside_a_git_repository(self, tmp_path):
        with pytest.raises(RuntimeError, match="not a git repository"):
            changed_files(tmp_path, "HEAD")

    def test_raises_a_clear_error_for_an_unknown_ref(self, repo):
        root, _ = repo
        with pytest.raises(RuntimeError, match="no-such-ref"):
            changed_files(root, "no-such-ref")
