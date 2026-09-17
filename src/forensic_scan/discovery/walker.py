"""Choosing what to scan.

Two selection modes share everything downstream:

*Full* -- walk a tree, honouring ``.gitignore`` and skipping the directories no
audit wants to read.

*Diff* -- only what changed against a git ref. This is the default posture for
PR review, and it is the single most effective false-positive control in the
tool: a vendored minified bundle is noise in a full scan but a real question
when it appears in a pull request that claims to fix a typo.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

import pathspec

from .classify import HEADER_READ_BYTES, ClassifiedFile, classify_file

DEFAULT_MAX_FILE_SIZE = 32 * 1024 * 1024
"""Above this a file is recorded as skipped rather than read into memory."""

ALWAYS_EXCLUDED = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".bzr",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".tox",
        ".venv",
        "venv",
        ".env",
        "env",
        ".idea",
        ".vscode",
        ".DS_Store",
        ".gradle",
        ".terraform",
    }
)

VENDORED_DIRECTORIES = frozenset(
    {"node_modules", "vendor", "third_party", "thirdparty", "bower_components", "site-packages"}
)
"""Excluded by default for speed, included with ``--include-vendored``.

These are where dependency-confusion payloads live, so the flag matters: when
auditing a package rather than reviewing a PR, this tree *is* the target.
"""


class SkipReason(str, Enum):
    TOO_LARGE = "too_large"
    SYMLINK = "symlink"
    UNREADABLE = "unreadable"


@dataclass(frozen=True)
class SkippedFile:
    path: Path
    reason: SkipReason
    detail: str = ""


@dataclass
class WalkResult:
    root: Path
    files: list[ClassifiedFile] = field(default_factory=list)
    skipped: list[SkippedFile] = field(default_factory=list)


class _IgnoreStack:
    """Layered ``.gitignore`` matching -- a nested file governs its own subtree."""

    def __init__(self) -> None:
        self._specs: list[tuple[Path, pathspec.PathSpec[pathspec.Pattern]]] = []

    def add(self, directory: Path, gitignore: Path) -> None:
        try:
            lines = gitignore.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return
        self._specs.append((directory, pathspec.PathSpec.from_lines("gitignore", lines)))

    def matches(self, path: Path, *, is_dir: bool) -> bool:
        for base, spec in self._specs:
            try:
                rel = path.relative_to(base).as_posix()
            except ValueError:
                continue
            if spec.match_file(rel + "/" if is_dir else rel):
                return True
        return False


def _read_header(path: Path) -> tuple[bytes, int] | None:
    try:
        size = path.stat().st_size
        with path.open("rb") as fh:
            return fh.read(HEADER_READ_BYTES), size
    except OSError:
        return None


def walk(
    root: Path,
    *,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    excludes: list[str] | None = None,
    respect_gitignore: bool = True,
    include_vendored: bool = False,
) -> WalkResult:
    """Walk ``root`` and classify every file worth scanning."""
    root = Path(root)
    result = WalkResult(root=root)
    extra = pathspec.PathSpec.from_lines("gitignore", excludes or [])

    if root.is_file():
        _consider(root, root, result, max_file_size)
        return result

    excluded_dirs = set(ALWAYS_EXCLUDED)
    if not include_vendored:
        excluded_dirs |= VENDORED_DIRECTORIES

    ignores = _IgnoreStack()
    _walk_directory(
        root, root, result, ignores, extra, excluded_dirs, respect_gitignore, max_file_size
    )
    result.files.sort(key=lambda c: c.path)
    result.skipped.sort(key=lambda s: s.path)
    return result


def _walk_directory(
    directory: Path,
    root: Path,
    result: WalkResult,
    ignores: _IgnoreStack,
    extra: pathspec.PathSpec[pathspec.Pattern],
    excluded_dirs: set[str],
    respect_gitignore: bool,
    max_file_size: int,
) -> None:
    try:
        entries = sorted(directory.iterdir(), key=lambda p: p.name)
    except OSError:
        return

    if respect_gitignore:
        gitignore = directory / ".gitignore"
        if gitignore.is_file():
            ignores.add(directory, gitignore)

    for entry in entries:
        rel = entry.relative_to(root).as_posix()
        is_dir = entry.is_dir()

        if entry.is_symlink():
            result.skipped.append(
                SkippedFile(entry, SkipReason.SYMLINK, "symlinks are not followed")
            )
            continue
        if is_dir and entry.name in excluded_dirs:
            continue
        if extra.match_file(rel + "/" if is_dir else rel):
            continue
        if respect_gitignore and ignores.matches(entry, is_dir=is_dir):
            continue

        if is_dir:
            _walk_directory(
                entry, root, result, ignores, extra, excluded_dirs, respect_gitignore, max_file_size
            )
        elif entry.is_file():
            _consider(entry, root, result, max_file_size)


def _consider(path: Path, root: Path, result: WalkResult, max_file_size: int) -> None:
    read = _read_header(path)
    if read is None:
        result.skipped.append(SkippedFile(path, SkipReason.UNREADABLE))
        return
    header, size = read
    if size > max_file_size:
        result.skipped.append(
            SkippedFile(path, SkipReason.TOO_LARGE, f"{size} bytes exceeds {max_file_size}")
        )
        return
    result.files.append(classify_file(path, header=header, size=size))


def _git(root: Path, *args: str) -> str:
    try:
        proc = subprocess.run(
            ["git", "-C", str(root), *args], capture_output=True, text=True, check=False
        )
    except FileNotFoundError:  # pragma: no cover - git is a hard requirement of diff mode
        raise RuntimeError("git executable not found; diff mode requires git") from None
    if proc.returncode != 0:
        stderr = proc.stderr.strip()
        if "not a git repository" in stderr.lower():
            raise RuntimeError(f"{root} is not a git repository; diff mode requires one")
        raise RuntimeError(f"git {' '.join(args)} failed: {stderr}")
    return proc.stdout


def changed_files(root: Path, ref: str) -> list[Path]:
    """Files added or modified since ``ref``, including uncommitted work.

    Deletions are omitted -- there is nothing left to scan. ``git diff`` is used
    rather than the two-dot form so that a stale local branch does not report
    every upstream change as a local one.
    """
    root = Path(root)
    _git(root, "rev-parse", "--git-dir")
    try:
        _git(root, "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}")
    except RuntimeError:
        raise RuntimeError(f"unknown git ref: {ref}") from None

    merge_base = _git(root, "merge-base", ref, "HEAD").strip() or ref
    tracked = _git(root, "diff", "--name-only", "--diff-filter=d", merge_base)
    untracked = _git(root, "ls-files", "--others", "--exclude-standard")

    seen: dict[str, None] = {}
    for line in (*tracked.splitlines(), *untracked.splitlines()):
        name = line.strip()
        if name:
            seen[name] = None
    return sorted((root / name) for name in seen if (root / name).is_file())
