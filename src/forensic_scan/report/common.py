"""Shared helpers for the reporters."""

from __future__ import annotations

from pathlib import Path


def relative(path: Path, root: Path) -> str:
    """A repository-relative path, which is what every consumer wants.

    Absolute paths leak the CI runner's directory layout into reports and break
    result matching between runs on different machines.
    """
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()
