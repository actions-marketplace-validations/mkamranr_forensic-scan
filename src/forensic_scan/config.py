"""Loading rules and locating project configuration."""

from __future__ import annotations

from pathlib import Path

from .rules.schema import RuleSet, load_builtin_rules, load_ruleset
from .scoring.baseline import DEFAULT_BASELINE_NAME

PROJECT_RULES_NAME = ".forensic-rules.yml"
PROJECT_RULES_ALTERNATES = (".forensic-rules.yaml",)


def find_project_rules(root: Path) -> Path | None:
    """The repository's own rule file, if it has one."""
    for name in (PROJECT_RULES_NAME, *PROJECT_RULES_ALTERNATES):
        candidate = root / name
        if candidate.is_file():
            return candidate
    return None


def find_baseline(root: Path) -> Path | None:
    candidate = root / DEFAULT_BASELINE_NAME
    return candidate if candidate.is_file() else None


def build_ruleset(root: Path, extra: Path | None = None, builtins: bool = True) -> RuleSet:
    """Built-in rules, then the project's, then any passed on the command line.

    Later definitions replace earlier ones by id, so a project can retune or
    disable a built-in rule without forking it.
    """
    ruleset = load_builtin_rules() if builtins else RuleSet(version="1.0", rules=[])
    project = find_project_rules(root)
    if project is not None:
        ruleset = ruleset.merged_with(load_ruleset(project))
    if extra is not None:
        ruleset = ruleset.merged_with(load_ruleset(extra))
    return ruleset
