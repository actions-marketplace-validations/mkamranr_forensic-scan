"""Turning signals into findings.

The evaluator is deliberately dull. All the judgement lives in the rule files
and in the engines that produced the signals; this module just applies
predicates and builds ``Finding`` objects. That is what keeps rule authoring a
YAML exercise rather than a Python one.
"""

from __future__ import annotations

import string
from collections import defaultdict
from pathlib import Path

import pathspec

from ..engine.linkage import SignalStore
from ..models import Finding, Signal, SignalKind
from .schema import Match, Rule, RuleSet


class _ForgivingFormatter(string.Formatter):
    """Renders a rule's detail template, absorbing every authoring mistake.

    A rule author's typo should produce a slightly odd sentence in a report, not
    a crash in the middle of a scan -- the scan is the valuable part. Two
    mistakes are absorbed: a placeholder naming a feature the signal does not
    carry, and a numeric format spec applied to something that is not a number.
    """

    def get_value(self, key, args, kwargs):  # type: ignore[no-untyped-def]
        if isinstance(key, str):
            return kwargs.get(key, "{" + key + "}")
        return super().get_value(key, args, kwargs)

    def format_field(self, value, format_spec):  # type: ignore[no-untyped-def]
        try:
            return super().format_field(value, format_spec)
        except (ValueError, TypeError):
            return str(value)


_FORMATTER = _ForgivingFormatter()


class RuleEvaluator:
    def __init__(self, ruleset: RuleSet) -> None:
        self.ruleset = ruleset
        self._specs: dict[str, pathspec.PathSpec[pathspec.Pattern]] = {}

    def evaluate(self, store: SignalStore, languages: dict[Path, str | None]) -> list[Finding]:
        findings: list[Finding] = []
        for rule in self.ruleset.enabled_rules:
            findings.extend(self._apply(rule, store, languages))
        findings.sort(key=lambda f: (-f.severity.value, str(f.location), f.rule_id))
        return findings

    def _apply(
        self, rule: Rule, store: SignalStore, languages: dict[Path, str | None]
    ) -> list[Finding]:
        candidates = [
            signal
            for signal in store.of_kinds(set(rule.match.signal))
            if self._accepts(rule.match, signal, store, languages)
        ]
        if rule.match.min_count > 1:
            candidates = self._filter_by_count(candidates, rule.match.min_count)
        return [self._finding(rule, signal) for signal in candidates]

    # -- predicates --------------------------------------------------------

    def _accepts(
        self,
        match: Match,
        signal: Signal,
        store: SignalStore,
        languages: dict[Path, str | None],
    ) -> bool:
        path = signal.location.path
        if match.languages is not None and languages.get(path) not in match.languages:
            return False
        if match.paths is not None and not self._matches_any(match.paths, path, store.root):
            return False
        if match.exclude_paths is not None and self._matches_any(
            match.exclude_paths, path, store.root
        ):
            return False
        for name, threshold in match.features.items():
            if not threshold.accepts(signal.features.get(name)):
                return False
        for key, predicate in match.metadata.items():
            if not predicate.accepts(signal.metadata.get(key)):
                return False
        if match.also_in_file is not None:
            present = {s.kind for s in store.in_file(path)}
            if not set(match.also_in_file) <= present:
                return False
        return True

    @staticmethod
    def _filter_by_count(signals: list[Signal], minimum: int) -> list[Signal]:
        """Keep signals only from files that carry at least ``minimum`` of them."""
        by_file: dict[Path, list[Signal]] = defaultdict(list)
        for signal in signals:
            by_file[signal.location.path].append(signal)
        return [s for group in by_file.values() if len(group) >= minimum for s in group]

    def _matches_any(self, patterns: list[str], path: Path, root: Path) -> bool:
        key = "\n".join(patterns)
        if key not in self._specs:
            self._specs[key] = pathspec.PathSpec.from_lines("gitignore", patterns)
        try:
            relative = path.relative_to(root).as_posix()
        except ValueError:
            relative = path.as_posix()
        return self._specs[key].match_file(relative)

    # -- finding construction ---------------------------------------------

    @staticmethod
    def _finding(rule: Rule, signal: Signal) -> Finding:
        context: dict[str, object] = {**signal.metadata, **signal.features}
        context.setdefault("path", signal.location.path.as_posix())
        context.setdefault("line", signal.location.line or 0)

        if rule.detail:
            detail = _FORMATTER.vformat(rule.detail, (), context)
        else:
            detail = _default_detail(signal)

        return Finding(
            rule_id=rule.id,
            name=rule.name,
            severity=rule.severity,
            location=signal.location,
            detail=detail,
            remediation=rule.remediation,
            signals=[signal],
            metadata={"confidence": rule.confidence * signal.confidence},
        )


def _default_detail(signal: Signal) -> str:
    """A readable sentence when a rule supplies no template."""
    subject = signal.kind.value.replace("_", " ")
    extras = [f"{k}={v}" for k, v in sorted(signal.metadata.items()) if k != "trace"]
    numeric = [
        f"{k}={v:.2f}" if isinstance(v, float) else f"{k}={v}"
        for k, v in sorted(signal.features.items())
    ]
    details = ", ".join(extras + numeric)
    return f"{subject}{f' ({details})' if details else ''}"


__all__ = ["RuleEvaluator", "SignalKind"]
