"""The ``.forensic-rules.yml`` schema.

Rules are predicates over signals, not over source code. An engine has already
done the work of noticing things; a rule decides which noticings are worth
telling a human about, and how loudly.

This indirection is the point of the whole design. It means a contributor can
add a detection by writing YAML rather than Python, and it means entropy can
inform a conclusion without ever being one -- ``features: {entropy: {min: 5.2}}``
is a *condition* on a signal that some other engine already qualified, not a
standalone tripwire.

Validation is strict on purpose: an unknown field is an error rather than a
silently ignored key, because a typo in a rule file would otherwise disable a
detection without anyone noticing.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ..models import Severity, SignalKind

BUILTIN_RULES_DIR = Path(__file__).parent / "builtin"

_VALID_SIGNAL_NAMES = {kind.value for kind in SignalKind}


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Threshold(_Strict):
    """A numeric bound on a signal feature. Both ends are optional."""

    min: float | None = None
    max: float | None = None

    def accepts(self, value: float | None) -> bool:
        if value is None:
            return False
        if self.min is not None and value < self.min:
            return False
        return not (self.max is not None and value > self.max)


class MetadataPredicate(_Strict):
    """A string test on a signal's metadata."""

    equals: str | None = None
    not_equals: str | None = Field(default=None, alias="not-equals")
    in_: list[str] | None = Field(default=None, alias="in")
    not_in: list[str] | None = Field(default=None, alias="not-in")
    matches: str | None = None
    contains: str | None = None

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    @field_validator("matches")
    @classmethod
    def _check_regex(cls, value: str | None) -> str | None:
        if value is not None:
            try:
                re.compile(value)
            except re.error as exc:
                raise ValueError(f"invalid regular expression {value!r}: {exc}") from exc
        return value

    def accepts(self, value: str | None) -> bool:
        if value is None:
            return False
        if self.equals is not None and value != self.equals:
            return False
        if self.not_equals is not None and value == self.not_equals:
            return False
        if self.in_ is not None and value not in self.in_:
            return False
        if self.not_in is not None and value in self.not_in:
            return False
        if self.contains is not None and self.contains not in value:
            return False
        return not (self.matches is not None and not re.search(self.matches, value))


class Match(_Strict):
    """What a rule looks for."""

    signal: list[SignalKind]
    languages: list[str] | None = None
    paths: list[str] | None = None
    exclude_paths: list[str] | None = None
    features: dict[str, Threshold] = Field(default_factory=dict)
    metadata: dict[str, MetadataPredicate] = Field(default_factory=dict)
    also_in_file: list[SignalKind] | None = None
    """Signal kinds that must also be present somewhere in the same file.

    Co-occurrence rather than data flow -- cheap, and enough to express "an
    encoded blob in a file that also calls eval" without a query language."""
    min_count: int = Field(default=1, ge=1)
    """How many matching signals a file needs before any of them are reported."""

    @field_validator("signal", "also_in_file", mode="before")
    @classmethod
    def _coerce_kinds(cls, value: Any) -> Any:
        if value is None:
            return value
        names = [value] if isinstance(value, str) else value
        if not isinstance(names, list):
            raise ValueError("signal must be a name or a list of names")
        for name in names:
            if name not in _VALID_SIGNAL_NAMES:
                valid = ", ".join(sorted(_VALID_SIGNAL_NAMES))
                raise ValueError(f"unknown signal kind {name!r}; expected one of: {valid}")
        return names


class Rule(_Strict):
    """One detection."""

    id: str
    name: str
    severity: Severity
    remediation: str
    match: Match
    detail: str | None = None
    enabled: bool = True
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)

    @field_validator("severity", mode="before")
    @classmethod
    def _parse_severity(cls, value: Any) -> Any:
        return Severity.parse(value) if isinstance(value, str) else value


class RuleSet(_Strict):
    version: str
    rules: list[Rule]

    @model_validator(mode="after")
    def _unique_ids(self) -> RuleSet:
        seen: set[str] = set()
        for rule in self.rules:
            if rule.id in seen:
                raise ValueError(f"duplicate rule id: {rule.id}")
            seen.add(rule.id)
        return self

    @property
    def enabled_rules(self) -> list[Rule]:
        return [r for r in self.rules if r.enabled]

    def merged_with(self, other: RuleSet) -> RuleSet:
        """Combine rulesets; a later rule replaces an earlier one of the same id.

        This is how a project overrides a built-in rule -- by redefining its id
        in ``.forensic-rules.yml``, including setting ``enabled: false``.
        """
        by_id = {rule.id: rule for rule in self.rules}
        for rule in other.rules:
            by_id[rule.id] = rule
        return RuleSet(version=other.version, rules=list(by_id.values()))


def load_ruleset(path: Path) -> RuleSet:
    """Load and validate one rule file."""
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ValueError(f"{path}: not valid YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise ValueError(f"{path}: expected a mapping with 'version' and 'rules'")
    try:
        return RuleSet.model_validate(raw)
    except Exception as exc:
        raise ValueError(f"{path}: {exc}") from exc


def load_builtin_rules() -> RuleSet:
    """Every rule shipped with the scanner, merged into one set."""
    merged = RuleSet(version="1.0", rules=[])
    for path in sorted(BUILTIN_RULES_DIR.glob("*.yml")):
        merged = merged.merged_with(load_ruleset(path))
    return merged
