"""Tests for the declarative rule schema and evaluator.

Rules are predicates over signals. Keeping them in YAML is what lets someone
contribute a detection without writing Python, so the schema has to fail loudly
and legibly on bad input.
"""

from pathlib import Path

import pytest
import yaml

from forensic_scan.engine.linkage import SignalStore
from forensic_scan.models import Location, Severity, Signal, SignalKind
from forensic_scan.rules.evaluator import RuleEvaluator
from forensic_scan.rules.schema import RuleSet, load_builtin_rules

ROOT = Path("/repo")


def _sig(kind, in_file, line=1, features=None, **metadata):
    return Signal(
        kind=kind,
        location=Location(path=ROOT / in_file, line=line, snippet="code"),
        features=features or {},
        metadata={k: str(v) for k, v in metadata.items()},
    )


def _ruleset(body: str) -> RuleSet:
    return RuleSet.model_validate(yaml.safe_load(body))


def _store(*signals):
    store = SignalStore(root=ROOT)
    store.add(list(signals))
    return store


def _evaluate(ruleset, store, languages=None):
    return RuleEvaluator(ruleset).evaluate(store, languages or {})


class TestSchemaValidation:
    def test_loads_a_minimal_rule(self):
        ruleset = _ruleset(
            """
            version: "1.0"
            rules:
              - id: TEST-001
                name: Test rule
                severity: HIGH
                remediation: do something
                match:
                  signal: dynamic_exec_sink
            """
        )
        assert ruleset.rules[0].id == "TEST-001"
        assert ruleset.rules[0].severity is Severity.HIGH

    def test_rejects_an_unknown_signal_kind_by_name(self):
        with pytest.raises(ValueError, match="unknown signal kind"):
            _ruleset(
                """
                version: "1.0"
                rules:
                  - id: TEST-001
                    name: Bad
                    severity: HIGH
                    remediation: x
                    match:
                      signal: not_a_real_signal
                """
            )

    def test_rejects_an_unknown_severity(self):
        with pytest.raises(ValueError, match="severity"):
            _ruleset(
                """
                version: "1.0"
                rules:
                  - id: TEST-001
                    name: Bad
                    severity: APOCALYPTIC
                    remediation: x
                    match:
                      signal: dynamic_exec_sink
                """
            )

    def test_rejects_a_duplicate_rule_id(self):
        with pytest.raises(ValueError, match="duplicate rule id"):
            _ruleset(
                """
                version: "1.0"
                rules:
                  - id: TEST-001
                    name: One
                    severity: HIGH
                    remediation: x
                    match: {signal: dynamic_exec_sink}
                  - id: TEST-001
                    name: Two
                    severity: LOW
                    remediation: x
                    match: {signal: decode_call}
                """
            )

    def test_rejects_an_invalid_regex_in_a_metadata_predicate(self):
        with pytest.raises(ValueError, match="invalid regular expression"):
            _ruleset(
                """
                version: "1.0"
                rules:
                  - id: TEST-001
                    name: Bad
                    severity: HIGH
                    remediation: x
                    match:
                      signal: dynamic_exec_sink
                      metadata:
                        sink: {matches: "([unclosed"}
                """
            )

    def test_rejects_an_unknown_field(self):
        """A typo in a rule file must be an error, not a silently ignored key."""
        with pytest.raises(ValueError):
            _ruleset(
                """
                version: "1.0"
                rules:
                  - id: TEST-001
                    name: Bad
                    severity: HIGH
                    remediation: x
                    sevarity: HIGH
                    match: {signal: dynamic_exec_sink}
                """
            )


class TestSignalMatching:
    RULE = """
        version: "1.0"
        rules:
          - id: TEST-001
            name: Dynamic execution
            severity: HIGH
            remediation: remove it
            match:
              signal: dynamic_exec_sink
        """

    def test_matches_a_signal_of_the_named_kind(self):
        findings = _evaluate(
            _ruleset(self.RULE), _store(_sig(SignalKind.DYNAMIC_EXEC_SINK, "a.py"))
        )
        assert [f.rule_id for f in findings] == ["TEST-001"]

    def test_ignores_signals_of_other_kinds(self):
        assert _evaluate(_ruleset(self.RULE), _store(_sig(SignalKind.DECODE_CALL, "a.py"))) == []

    def test_a_rule_may_match_several_kinds(self):
        ruleset = _ruleset(
            """
            version: "1.0"
            rules:
              - id: TEST-002
                name: Asset anomaly
                severity: CRITICAL
                remediation: x
                match:
                  signal: [magic_mismatch, executable_header]
            """
        )
        store = _store(
            _sig(SignalKind.MAGIC_MISMATCH, "a.png"),
            _sig(SignalKind.EXECUTABLE_HEADER, "b.dat"),
            _sig(SignalKind.OPAQUE_ASSET, "c.dat"),
        )
        assert len(_evaluate(ruleset, store)) == 2

    def test_a_disabled_rule_produces_nothing(self):
        ruleset = _ruleset(
            """
            version: "1.0"
            rules:
              - id: TEST-003
                name: "Off"  # quoted: YAML 1.1 reads bare Off as boolean false
                severity: HIGH
                remediation: x
                enabled: false
                match: {signal: dynamic_exec_sink}
            """
        )
        assert _evaluate(ruleset, _store(_sig(SignalKind.DYNAMIC_EXEC_SINK, "a.py"))) == []


class TestFeaturePredicates:
    RULE = """
        version: "1.0"
        rules:
          - id: TEST-010
            name: Long encoded payload
            severity: CRITICAL
            remediation: x
            match:
              signal: taint_flow
              features:
                source_length: {min: 64}
                source_looks_encoded: {min: 1}
        """

    def test_matches_when_every_threshold_is_met(self):
        sig = _sig(
            SignalKind.TAINT_FLOW,
            "a.js",
            features={"source_length": 512.0, "source_looks_encoded": 1.0},
        )
        assert len(_evaluate(_ruleset(self.RULE), _store(sig))) == 1

    def test_rejects_when_one_threshold_is_missed(self):
        sig = _sig(
            SignalKind.TAINT_FLOW,
            "a.js",
            features={"source_length": 12.0, "source_looks_encoded": 1.0},
        )
        assert _evaluate(_ruleset(self.RULE), _store(sig)) == []

    def test_a_missing_feature_does_not_match_a_minimum(self):
        assert _evaluate(_ruleset(self.RULE), _store(_sig(SignalKind.TAINT_FLOW, "a.js"))) == []

    def test_supports_a_maximum(self):
        ruleset = _ruleset(
            """
            version: "1.0"
            rules:
              - id: TEST-011
                name: Suspiciously uniform
                severity: LOW
                remediation: x
                match:
                  signal: high_entropy_identifiers
                  features:
                    identifier_count: {max: 100}
            """
        )
        low = _sig(SignalKind.HIGH_ENTROPY_IDENTIFIERS, "a.js", features={"identifier_count": 50.0})
        high = _sig(
            SignalKind.HIGH_ENTROPY_IDENTIFIERS, "b.js", features={"identifier_count": 500.0}
        )
        assert len(_evaluate(ruleset, _store(low, high))) == 1


class TestMetadataPredicates:
    def _rule(self, predicate: str) -> RuleSet:
        return _ruleset(
            f"""
            version: "1.0"
            rules:
              - id: TEST-020
                name: Specific sink
                severity: HIGH
                remediation: x
                match:
                  signal: dynamic_exec_sink
                  metadata:
                    sink: {predicate}
            """
        )

    def test_equals(self):
        store = _store(
            _sig(SignalKind.DYNAMIC_EXEC_SINK, "a.py", sink="eval"),
            _sig(SignalKind.DYNAMIC_EXEC_SINK, "b.py", sink="exec"),
        )
        assert len(_evaluate(self._rule('{equals: "eval"}'), store)) == 1

    def test_in_a_list(self):
        store = _store(
            _sig(SignalKind.DYNAMIC_EXEC_SINK, "a.py", sink="eval"),
            _sig(SignalKind.DYNAMIC_EXEC_SINK, "b.py", sink="exec"),
            _sig(SignalKind.DYNAMIC_EXEC_SINK, "c.py", sink="os.system"),
        )
        assert len(_evaluate(self._rule('{in: ["eval", "exec"]}'), store)) == 2

    def test_regex(self):
        store = _store(
            _sig(SignalKind.DYNAMIC_EXEC_SINK, "a.py", sink="subprocess.Popen"),
            _sig(SignalKind.DYNAMIC_EXEC_SINK, "b.py", sink="eval"),
        )
        assert len(_evaluate(self._rule('{matches: "^subprocess\\\\."}'), store)) == 1

    def test_contains(self):
        store = _store(_sig(SignalKind.DYNAMIC_EXEC_SINK, "a.py", sink="vm.runInNewContext"))
        assert len(_evaluate(self._rule('{contains: "runIn"}'), store)) == 1

    def test_a_missing_metadata_key_does_not_match(self):
        assert (
            _evaluate(
                self._rule('{equals: "eval"}'), _store(_sig(SignalKind.DYNAMIC_EXEC_SINK, "a.py"))
            )
            == []
        )


class TestPathAndLanguageScoping:
    def _rule(self, extra: str) -> RuleSet:
        return _ruleset(
            f"""
            version: "1.0"
            rules:
              - id: TEST-030
                name: Scoped
                severity: HIGH
                remediation: x
                match:
                  signal: opaque_asset
                  {extra}
            """
        )

    def test_restricts_to_matching_paths(self):
        store = _store(
            _sig(SignalKind.OPAQUE_ASSET, "tests/fixtures/a.dat"),
            _sig(SignalKind.OPAQUE_ASSET, "src/data/b.dat"),
        )
        findings = _evaluate(self._rule('paths: ["tests/**"]'), store)
        assert [f.location.path.as_posix() for f in findings] == ["/repo/tests/fixtures/a.dat"]

    def test_excludes_matching_paths(self):
        store = _store(
            _sig(SignalKind.OPAQUE_ASSET, "tests/a.dat"),
            _sig(SignalKind.OPAQUE_ASSET, "src/b.dat"),
        )
        findings = _evaluate(self._rule('exclude_paths: ["tests/**"]'), store)
        assert [f.location.path.name for f in findings] == ["b.dat"]

    def test_restricts_to_matching_languages(self):
        ruleset = _ruleset(
            """
            version: "1.0"
            rules:
              - id: TEST-031
                name: Python only
                severity: HIGH
                remediation: x
                match:
                  signal: dynamic_exec_sink
                  languages: [python]
            """
        )
        store = _store(
            _sig(SignalKind.DYNAMIC_EXEC_SINK, "a.py"),
            _sig(SignalKind.DYNAMIC_EXEC_SINK, "b.js"),
        )
        languages = {ROOT / "a.py": "python", ROOT / "b.js": "javascript"}
        assert len(RuleEvaluator(ruleset).evaluate(store, languages)) == 1


class TestCoOccurrence:
    RULE = """
        version: "1.0"
        rules:
          - id: TEST-040
            name: Encoded blob near a sink
            severity: HIGH
            remediation: x
            match:
              signal: encoded_alphabet_string
              also_in_file: [dynamic_exec_sink]
        """

    def test_matches_when_the_companion_signal_shares_the_file(self):
        store = _store(
            _sig(SignalKind.ENCODED_ALPHABET_STRING, "a.py", 1),
            _sig(SignalKind.DYNAMIC_EXEC_SINK, "a.py", 5),
        )
        assert len(_evaluate(_ruleset(self.RULE), store)) == 1

    def test_does_not_match_when_the_companion_is_in_another_file(self):
        store = _store(
            _sig(SignalKind.ENCODED_ALPHABET_STRING, "a.py", 1),
            _sig(SignalKind.DYNAMIC_EXEC_SINK, "b.py", 5),
        )
        assert _evaluate(_ruleset(self.RULE), store) == []

    def test_min_count_requires_repetition(self):
        ruleset = _ruleset(
            """
            version: "1.0"
            rules:
              - id: TEST-041
                name: Many encoded blobs
                severity: MEDIUM
                remediation: x
                match:
                  signal: encoded_alphabet_string
                  min_count: 3
            """
        )
        two = _store(*[_sig(SignalKind.ENCODED_ALPHABET_STRING, "a.py", i) for i in range(2)])
        three = _store(*[_sig(SignalKind.ENCODED_ALPHABET_STRING, "b.py", i) for i in range(3)])
        assert _evaluate(ruleset, two) == []
        assert len(_evaluate(ruleset, three)) == 3


class TestFindingConstruction:
    def test_the_finding_carries_the_rule_metadata(self):
        ruleset = _ruleset(
            """
            version: "1.0"
            rules:
              - id: TEST-050
                name: Named rule
                severity: CRITICAL
                remediation: fix it properly
                detail: "found {sink} at this location"
                match: {signal: dynamic_exec_sink}
            """
        )
        (finding,) = _evaluate(
            ruleset, _store(_sig(SignalKind.DYNAMIC_EXEC_SINK, "a.py", sink="eval"))
        )
        assert finding.name == "Named rule"
        assert finding.remediation == "fix it properly"
        assert finding.severity is Severity.CRITICAL

    def test_detail_interpolates_signal_metadata(self):
        ruleset = _ruleset(
            """
            version: "1.0"
            rules:
              - id: TEST-051
                name: Interpolating
                severity: HIGH
                remediation: x
                detail: "sink {sink} reached"
                match: {signal: dynamic_exec_sink}
            """
        )
        (finding,) = _evaluate(
            ruleset, _store(_sig(SignalKind.DYNAMIC_EXEC_SINK, "a.py", sink="eval"))
        )
        assert finding.detail == "sink eval reached"

    def test_an_unknown_placeholder_does_not_raise(self):
        ruleset = _ruleset(
            """
            version: "1.0"
            rules:
              - id: TEST-052
                name: Bad template
                severity: HIGH
                remediation: x
                detail: "value is {nonexistent}"
                match: {signal: dynamic_exec_sink}
            """
        )
        (finding,) = _evaluate(ruleset, _store(_sig(SignalKind.DYNAMIC_EXEC_SINK, "a.py")))
        assert "nonexistent" in finding.detail

    def test_the_finding_keeps_the_signal_that_triggered_it(self):
        ruleset = _ruleset(
            """
            version: "1.0"
            rules:
              - id: TEST-053
                name: Keeps signal
                severity: HIGH
                remediation: x
                match: {signal: dynamic_exec_sink}
            """
        )
        (finding,) = _evaluate(ruleset, _store(_sig(SignalKind.DYNAMIC_EXEC_SINK, "a.py")))
        assert finding.signals[0].kind is SignalKind.DYNAMIC_EXEC_SINK


class TestBuiltinRules:
    def test_the_builtin_ruleset_loads(self):
        assert len(load_builtin_rules().rules) > 0

    def test_every_builtin_rule_has_remediation_advice(self):
        for rule in load_builtin_rules().rules:
            assert rule.remediation.strip(), f"{rule.id} has no remediation"

    def test_builtin_rule_ids_follow_the_for_convention(self):
        for rule in load_builtin_rules().rules:
            assert rule.id.startswith("FOR-"), rule.id

    def test_the_prd_rules_are_present(self):
        ids = {r.id for r in load_builtin_rules().rules}
        assert {"FOR-001", "FOR-002", "FOR-003"} <= ids

    def test_no_builtin_rule_claims_the_linkage_id(self):
        """FOR-010 is emitted in code -- a graph join is not a signal predicate."""
        assert "FOR-010" not in {r.id for r in load_builtin_rules().rules}


class TestTemplateRobustness:
    """A rule author's mistake must degrade one sentence, never end a scan."""

    def _rule(self, detail: str) -> RuleSet:
        return _ruleset(
            f"""
            version: "1.0"
            rules:
              - id: TEST-060
                name: Template
                severity: HIGH
                remediation: x
                detail: "{detail}"
                match: {{signal: charcode_construction}}
            """
        )

    def test_a_numeric_format_spec_on_a_missing_feature_does_not_raise(self):
        store = _store(_sig(SignalKind.CHARCODE_CONSTRUCTION, "a.js"))
        (finding,) = _evaluate(self._rule("count is {elements:.0f}"), store)
        assert "elements" in finding.detail

    def test_a_numeric_format_spec_on_a_string_value_does_not_raise(self):
        store = _store(_sig(SignalKind.CHARCODE_CONSTRUCTION, "a.js", elements="many"))
        (finding,) = _evaluate(self._rule("count is {elements:.0f}"), store)
        assert "many" in finding.detail

    def test_a_present_numeric_feature_still_formats(self):
        store = _store(_sig(SignalKind.CHARCODE_CONSTRUCTION, "a.js", features={"elements": 42.0}))
        (finding,) = _evaluate(self._rule("count is {elements:.0f}"), store)
        assert finding.detail == "count is 42"


class TestSignatureTableIntegrity:
    """Guards against a positional-argument slip in the signature table.

    `_sig(..., "high")` puts a severity hint into the match-mode slot, which
    silently changes how the pattern matches. Type checking catches it; so does
    this, for anyone reading the table rather than running mypy.
    """

    def test_every_signature_has_a_valid_match_mode(self):
        from forensic_scan.engine.signatures import SIGNATURES, MatchMode

        for signature in SIGNATURES:
            assert isinstance(signature.mode, MatchMode), signature.pattern

    def test_every_signature_has_a_known_severity_hint(self):
        from forensic_scan.engine.signatures import SIGNATURES

        for signature in SIGNATURES:
            assert signature.severity_hint in {"info", "low", "medium", "high"}, signature.pattern

    def test_every_signature_has_an_explanatory_note(self):
        from forensic_scan.engine.signatures import SIGNATURES

        for signature in SIGNATURES:
            assert signature.note.strip(), signature.pattern


class TestNegativeMetadataPredicates:
    def _rule(self, predicate: str) -> RuleSet:
        return _ruleset(
            f"""
            version: "1.0"
            rules:
              - id: TEST-070
                name: Negated
                severity: LOW
                remediation: x
                match:
                  signal: magic_mismatch
                  metadata:
                    detected_category: {predicate}
            """
        )

    def _store_of_categories(self, *categories):
        return _store(
            *[_sig(SignalKind.MAGIC_MISMATCH, f"{c}.png", detected_category=c) for c in categories]
        )

    def test_not_in_excludes_listed_values(self):
        store = self._store_of_categories("executable", "archive", "text")
        findings = _evaluate(self._rule('{not-in: ["executable", "archive"]}'), store)
        assert [f.location.path.name for f in findings] == ["text.png"]

    def test_not_equals_excludes_one_value(self):
        store = self._store_of_categories("executable", "text")
        findings = _evaluate(self._rule('{not-equals: "executable"}'), store)
        assert [f.location.path.name for f in findings] == ["text.png"]

    def test_a_missing_key_still_fails_a_negated_predicate(self):
        """Absence is not proof; a rule must match on evidence it can see."""
        assert (
            _evaluate(
                self._rule('{not-in: ["executable"]}'),
                _store(_sig(SignalKind.MAGIC_MISMATCH, "a.png")),
            )
            == []
        )
