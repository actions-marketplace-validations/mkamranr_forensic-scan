"""Tests for the tree-sitter access layer."""

from pathlib import Path

import pytest

from forensic_scan.parser.registry import QUERY_KINDS, ParserRegistry

PY = b"""import os

SECRET = "aGVsbG8="

def run(payload):
    decoded = os.popen(payload)
    return eval(decoded)
"""

JS = b"""const raw = "aW1wb3J0IG9z";
function boot() {
  const decoded = Buffer.from(raw, 'base64').toString('utf8');
  new Function(decoded)();
}
"""

C = b"""#include <stdio.h>
#define HIDDEN(x) system(x)

int main(void) {
  char buf[8] = {1, 2, 3, 4};
  for (int i = 0; i < 8; i++) buf[i] ^= 0x42;
  return 0;
}
"""


@pytest.fixture
def registry():
    return ParserRegistry()


class TestParsing:
    @pytest.mark.parametrize("language,source", [("python", PY), ("javascript", JS), ("c", C)])
    def test_parses_each_supported_language(self, registry, language, source):
        parsed = registry.parse(Path(f"x.{language}"), source, language)
        assert parsed is not None
        assert parsed.root.child_count > 0
        assert not parsed.has_error

    def test_unknown_language_returns_none(self, registry):
        assert registry.parse(Path("x.cob"), b"IDENTIFICATION DIVISION.", "cobol") is None

    def test_syntactically_broken_source_still_parses(self, registry):
        """A parse failure must downgrade one file, never abort the scan."""
        parsed = registry.parse(Path("x.py"), b"def broken(:\n  ???\n", "python")
        assert parsed is not None
        assert parsed.has_error is True

    def test_typescript_reuses_the_javascript_queries(self, registry):
        parsed = registry.parse(Path("x.ts"), b'const a: string = "hi";\n', "typescript")
        assert parsed is not None
        assert len(parsed.captures("strings").get("string", [])) == 1

    def test_decodes_source_with_invalid_utf8_without_raising(self, registry):
        parsed = registry.parse(Path("x.py"), b'x = "\xff\xfe"\n', "python")
        assert parsed is not None


class TestCaptures:
    def test_finds_string_literals(self, registry):
        parsed = registry.parse(Path("x.py"), PY, "python")
        strings = parsed.captures("strings")["string"]
        assert [parsed.text(n) for n in strings] == ['"aGVsbG8="']

    def test_finds_calls_with_their_callee(self, registry):
        parsed = registry.parse(Path("x.py"), PY, "python")
        caps = parsed.captures("calls")
        assert {parsed.text(n) for n in caps["callee"]} == {"os.popen", "eval"}

    def test_finds_assignment_target_and_value_together(self, registry):
        parsed = registry.parse(Path("x.js"), JS, "javascript")
        pairs = [
            (parsed.text(m["target"][0]), parsed.text(m["value"][0]))
            for m in parsed.matches("assignments")
        ]
        assert ("raw", '"aW1wb3J0IG9z"') in pairs

    def test_finds_new_expressions_as_calls(self, registry):
        parsed = registry.parse(Path("x.js"), JS, "javascript")
        assert "Function" in {parsed.text(n) for n in parsed.captures("calls")["callee"]}

    def test_finds_c_macro_definitions(self, registry):
        parsed = registry.parse(Path("x.c"), C, "c")
        names = [parsed.text(n) for n in parsed.captures("macros")["name"]]
        assert names == ["HIDDEN"]

    def test_finds_bitwise_operators(self, registry):
        parsed = registry.parse(Path("x.c"), C, "c")
        ops = {parsed.text(n) for n in parsed.captures("bitwise")["operator"]}
        assert "^=" in ops

    def test_missing_capture_name_yields_empty_list_not_keyerror(self, registry):
        parsed = registry.parse(Path("x.py"), b"pass\n", "python")
        assert parsed.captures("strings").get("string", []) == []

    def test_a_query_kind_absent_for_a_language_is_empty_not_an_error(self, registry):
        """Only C has macros; asking Python for them is a no-op."""
        parsed = registry.parse(Path("x.py"), PY, "python")
        assert parsed.captures("macros") == {}

    def test_unknown_query_kind_is_rejected_loudly(self, registry):
        parsed = registry.parse(Path("x.py"), PY, "python")
        with pytest.raises(KeyError, match="unknown query kind"):
            parsed.captures("nonsense")


class TestNodeHelpers:
    def test_line_numbers_are_one_indexed(self, registry):
        parsed = registry.parse(Path("x.py"), PY, "python")
        node = parsed.captures("strings")["string"][0]
        assert parsed.line_of(node) == 3

    def test_location_carries_the_source_line_as_a_snippet(self, registry):
        parsed = registry.parse(Path("x.py"), PY, "python")
        loc = parsed.location(parsed.captures("strings")["string"][0])
        assert loc.line == 3
        assert loc.snippet == 'SECRET = "aGVsbG8="'

    def test_enclosing_function_is_reported_for_scoping(self, registry):
        parsed = registry.parse(Path("x.py"), PY, "python")
        eval_call = next(n for n in parsed.captures("calls")["callee"] if parsed.text(n) == "eval")
        fn = parsed.enclosing_function(eval_call)
        assert fn is not None and parsed.text(fn["name"][0]) == "run"

    def test_enclosing_function_is_none_at_module_level(self, registry):
        parsed = registry.parse(Path("x.py"), PY, "python")
        assert parsed.enclosing_function(parsed.captures("strings")["string"][0]) is None


class TestQueryCoverage:
    @pytest.mark.parametrize("language", ["python", "javascript", "c"])
    def test_every_core_query_kind_compiles_for_every_language(self, registry, language):
        """A malformed .scm must fail here, not silently return nothing at scan time."""
        parsed = registry.parse(Path("f"), b"", language)
        for kind in QUERY_KINDS:
            parsed.captures(kind)
