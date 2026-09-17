"""Tests for intra-procedural data flow.

Scope is deliberately narrow: local variables, one file, one function body. That
is enough to trace the PRD's own FOR-001 example, and the limit is documented
rather than implied away.
"""

from pathlib import Path

import pytest

from forensic_scan.engine.dataflow import DataFlowAnalyzer
from forensic_scan.parser.registry import ParserRegistry


@pytest.fixture
def registry():
    return ParserRegistry()


def _analyze(registry, source: bytes, language: str, suffix: str):
    parsed = registry.parse(Path(f"x{suffix}"), source, language)
    return parsed, DataFlowAnalyzer(parsed)


def _callee(parsed, name: str):
    return next(n for n in parsed.captures("calls")["callee"] if parsed.text(n) == name)


def _call_of(parsed, name: str):
    node = _callee(parsed, name)
    return node.parent


class TestPythonFlow:
    SOURCE = b"""import base64

BLOB = "TG9uZyBiYXNlNjQgcGF5bG9hZCB0aGF0IGlzIGRlZmluaXRlbHkgbG9uZyBlbm91Z2g="

def launch():
    raw = base64.b64decode(BLOB)
    exec(raw)
"""

    def test_traces_a_literal_through_a_decoder_into_exec(self, registry):
        parsed, flow = _analyze(registry, self.SOURCE, "python", ".py")
        paths = flow.paths_into(_call_of(parsed, "exec"))
        assert len(paths) == 1
        assert paths[0].source_profile.looks_encoded

    def test_the_trace_is_ordered_source_first(self, registry):
        parsed, flow = _analyze(registry, self.SOURCE, "python", ".py")
        lines = [step.location.line for step in flow.paths_into(_call_of(parsed, "exec"))[0].steps]
        assert lines == sorted(lines)

    def test_the_trace_names_each_hop(self, registry):
        parsed, flow = _analyze(registry, self.SOURCE, "python", ".py")
        steps = flow.paths_into(_call_of(parsed, "exec"))[0].steps
        assert "literal" in steps[0].description.lower()
        assert steps[-1].location.line == 7

    def test_a_direct_literal_argument_is_traced(self, registry):
        src = b'exec("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")\n'
        parsed, flow = _analyze(registry, src, "python", ".py")
        assert len(flow.paths_into(_call_of(parsed, "exec"))) == 1

    def test_a_call_with_no_literal_reachable_yields_nothing(self, registry):
        src = b"import sys\nexec(sys.argv[1])\n"
        parsed, flow = _analyze(registry, src, "python", ".py")
        assert flow.paths_into(_call_of(parsed, "exec")) == []

    def test_reassignment_resolves_to_the_definition_above_the_use(self, registry):
        src = (
            b'x = "first-value-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\n'
            b'x = "second-value-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"\n'
            b"exec(x)\n"
        )
        parsed, flow = _analyze(registry, src, "python", ".py")
        (path,) = flow.paths_into(_call_of(parsed, "exec"))
        assert "second-value" in path.source_profile.text


class TestJavaScriptFlow:
    SOURCE = b"""const raw = "aW1wb3J0IG9zOyBvcy5zeXN0ZW0oJ2VjaG8gcHduZWQnKTsgcGF5bG9hZA==";
function boot() {
  const decoded = Buffer.from(raw, 'base64').toString('utf8');
  new Function(decoded)();
}
"""

    def test_traces_the_prd_postinstall_example_end_to_end(self, registry):
        parsed, flow = _analyze(registry, self.SOURCE, "javascript", ".js")
        paths = flow.paths_into(_call_of(parsed, "Function"))
        assert len(paths) == 1
        assert paths[0].source_profile.looks_encoded

    def test_the_trace_records_all_three_hops(self, registry):
        parsed, flow = _analyze(registry, self.SOURCE, "javascript", ".js")
        (path,) = flow.paths_into(_call_of(parsed, "Function"))
        assert [s.location.line for s in path.steps] == [1, 3, 4]

    def test_template_literals_are_traced(self, registry):
        src = b"const a = `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`;\neval(a);\n"
        parsed, flow = _analyze(registry, src, "javascript", ".js")
        assert len(flow.paths_into(_call_of(parsed, "eval"))) == 1


class TestCFlow:
    def test_traces_a_string_through_a_local_into_system(self, registry):
        src = b"""int main(void) {
  const char *cmd = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  system(cmd);
}
"""
        parsed, flow = _analyze(registry, src, "c", ".c")
        assert len(flow.paths_into(_call_of(parsed, "system"))) == 1


class TestScopeAndLimits:
    def test_does_not_cross_function_boundaries(self, registry):
        """A documented v1 limit: locals in another function are not resolved."""
        src = b"""def maker():
    secret = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

def user(secret):
    exec(secret)
"""
        parsed, flow = _analyze(registry, src, "python", ".py")
        assert flow.paths_into(_call_of(parsed, "exec")) == []

    def test_module_level_names_are_visible_inside_functions(self, registry):
        src = b"""BLOB = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

def run():
    exec(BLOB)
"""
        parsed, flow = _analyze(registry, src, "python", ".py")
        assert len(flow.paths_into(_call_of(parsed, "exec"))) == 1

    def test_a_local_shadows_a_module_level_name(self, registry):
        src = b"""BLOB = "module-level-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

def run():
    BLOB = "local-value-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    exec(BLOB)
"""
        parsed, flow = _analyze(registry, src, "python", ".py")
        (path,) = flow.paths_into(_call_of(parsed, "exec"))
        assert "local-value" in path.source_profile.text

    def test_self_referential_assignment_terminates(self, registry):
        src = b"x = x\nexec(x)\n"
        parsed, flow = _analyze(registry, src, "python", ".py")
        assert flow.paths_into(_call_of(parsed, "exec")) == []

    def test_mutually_referential_assignments_terminate(self, registry):
        src = b"a = b\nb = a\nexec(a)\n"
        parsed, flow = _analyze(registry, src, "python", ".py")
        assert flow.paths_into(_call_of(parsed, "exec")) == []

    def test_a_long_chain_stops_at_the_depth_limit(self, registry):
        chain = b'v0 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\n'
        chain += b"".join(f"v{i} = v{i - 1}\n".encode() for i in range(1, 40))
        chain += b"exec(v39)\n"
        parsed, flow = _analyze(registry, chain, "python", ".py")
        assert flow.paths_into(_call_of(parsed, "exec")) == []

    def test_a_chain_within_the_depth_limit_resolves(self, registry):
        chain = b'v0 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\n'
        chain += b"".join(f"v{i} = v{i - 1}\n".encode() for i in range(1, 4))
        chain += b"exec(v3)\n"
        parsed, flow = _analyze(registry, chain, "python", ".py")
        assert len(flow.paths_into(_call_of(parsed, "exec"))) == 1


class TestSourceFiltering:
    def test_encoding_argument_literals_are_not_reported_as_sources(self, registry):
        """`Buffer.from(raw, 'base64')` puts 'base64' on the path to the sink.
        Reporting it would bury the payload it decodes."""
        src = (
            b'const raw = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";\n'
            b"const decoded = Buffer.from(raw, 'base64').toString('utf8');\n"
            b"eval(decoded);\n"
        )
        parsed, flow = _analyze(registry, src, "javascript", ".js")
        paths = flow.paths_into(_call_of(parsed, "eval"))
        assert [p.source_profile.text for p in paths] == ["a" * 52]

    def test_the_length_floor_can_be_lowered_by_a_caller(self, registry):
        src = b'const a = "short";\neval(a);\n'
        parsed, flow = _analyze(registry, src, "javascript", ".js")
        assert flow.paths_into(_call_of(parsed, "eval")) == []
        assert len(flow.paths_into(_call_of(parsed, "eval"), min_source_length=1)) == 1


class TestDecoderAnnotation:
    def test_a_decoder_hop_is_labelled_as_such(self, registry):
        src = (
            b"import base64\n"
            b'B = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\n'
            b"exec(base64.b64decode(B))\n"
        )
        parsed, flow = _analyze(registry, src, "python", ".py")
        (path,) = flow.paths_into(_call_of(parsed, "exec"))
        assert any("decode" in s.description.lower() for s in path.steps)

    def test_paths_report_whether_a_decoder_was_involved(self, registry):
        src = (
            b"import base64\n"
            b'B = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\n'
            b"exec(base64.b64decode(B))\n"
        )
        parsed, flow = _analyze(registry, src, "python", ".py")
        assert flow.paths_into(_call_of(parsed, "exec"))[0].through_decoder is True

    def test_a_direct_flow_reports_no_decoder(self, registry):
        src = b'x = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\nexec(x)\n'
        parsed, flow = _analyze(registry, src, "python", ".py")
        assert flow.paths_into(_call_of(parsed, "exec"))[0].through_decoder is False
