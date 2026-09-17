"""Tests for the correlation engine -- the XZ Utils detector.

No single signal here is damning. A build script naming a file is ordinary. An
opaque test fixture is ordinary. An XOR loop is ordinary. The *chain* joining
them is not, and finding that chain is the reason this tool exists.
"""

from pathlib import Path

import pytest

from forensic_scan.engine.linkage import LinkageEngine, SignalStore
from forensic_scan.models import Location, Severity, Signal, SignalKind

ROOT = Path("/repo")


def _sig(kind, in_file, line=1, **metadata):
    """A signal located in `in_file`; keyword args become signal metadata.

    Note `in_file` (where the signal was observed) is distinct from a `path`
    metadata key (which file the signal *names*) -- the linkage engine joins
    one to the other.
    """
    return Signal(
        kind=kind,
        location=Location(path=ROOT / in_file, line=line),
        metadata={k: str(v) for k, v in metadata.items()},
    )


@pytest.fixture
def engine():
    return LinkageEngine()


def _store(*signals):
    store = SignalStore(root=ROOT)
    store.add(list(signals))
    return store


class TestTheFullChain:
    """The XZ shape: configure script -> opaque fixture -> transform -> execution."""

    def _full_chain(self):
        return _store(
            _sig(
                SignalKind.BUILD_FILE_REFERENCE,
                "m4/build-to-host.m4",
                3,
                path="tests/files/bad-3-corrupt_lzma2.xz",
                phase="configure",
            ),
            _sig(SignalKind.OPAQUE_ASSET, "tests/files/bad-3-corrupt_lzma2.xz"),
            _sig(
                SignalKind.FILE_READ,
                "src/liblzma/loader.c",
                82,
                path="tests/files/bad-3-corrupt_lzma2.xz",
                function="fopen",
            ),
            _sig(SignalKind.BITWISE_DECODE_LOOP, "src/liblzma/loader.c", 86, operator="^="),
            _sig(SignalKind.DYNAMIC_EXEC_SINK, "src/liblzma/loader.c", 92, sink="dlopen"),
        )

    def test_the_complete_chain_is_critical(self, engine):
        findings = engine.correlate(self._full_chain())
        assert len(findings) == 1
        assert findings[0].severity is Severity.CRITICAL

    def test_the_finding_points_at_the_asset(self, engine):
        (finding,) = engine.correlate(self._full_chain())
        assert finding.location.path.name == "bad-3-corrupt_lzma2.xz"

    def test_the_trace_shows_every_link_in_order(self, engine):
        (finding,) = engine.correlate(self._full_chain())
        descriptions = " | ".join(step.description for step in finding.trace)
        assert "build" in descriptions.lower()
        assert "read" in descriptions.lower()
        assert "transform" in descriptions.lower()
        assert "execut" in descriptions.lower()

    def test_the_finding_records_which_links_held(self, engine):
        (finding,) = engine.correlate(self._full_chain())
        assert finding.metadata["links"] == 4

    def test_the_finding_carries_its_supporting_signals(self, engine):
        (finding,) = engine.correlate(self._full_chain())
        assert len(finding.signals) >= 4

    def test_the_finding_uses_the_linkage_rule_id(self, engine):
        (finding,) = engine.correlate(self._full_chain())
        assert finding.rule_id == "FOR-010"


class TestPartialChains:
    def test_three_of_four_links_is_still_critical(self, engine):
        """No execution sink found, but a build script feeds a decoder an
        anomalous fixture. That is enough to stop a merge."""
        store = _store(
            _sig(SignalKind.BUILD_FILE_REFERENCE, "Makefile", 4, path="tests/blob.dat"),
            _sig(SignalKind.MAGIC_MISMATCH, "tests/blob.dat", declared="dat", detected="elf"),
            _sig(SignalKind.FILE_READ, "tests/harness.c", 10, path="tests/blob.dat"),
            _sig(SignalKind.BITWISE_DECODE_LOOP, "tests/harness.c", 12, operator="^="),
        )
        (finding,) = engine.correlate(store)
        assert finding.severity is Severity.CRITICAL

    def test_two_links_is_high_not_critical(self, engine):
        store = _store(
            _sig(SignalKind.BUILD_FILE_REFERENCE, "Makefile", 4, path="tests/blob.dat"),
            _sig(SignalKind.OPAQUE_ASSET, "tests/blob.dat"),
        )
        (finding,) = engine.correlate(store)
        assert finding.severity is Severity.HIGH

    def test_an_anomalous_asset_nobody_touches_produces_no_linkage_finding(self, engine):
        """One lonely signal is a job for a plain rule, not the correlator."""
        assert engine.correlate(_store(_sig(SignalKind.OPAQUE_ASSET, "tests/blob.dat"))) == []

    def test_a_build_reference_to_an_unremarkable_file_is_ignored(self, engine):
        store = _store(
            _sig(SignalKind.BUILD_FILE_REFERENCE, "Makefile", 2, path="src/main.c"),
            _sig(SignalKind.FILE_READ, "src/app.c", 5, path="src/main.c"),
        )
        assert engine.correlate(store) == []

    def test_a_transform_without_a_read_of_the_asset_does_not_link(self, engine):
        store = _store(
            _sig(SignalKind.OPAQUE_ASSET, "tests/blob.dat"),
            _sig(SignalKind.BITWISE_DECODE_LOOP, "src/unrelated.c", 3, operator="^="),
        )
        assert engine.correlate(store) == []


class TestPathResolution:
    def _chain_with_reference(self, reference: str, asset: str):
        return _store(
            _sig(SignalKind.BUILD_FILE_REFERENCE, "Makefile", 2, path=reference),
            _sig(SignalKind.OPAQUE_ASSET, asset),
        )

    @pytest.mark.parametrize(
        "reference",
        [
            "tests/fixtures/blob.dat",
            "./tests/fixtures/blob.dat",
            "$srcdir/tests/fixtures/blob.dat",
            "${CMAKE_SOURCE_DIR}/tests/fixtures/blob.dat",
            "$(TOP)/tests/fixtures/blob.dat",
        ],
    )
    def test_resolves_references_through_build_variables(self, engine, reference):
        store = self._chain_with_reference(reference, "tests/fixtures/blob.dat")
        assert len(engine.correlate(store)) == 1

    def test_resolves_a_bare_basename_reference(self, engine):
        store = self._chain_with_reference("blob.dat", "tests/fixtures/blob.dat")
        assert len(engine.correlate(store)) == 1

    def test_a_basename_match_is_marked_as_lower_confidence(self, engine):
        store = self._chain_with_reference("blob.dat", "tests/fixtures/blob.dat")
        (finding,) = engine.correlate(store)
        assert finding.signals[0].confidence < 1.0

    def test_does_not_match_a_merely_similar_name(self, engine):
        store = self._chain_with_reference("other.dat", "tests/fixtures/blob.dat")
        assert engine.correlate(store) == []

    def test_a_partial_path_suffix_resolves(self, engine):
        store = self._chain_with_reference("fixtures/blob.dat", "tests/fixtures/blob.dat")
        assert len(engine.correlate(store)) == 1


class TestMultipleAssets:
    def test_each_anomalous_asset_gets_its_own_finding(self, engine):
        store = _store(
            _sig(SignalKind.BUILD_FILE_REFERENCE, "Makefile", 2, path="tests/a.dat"),
            _sig(SignalKind.OPAQUE_ASSET, "tests/a.dat"),
            _sig(SignalKind.BUILD_FILE_REFERENCE, "Makefile", 3, path="tests/b.dat"),
            _sig(SignalKind.MAGIC_MISMATCH, "tests/b.dat", declared="dat", detected="elf"),
        )
        assert len({f.location.path for f in engine.correlate(store)}) == 2

    def test_findings_are_ordered_most_severe_first(self, engine):
        store = _store(
            _sig(SignalKind.BUILD_FILE_REFERENCE, "Makefile", 2, path="tests/weak.dat"),
            _sig(SignalKind.OPAQUE_ASSET, "tests/weak.dat"),
            _sig(SignalKind.BUILD_FILE_REFERENCE, "Makefile", 3, path="tests/strong.dat"),
            _sig(SignalKind.OPAQUE_ASSET, "tests/strong.dat"),
            _sig(SignalKind.FILE_READ, "t.c", 1, path="tests/strong.dat"),
            _sig(SignalKind.DECODE_CALL, "t.c", 2, sink="atob"),
            _sig(SignalKind.DYNAMIC_EXEC_SINK, "t.c", 3, sink="system"),
        )
        findings = engine.correlate(store)
        assert findings[0].severity >= findings[-1].severity
        assert findings[0].location.path.name == "strong.dat"

    def test_one_asset_produces_one_finding_despite_many_references(self, engine):
        store = _store(
            _sig(SignalKind.BUILD_FILE_REFERENCE, "Makefile", 2, path="tests/a.dat"),
            _sig(SignalKind.BUILD_FILE_REFERENCE, "setup.py", 9, path="tests/a.dat"),
            _sig(SignalKind.BUILD_FILE_REFERENCE, "CMakeLists.txt", 4, path="tests/a.dat"),
            _sig(SignalKind.OPAQUE_ASSET, "tests/a.dat"),
        )
        assert len(engine.correlate(store)) == 1


class TestSignalStore:
    def test_groups_signals_by_file(self):
        store = _store(
            _sig(SignalKind.DYNAMIC_EXEC_SINK, "a.py", 1, sink="eval"),
            _sig(SignalKind.DECODE_CALL, "a.py", 2, sink="b64decode"),
            _sig(SignalKind.OPAQUE_ASSET, "b.dat"),
        )
        assert len(store.in_file(ROOT / "a.py")) == 2

    def test_selects_by_kind(self):
        store = _store(
            _sig(SignalKind.DYNAMIC_EXEC_SINK, "a.py", 1, sink="eval"),
            _sig(SignalKind.OPAQUE_ASSET, "b.dat"),
        )
        assert len(store.of_kind(SignalKind.OPAQUE_ASSET)) == 1

    def test_selects_by_several_kinds_at_once(self):
        store = _store(
            _sig(SignalKind.DYNAMIC_EXEC_SINK, "a.py", 1, sink="eval"),
            _sig(SignalKind.DECODE_CALL, "a.py", 2, sink="b64decode"),
            _sig(SignalKind.OPAQUE_ASSET, "b.dat"),
        )
        selected = store.of_kinds({SignalKind.DYNAMIC_EXEC_SINK, SignalKind.DECODE_CALL})
        assert len(selected) == 2

    def test_an_empty_store_correlates_to_nothing(self, engine):
        assert engine.correlate(SignalStore(root=ROOT)) == []
