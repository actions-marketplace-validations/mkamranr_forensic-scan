"""The correlation engine -- what this scanner is actually for.

The PRD leads with entropy analysis. But the attack it names as the motivating
example would have walked past an entropy scanner: the XZ Utils backdoor put no
suspicious strings in any source file. It worked like this:

1. ``build-to-host.m4`` -- a file nobody reads -- named a test fixture.
2. The fixture, ``bad-3-corrupt_lzma2.xz``, was a "corrupt" archive in a
   directory full of deliberately corrupt archives.
3. A byte substitution turned it into a shell script.
4. That script patched the build and produced a backdoored binary.

Every step is individually unremarkable. Build scripts name files. Test suites
contain broken fixtures. Code applies byte transformations. What is *not*
unremarkable is all four happening to the same file, and that is a graph query,
not a pattern match.

So this engine consumes every signal the other engines produced and looks for
the join. Four links:

``A`` a build or install script names the asset
``B`` the asset is anomalous (opaque, mismatched, or carrying hidden content)
``C`` code reads the asset and transforms the bytes
``D`` the transformed result reaches an execution sink

``B`` is required -- without it there is no asset worth tracing. Two links raise
HIGH, three or more raise CRITICAL. One link alone is left to the ordinary
rules, since "there is an opaque file in tests/" is a description of most
repositories rather than a finding.

This is the one detector that cannot be written in the YAML rule schema, which
expresses predicates over individual signals rather than joins across them.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from ..models import Finding, Location, Severity, Signal, SignalKind, TraceStep
from .signatures import EXECUTION_KINDS, TRANSFORM_KINDS

LINKAGE_RULE_ID = "FOR-010"

ASSET_ANOMALY_KINDS = frozenset(
    {
        SignalKind.OPAQUE_ASSET,
        SignalKind.MAGIC_MISMATCH,
        SignalKind.EMBEDDED_ARCHIVE,
        SignalKind.EXECUTABLE_HEADER,
        SignalKind.TRAILING_DATA,
    }
)

CRITICAL_LINK_COUNT = 3
MINIMUM_LINK_COUNT = 2

BASENAME_MATCH_CONFIDENCE = 0.6
"""A reference matched only by filename could be a different file of that name."""

# Build systems address files through variables: $srcdir, ${CMAKE_SOURCE_DIR},
# $(TOP). Stripping them is what lets a reference in a Makefile resolve to a
# path on disk.
_BUILD_VARIABLE_RE = re.compile(r"^(?:\$\{[^}]*\}|\$\([^)]*\)|\$\w+|\.)/+")


@dataclass
class SignalStore:
    """Every signal from every engine, indexed for the queries linkage makes."""

    root: Path
    signals: list[Signal] = field(default_factory=list)
    _by_kind: dict[SignalKind, list[Signal]] = field(default_factory=lambda: defaultdict(list))
    _by_file: dict[Path, list[Signal]] = field(default_factory=lambda: defaultdict(list))

    def add(self, signals: list[Signal]) -> None:
        for signal in signals:
            self.signals.append(signal)
            self._by_kind[signal.kind].append(signal)
            self._by_file[signal.location.path].append(signal)

    def of_kind(self, kind: SignalKind) -> list[Signal]:
        return list(self._by_kind.get(kind, ()))

    def of_kinds(self, kinds: frozenset[SignalKind] | set[SignalKind]) -> list[Signal]:
        return [s for kind in kinds for s in self._by_kind.get(kind, ())]

    def in_file(self, path: Path) -> list[Signal]:
        return list(self._by_file.get(path, ()))

    def files_with_kind(self, kinds: frozenset[SignalKind] | set[SignalKind]) -> set[Path]:
        return {s.location.path for s in self.of_kinds(kinds)}


@dataclass(frozen=True)
class _Reference:
    """A signal that names a file, resolved to an actual path."""

    signal: Signal
    target: Path
    confidence: float


class LinkageEngine:
    """Joins signals across files into chains no single engine can see."""

    def correlate(self, store: SignalStore) -> list[Finding]:
        anomalies = self._anomalies_by_asset(store)
        if not anomalies:
            return []

        known = set(anomalies)
        relative = _relative_paths(known, store.root)
        build_refs = self._resolve(store.of_kind(SignalKind.BUILD_FILE_REFERENCE), known, relative)
        reads = self._resolve(store.of_kind(SignalKind.FILE_READ), known, relative)

        findings = [
            finding
            for asset, asset_signals in sorted(anomalies.items())
            if (finding := self._chain_for(store, asset, asset_signals, build_refs, reads))
        ]
        findings.sort(key=lambda f: (-f.severity.value, -int(f.metadata["links"]), str(f.location)))
        return findings

    # -- chain construction ------------------------------------------------

    def _chain_for(
        self,
        store: SignalStore,
        asset: Path,
        asset_signals: list[Signal],
        build_refs: dict[Path, list[_Reference]],
        reads: dict[Path, list[_Reference]],
    ) -> Finding | None:
        supporting: list[Signal] = []
        trace: list[TraceStep] = []
        links = 0

        # Link A -- a build or install script names this asset.
        referencing = build_refs.get(asset, [])
        if referencing:
            links += 1
            best = max(referencing, key=lambda r: r.confidence)
            supporting.append(_with_confidence(best.signal, best.confidence))
            trace.append(
                TraceStep(
                    location=best.signal.location,
                    description=(
                        f"build script references this asset during the "
                        f"{best.signal.metadata.get('phase', 'build')} phase"
                    ),
                    snippet=best.signal.location.snippet,
                )
            )

        # Link B -- the asset itself is anomalous. Always true here.
        links += 1
        supporting.extend(asset_signals)
        trace.append(
            TraceStep(
                location=Location(path=asset),
                description=f"asset is anomalous: {_describe_anomalies(asset_signals)}",
            )
        )

        # Link C -- code reads the asset and transforms the bytes.
        reading = reads.get(asset, [])
        transformer: _Reference | None = None
        for reference in sorted(reading, key=lambda r: -r.confidence):
            readers_file = reference.signal.location.path
            transforms = [s for s in store.in_file(readers_file) if s.kind in TRANSFORM_KINDS]
            if transforms:
                transformer = reference
                links += 1
                supporting.append(_with_confidence(reference.signal, reference.confidence))
                supporting.append(transforms[0])
                trace.append(
                    TraceStep(
                        location=reference.signal.location,
                        description=(
                            f"read by {reference.signal.metadata.get('function', 'code')}, "
                            f"then transformed ({transforms[0].kind.value})"
                        ),
                        snippet=reference.signal.location.snippet,
                    )
                )
                break

        # Link D -- the same file reaches an execution sink.
        if transformer is not None:
            readers_file = transformer.signal.location.path
            sinks = [s for s in store.in_file(readers_file) if s.kind in EXECUTION_KINDS]
            if sinks:
                links += 1
                supporting.append(sinks[0])
                trace.append(
                    TraceStep(
                        location=sinks[0].location,
                        description=(
                            f"same file reaches execution sink "
                            f"{sinks[0].metadata.get('sink', '')}".strip()
                        ),
                        snippet=sinks[0].location.snippet,
                    )
                )

        if links < MINIMUM_LINK_COUNT:
            return None

        severity = Severity.CRITICAL if links >= CRITICAL_LINK_COUNT else Severity.HIGH
        return Finding(
            rule_id=LINKAGE_RULE_ID,
            name="Build-time payload extraction chain",
            severity=severity,
            location=Location(path=asset),
            detail=(
                f"{links} of 4 links of a payload-extraction chain hold for this asset: "
                f"{_describe_links(trace)}. Individually each step is ordinary; together "
                f"they describe the mechanism used by the XZ Utils backdoor."
            ),
            remediation=(
                "Establish what this asset contains and why the build reads it. If it is a "
                "test fixture, confirm the test that consumes it and that nothing executes "
                "the decoded result. Treat an unexplained chain as a compromised dependency."
            ),
            signals=supporting,
            trace=trace,
            metadata={"links": links, "asset": asset.as_posix()},
            fingerprint_extra=f"links={links}",
        )

    # -- indexing and resolution ------------------------------------------

    @staticmethod
    def _anomalies_by_asset(store: SignalStore) -> dict[Path, list[Signal]]:
        anomalies: dict[Path, list[Signal]] = defaultdict(list)
        for signal in store.of_kinds(ASSET_ANOMALY_KINDS):
            anomalies[signal.location.path].append(signal)
        return dict(anomalies)

    def _resolve(
        self,
        signals: list[Signal],
        known_assets: set[Path],
        relative: dict[Path, str],
    ) -> dict[Path, list[_Reference]]:
        """Map each path-naming signal onto an actual anomalous asset."""
        by_basename: dict[str, list[Path]] = defaultdict(list)
        for asset in known_assets:
            by_basename[asset.name].append(asset)

        resolved: dict[Path, list[_Reference]] = defaultdict(list)
        for signal in signals:
            raw = signal.metadata.get("path")
            if not raw:
                continue
            match = self._match_asset(raw, relative, by_basename)
            if match is not None:
                asset, confidence = match
                resolved[asset].append(_Reference(signal, asset, confidence))
        return dict(resolved)

    @staticmethod
    def _match_asset(
        raw: str, relative: dict[Path, str], by_basename: dict[str, list[Path]]
    ) -> tuple[Path, float] | None:
        """Resolve a written reference to an asset, with a confidence.

        A reference carrying a directory component (``tests/blob.dat``) can be
        matched as a path suffix and is trusted outright. A bare filename
        (``blob.dat``) can only be matched by name, and a repository may well
        contain two files so called -- hence the reduced confidence, which the
        scoring layer carries through to the finding.
        """
        normalized = _BUILD_VARIABLE_RE.sub("", raw.strip().strip("\"'`")).lstrip("/")
        if not normalized:
            return None

        if "/" in normalized:
            best: Path | None = None
            for asset, rel in relative.items():
                if rel != normalized and not rel.endswith("/" + normalized):
                    continue
                if best is None or len(rel) < len(relative[best]):
                    best = asset
            return (best, 1.0) if best is not None else None

        for asset, rel in relative.items():
            if rel == normalized:
                return asset, 1.0

        candidates = by_basename.get(normalized, [])
        if len(candidates) == 1:
            return candidates[0], BASENAME_MATCH_CONFIDENCE
        return None


def _relative_paths(assets: set[Path], root: Path) -> dict[Path, str]:
    """Each asset's path as written in the repository, for matching references."""
    relative: dict[Path, str] = {}
    for asset in assets:
        try:
            relative[asset] = asset.relative_to(root).as_posix()
        except ValueError:
            relative[asset] = asset.as_posix().lstrip("/")
    return relative


def _with_confidence(signal: Signal, confidence: float) -> Signal:
    if confidence >= 1.0:
        return signal
    return Signal(
        kind=signal.kind,
        location=signal.location,
        features=dict(signal.features),
        metadata=dict(signal.metadata),
        confidence=confidence,
    )


def _describe_anomalies(signals: list[Signal]) -> str:
    return ", ".join(sorted({s.kind.value.replace("_", " ") for s in signals}))


def _describe_links(trace: list[TraceStep]) -> str:
    return "; ".join(step.description for step in trace)
