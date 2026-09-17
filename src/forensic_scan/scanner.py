"""The scan pipeline.

Selection -> classification -> engines -> correlation -> rules -> scoring.

The ordering matters in one non-obvious place: correlation runs *after* every
engine has finished, because the whole point of it is to join signals that
different engines produced about different files. An engine that could see the
answer on its own would not need it.
"""

from __future__ import annotations

import os
import time
from collections.abc import Iterator
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

from .discovery.classify import ClassifiedFile, FileRole, classify_file
from .discovery.walker import (
    DEFAULT_MAX_FILE_SIZE,
    SkippedFile,
    WalkResult,
    changed_files,
    walk,
)
from .engine.binary_assets import BinaryAssetEngine
from .engine.build_inspector import BuildInspector
from .engine.linkage import LinkageEngine, SignalStore
from .engine.obfuscation import ObfuscationEngine
from .models import Finding, Severity, Signal
from .parser.registry import ParserRegistry
from .rules.evaluator import RuleEvaluator
from .rules.schema import RuleSet, load_builtin_rules
from .scoring.baseline import Baseline
from .scoring.score import RiskScore, score_findings
from .scoring.suppress import SuppressionReason, Suppressor

MAX_SOURCE_BYTES = 8 * 1024 * 1024
"""Source files larger than this are treated as assets, not parsed. A source
file this size is generated or packed, and parsing it costs more than it tells."""

PARALLEL_THRESHOLD = 64
"""Below this many files, process startup costs more than it saves.

Diff mode usually lands here, which is the point: a pull-request scan should not
pay to spin up a worker pool to look at three files."""

DEFAULT_JOBS = min(os.cpu_count() or 1, 8)


@dataclass
class FileAnalysis:
    """One file's contribution to a scan.

    The suppression verdict is computed here rather than in the main process so
    that file contents never have to travel anywhere -- not across a process
    boundary, and not into a dictionary held for the length of the scan. A
    previous version kept every source file's bytes in memory until the end.
    """

    signals: list[Signal] = field(default_factory=list)
    suppression: SuppressionReason | None = None
    parsed: bool = False
    error: str | None = None


@dataclass
class ScanConfig:
    root: Path
    diff_ref: str | None = None
    excludes: list[str] = field(default_factory=list)
    include_vendored: bool = False
    respect_gitignore: bool = True
    max_file_size: int = DEFAULT_MAX_FILE_SIZE
    ruleset: RuleSet | None = None
    baseline_path: Path | None = None
    suppress: bool = True
    suppress_paths: list[str] = field(default_factory=list)
    fail_on: Severity | None = Severity.HIGH
    jobs: int | None = None
    """Worker processes. ``None`` picks a default; ``1`` forces sequential."""


@dataclass
class ScanResult:
    root: Path
    findings: list[Finding] = field(default_factory=list)
    suppressed: list[Finding] = field(default_factory=list)
    baselined: list[Finding] = field(default_factory=list)
    files_analyzed: int = 0
    files_parsed: int = 0
    skipped: list[SkippedFile] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    duration_seconds: float = 0.0
    score: RiskScore = field(default_factory=lambda: RiskScore(0, "CLEAN", {}))
    diff_ref: str | None = None
    unavailable_languages: dict[str, str] = field(default_factory=dict)
    """Languages whose grammar could not be loaded, and why.

    Non-empty means the scan is incomplete and its "no findings" is worthless
    for those files. Callers must treat it as a failure, not a clean result."""
    files_unanalyzed: int = 0
    """Source files skipped because their grammar was unavailable."""


class Scanner:
    def __init__(self, registry: ParserRegistry | None = None) -> None:
        self.registry = registry or ParserRegistry()
        self.obfuscation = ObfuscationEngine(self.registry)
        self.binary_assets = BinaryAssetEngine()
        self.build = BuildInspector(self.registry)
        self.linkage = LinkageEngine()

    def scan(self, config: ScanConfig) -> ScanResult:
        started = time.monotonic()
        root = config.root.resolve()
        result = ScanResult(root=root, diff_ref=config.diff_ref)

        files, walk_result = self._select(root, config, result)
        result.skipped = walk_result.skipped
        self._preflight_grammars(files, result)

        store = SignalStore(root=root)
        languages: dict[Path, str | None] = {}
        suppressed_paths: dict[Path, SuppressionReason] = {}

        for classified, analysis in self._analyze_all(files, config, root):
            languages[classified.path] = classified.language
            if analysis.error:
                result.errors.append(analysis.error)
                continue
            if analysis.suppression is not None:
                suppressed_paths[classified.path] = analysis.suppression
            if analysis.parsed:
                result.files_parsed += 1
            store.add(analysis.signals)
            result.files_analyzed += 1

        ruleset = config.ruleset or load_builtin_rules()
        findings = self.linkage.correlate(store)
        findings.extend(RuleEvaluator(ruleset).evaluate(store, languages))
        findings = _deduplicate(findings)
        findings, result.suppressed = _apply_suppression(findings, suppressed_paths)

        if config.baseline_path is not None:
            baseline = Baseline.load(config.baseline_path)
            findings, result.baselined = baseline.partition(findings)

        findings.sort(key=lambda f: (-f.severity.value, str(f.location), f.rule_id))
        result.findings = findings
        result.score = score_findings(findings)
        result.duration_seconds = time.monotonic() - started
        return result

    def _preflight_grammars(self, files: list[ClassifiedFile], result: ScanResult) -> None:
        """Load every grammar the scan needs, before analysing anything.

        Grammars are fetched on first use and cached. If that fetch fails --
        offline CI, a blocked proxy, an unwarmed container -- every source file
        would otherwise parse to nothing and the scan would report a clean
        result it never established. Checking up front turns a silent blind spot
        into a loud error.
        """
        needed = sorted({c.language for c in files if c.language})
        for language in needed:
            if self.registry.ensure(language):
                continue
            reason = self.registry.grammar_errors.get(language, "unknown error")
            affected = sum(1 for c in files if c.language == language)
            result.unavailable_languages[language] = reason
            result.files_unanalyzed += affected
            result.errors.append(
                f"grammar for {language!r} could not be loaded ({reason}); "
                f"{affected} file(s) were NOT analysed. Run 'forensic-scan prefetch' "
                f"while online, or use the container image, which ships them."
            )

    # -- selection ---------------------------------------------------------

    def _select(
        self, root: Path, config: ScanConfig, result: ScanResult
    ) -> tuple[list[ClassifiedFile], WalkResult]:
        if config.diff_ref is None:
            walk_result = walk(
                root,
                max_file_size=config.max_file_size,
                excludes=config.excludes,
                respect_gitignore=config.respect_gitignore,
                include_vendored=config.include_vendored,
            )
            return walk_result.files, walk_result

        changed = changed_files(root, config.diff_ref)
        walk_result = WalkResult(root=root)
        selected: list[ClassifiedFile] = []
        for path in changed:
            try:
                if path.stat().st_size > config.max_file_size:
                    continue
                selected.append(classify_file(path))
            except OSError as exc:
                result.errors.append(f"{path}: {exc}")
        return selected, walk_result

    # -- per-file analysis -------------------------------------------------

    def _analyze_all(
        self, files: list[ClassifiedFile], config: ScanConfig, root: Path
    ) -> Iterator[tuple[ClassifiedFile, FileAnalysis]]:
        """Analyse every file, in parallel when there are enough to be worth it."""
        jobs = config.jobs if config.jobs is not None else DEFAULT_JOBS
        suppressor_args = (root, config.suppress, tuple(config.suppress_paths))

        if jobs <= 1 or len(files) < PARALLEL_THRESHOLD:
            analyzer = _FileAnalyzer(*suppressor_args, registry=self.registry)
            for classified in files:
                yield classified, analyzer.analyze(classified)
            return

        try:
            with ProcessPoolExecutor(
                max_workers=jobs, initializer=_init_worker, initargs=suppressor_args
            ) as pool:
                chunk = max(1, min(64, len(files) // (jobs * 4) or 1))
                results = pool.map(_analyze_in_worker, files, chunksize=chunk)
                yield from zip(files, results, strict=False)
        except (OSError, RuntimeError, ImportError):
            # Sandboxes and some CI images forbid process creation. Falling back
            # is slower but correct, which beats failing the scan.
            analyzer = _FileAnalyzer(*suppressor_args, registry=self.registry)
            for classified in files:
                yield classified, analyzer.analyze(classified)


class _FileAnalyzer:
    """Runs every engine over one file. Safe to construct per worker process."""

    def __init__(
        self,
        root: Path,
        suppress: bool,
        suppress_paths: tuple[str, ...],
        registry: ParserRegistry | None = None,
    ) -> None:
        self.registry = registry or ParserRegistry()
        self.obfuscation = ObfuscationEngine(self.registry)
        self.binary_assets = BinaryAssetEngine()
        self.build = BuildInspector(self.registry)
        self.suppressor = Suppressor(root=root, enabled=suppress, extra_paths=list(suppress_paths))

    def analyze(self, classified: ClassifiedFile) -> FileAnalysis:
        try:
            return self._analyze(classified)
        except Exception as exc:  # one bad file must never end a scan
            return FileAnalysis(error=f"{classified.path}: {type(exc).__name__}: {exc}")

    def _analyze(self, classified: ClassifiedFile) -> FileAnalysis:
        signals: list[Signal] = []
        content: bytes | None = None
        parsed = False

        if classified.role is FileRole.SOURCE and classified.size <= MAX_SOURCE_BYTES:
            content = _read(classified.path)
            if content is not None and classified.language:
                signals.extend(
                    self.obfuscation.analyze(classified.path, content, classified.language)
                )
                parsed = True

        if classified.is_build:
            if content is None:
                content = _read(classified.path)
            if content is not None:
                signals.extend(self.build.analyze(classified, content))

        if classified.role is not FileRole.SOURCE:
            signals.extend(self.binary_assets.analyze(classified))
            if content is None and not classified.is_binary:
                content = _read(classified.path)

        return FileAnalysis(
            signals=signals,
            suppression=self.suppressor.reason_for(classified.path, content),
            parsed=parsed,
        )


_WORKER: _FileAnalyzer | None = None


def _init_worker(root: Path, suppress: bool, suppress_paths: tuple[str, ...]) -> None:
    global _WORKER
    _WORKER = _FileAnalyzer(root, suppress, suppress_paths)


def _analyze_in_worker(classified: ClassifiedFile) -> FileAnalysis:
    assert _WORKER is not None  # set by the pool initializer
    return _WORKER.analyze(classified)


def _apply_suppression(
    findings: list[Finding], suppressed_paths: dict[Path, SuppressionReason]
) -> tuple[list[Finding], list[Finding]]:
    reported: list[Finding] = []
    suppressed: list[Finding] = []
    for finding in findings:
        reason = suppressed_paths.get(finding.location.path)
        if reason is None:
            reported.append(finding)
        else:
            finding.metadata["suppressed_by"] = reason.value
            suppressed.append(finding)
    return reported, suppressed


def _read(path: Path) -> bytes | None:
    try:
        return path.read_bytes()
    except OSError:
        return None


def _deduplicate(findings: list[Finding]) -> list[Finding]:
    """Collapse findings that would show a reviewer the same thing twice.

    Several rules can legitimately match one signal -- FOR-001 and FOR-004 both
    describe a payload reaching a sink. The most severe wins; reporting both
    would double-count in the risk score and waste the reader's attention.
    """
    best: dict[tuple[str, int | None, str], Finding] = {}
    for finding in findings:
        key = (
            finding.location.path.as_posix(),
            finding.location.line,
            finding.signals[0].kind.value if finding.signals else finding.rule_id,
        )
        existing = best.get(key)
        if existing is None or finding.severity > existing.severity:
            best[key] = finding
    return list(best.values())
