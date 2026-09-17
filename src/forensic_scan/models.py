"""The shared vocabulary of the scanner.

Three types carry everything between components:

``Signal``
    A raw observation from one engine -- "this literal has entropy 5.84", "this
    call is ``eval``". Signals are cheap, numerous, and on their own mean
    nothing. Engines emit them; they are never shown to a user.

``Finding``
    A conclusion drawn from one or more signals by a rule. Findings are what a
    user sees and what a baseline suppresses.

``Location``
    Where either of the above lives.

Keeping signals and findings distinct is what lets entropy be a *feature* that
contributes to a conclusion rather than a rule that fires on its own -- the
design decision the rest of the scanner is built around.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

_WHITESPACE = re.compile(r"\s+")


class Severity(Enum):
    """Ordered severity. Comparison is by rank, display is by name."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, raw: str) -> Severity:
        try:
            return cls[raw.strip().upper()]
        except KeyError:
            valid = ", ".join(s.name for s in cls)
            raise ValueError(f"unknown severity {raw!r}; expected one of: {valid}") from None

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.value < other.value

    def __le__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.value <= other.value

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.value > other.value

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.value >= other.value

    def __str__(self) -> str:
        return self.name


class SignalKind(str, Enum):
    """Every observation an engine can make.

    Grouped by the engine that emits it. Adding a kind here is the first step in
    adding a detector.
    """

    # Engine A -- entropy
    HIGH_ENTROPY_STRING = "high_entropy_string"
    HIGH_ENTROPY_IDENTIFIERS = "high_entropy_identifiers"
    ENCODED_ALPHABET_STRING = "encoded_alphabet_string"

    # Engine B -- obfuscation and dynamic execution
    DYNAMIC_EXEC_SINK = "dynamic_exec_sink"
    DECODE_CALL = "decode_call"
    CHARCODE_CONSTRUCTION = "charcode_construction"
    BITWISE_DECODE_LOOP = "bitwise_decode_loop"
    DYNAMIC_IMPORT = "dynamic_import"
    DYNAMIC_SYMBOL_RESOLUTION = "dynamic_symbol_resolution"
    INLINE_ASSEMBLY = "inline_assembly"
    STRING_CONCAT_CHAIN = "string_concat_chain"

    # Engine C -- binary assets
    MAGIC_MISMATCH = "magic_mismatch"
    EXECUTABLE_HEADER = "executable_header"
    EMBEDDED_ARCHIVE = "embedded_archive"
    TRAILING_DATA = "trailing_data"
    OPAQUE_ASSET = "opaque_asset"

    # Engine D -- build scripts
    BUILD_SHELL_EXEC = "build_shell_exec"
    BUILD_NETWORK_ACCESS = "build_network_access"
    BUILD_DECOMPRESSION = "build_decompression"
    BUILD_FILE_REFERENCE = "build_file_reference"
    BUILD_MACRO_ANOMALY = "build_macro_anomaly"

    # Data flow
    TAINT_FLOW = "taint_flow"
    FILE_READ = "file_read"


@dataclass(frozen=True)
class Location:
    """A point or span in a file. Lines are 1-indexed; ``None`` means whole-file."""

    path: Path
    line: int | None = None
    end_line: int | None = None
    column: int | None = None
    byte_start: int | None = None
    byte_end: int | None = None
    snippet: str | None = None

    def __str__(self) -> str:
        return f"{self.path.as_posix()}:{self.line}" if self.line else self.path.as_posix()


@dataclass
class Signal:
    """One observation. Meaningless alone; correlated by rules and by linkage."""

    kind: SignalKind
    location: Location
    features: dict[str, float] = field(default_factory=dict)
    metadata: dict[str, str] = field(default_factory=dict)
    confidence: float = 1.0

    def feature(self, name: str, default: float = 0.0) -> float:
        return self.features.get(name, default)


@dataclass(frozen=True)
class TraceStep:
    """One hop in a taint path or a correlation chain, rendered in reports."""

    location: Location
    description: str
    snippet: str | None = None


@dataclass
class Finding:
    """A conclusion a user acts on."""

    rule_id: str
    name: str
    severity: Severity
    location: Location
    detail: str
    remediation: str = ""
    signals: list[Signal] = field(default_factory=list)
    trace: list[TraceStep] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    fingerprint_extra: str = ""

    @property
    def fingerprint(self) -> str:
        """A stable identity for baselining.

        Deliberately excludes the line number: an unrelated edit higher in the
        file must not silently un-suppress a finding the maintainer already
        accepted. Identity is the rule, the file, and the normalised code that
        triggered it.
        """
        snippet = _WHITESPACE.sub(" ", (self.location.snippet or "").strip())
        material = "|".join(
            [self.rule_id, self.location.path.as_posix(), snippet, self.fingerprint_extra]
        )
        return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]
