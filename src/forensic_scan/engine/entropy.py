"""Entropy measurement -- Module A of the PRD, deliberately demoted to a feature.

The PRD specifies fixed thresholds (``H > 5.2`` for strings). Two problems make
that unusable as a rule on real repositories:

*Short strings.* Shannon entropy over a 12-character string is dominated by the
sample size, not the content. ``"aB3xQ9"`` scores high and means nothing. Hence
``MIN_PAYLOAD_LENGTH``.

*Hex.* A hex-encoded blob draws from 16 symbols, so its entropy cannot exceed
4.0 bits/char no matter how random the underlying bytes. A 5.2 threshold misses
every hex payload ever written. Alphabet detection catches what entropy cannot.

So this module reports *numbers* -- entropy, alphabet, normalised entropy, and a
per-repository baseline -- and leaves conclusions to the rules and the
correlation engine. Nothing here raises a finding on its own.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from enum import Enum

MIN_PAYLOAD_LENGTH = 40
"""Below this, entropy estimates are dominated by sample size. Do not guess."""

MIN_CALIBRATION_SAMPLES = 8
"""Fewer samples than this and a repository baseline means nothing."""

_MAD_TO_SIGMA = 1.4826
"""Scales median absolute deviation onto the standard-deviation scale."""


class Alphabet(str, Enum):
    """The symbol set a string draws from, which bounds its possible entropy."""

    HEX = "hex"
    BASE64 = "base64"
    BASE32 = "base32"
    NATURAL = "natural"
    """Prose, identifiers, paths -- anything not drawn from an encoding alphabet."""
    BINARY = "binary"


_ALPHABET_SIZE = {
    Alphabet.HEX: 16,
    Alphabet.BASE32: 32,
    Alphabet.BASE64: 64,
    Alphabet.NATURAL: 96,
    Alphabet.BINARY: 256,
}

# Minimum lengths before an alphabet claim is credible. "deface" is valid hex
# and an English word; "added" is both too. Length is what separates them.
_MIN_ALPHABET_LENGTH = {
    Alphabet.HEX: 32,
    Alphabet.BASE32: 32,
    Alphabet.BASE64: 40,
}

_HEX_RE = re.compile(r"\A[0-9a-fA-F]+\Z")
_BASE64_RE = re.compile(r"\A[A-Za-z0-9+/_-]+={0,2}\Z")
_BASE32_RE = re.compile(r"\A[A-Z2-7]+={0,6}\Z")
_WORD_RE = re.compile(r"[a-z]{3,}")
# A per-character generator over every literal in a repository was the second
# hottest line in the profile; the regex engine does the same scan in C.
_NON_TEXT_RE = re.compile(r"[^\t\n\r\x20-\x7e]")

_MIN_DISTINCT_SYMBOLS = 12
"""``"A" * 400`` matches the base64 alphabet but carries no information."""


def shannon_entropy(data: bytes | str) -> float:
    """Shannon entropy in bits per symbol. ``H = -sum(p_i * log2(p_i))``."""
    if isinstance(data, str):
        data = data.encode("utf-8", errors="replace")
    if not data:
        return 0.0
    total = len(data)
    return -sum((count / total) * math.log2(count / total) for count in Counter(data).values())


@dataclass(frozen=True)
class EntropyWindow:
    offset: int
    length: int
    entropy: float


def windowed_entropy(data: bytes, window: int = 1024) -> list[EntropyWindow]:
    """Entropy per fixed-size window.

    A whole-file average hides an appended payload: 4 KB of random data inside a
    1 MB file of zeroes barely moves the mean but stands out as a plateau. This
    is how the binary-asset engine finds smuggled content inside a real image.
    """
    if not data:
        return []
    if window <= 0:
        raise ValueError("window must be positive")
    return [
        EntropyWindow(offset=off, length=len(chunk), entropy=shannon_entropy(chunk))
        for off in range(0, len(data), window)
        if (chunk := data[off : off + window])
    ]


def _detect_alphabet(text: str) -> Alphabet:
    stripped = text.strip()
    if not stripped:
        return Alphabet.NATURAL
    if len(stripped) >= _MIN_ALPHABET_LENGTH[Alphabet.HEX] and _HEX_RE.match(stripped):
        return Alphabet.HEX
    if len(stripped) >= _MIN_ALPHABET_LENGTH[Alphabet.BASE32] and _BASE32_RE.match(stripped):
        return Alphabet.BASE32
    if len(stripped) >= _MIN_ALPHABET_LENGTH[Alphabet.BASE64] and _BASE64_RE.match(stripped):
        return Alphabet.BASE64
    if _NON_TEXT_RE.search(stripped):
        return Alphabet.BINARY
    return Alphabet.NATURAL


@dataclass(frozen=True)
class StringProfile:
    """Everything measurable about one string literal."""

    text: str
    length: int
    entropy: float
    alphabet: Alphabet
    distinct_symbols: int
    word_ratio: float
    """Share of characters belonging to lowercase words of 3+ letters.

    High for prose, URLs and file paths; near zero for encoded blobs. This is
    what keeps a long log message from being read as a payload.
    """

    @property
    def normalized_entropy(self) -> float:
        """Entropy as a fraction of the maximum its alphabet allows.

        Puts hex and base64 on one scale: a random hex blob and a random base64
        blob both score near 1.0 despite differing by 2 bits per character.
        """
        ceiling = math.log2(_ALPHABET_SIZE[self.alphabet])
        return min(self.entropy / ceiling, 1.0) if ceiling else 0.0

    @property
    def looks_encoded(self) -> bool:
        """Whether this string plausibly carries encoded data rather than text.

        A deliberately permissive test -- an embedded certificate passes it, and
        should. It is a feature for the correlation engine, not a verdict.
        """
        if self.length < MIN_PAYLOAD_LENGTH:
            return False
        if self.distinct_symbols < _MIN_DISTINCT_SYMBOLS:
            return False
        if self.alphabet in (Alphabet.HEX, Alphabet.BASE64, Alphabet.BASE32):
            return self.normalized_entropy > 0.75
        if self.alphabet is Alphabet.BINARY:
            return self.entropy > 4.5
        return self.word_ratio < 0.35 and self.normalized_entropy > 0.72


def profile_string(text: str) -> StringProfile:
    """Measure one string literal."""
    stripped = text.strip()
    words = _WORD_RE.findall(stripped.lower())
    word_chars = sum(len(w) for w in words)
    return StringProfile(
        text=stripped,
        length=len(stripped),
        entropy=shannon_entropy(stripped),
        alphabet=_detect_alphabet(stripped),
        distinct_symbols=len(set(stripped)),
        word_ratio=word_chars / len(stripped) if stripped else 0.0,
    )


@dataclass(frozen=True)
class Calibration:
    """A repository's own entropy baseline.

    Absolute thresholds cannot distinguish a minified-JS project from a C
    codebase. Comparing each measurement against the distribution of its own
    repository can. Median and MAD are used rather than mean and standard
    deviation so that a handful of vendored blobs cannot drag the baseline up
    and hide the payload sitting next to them.
    """

    median: float
    mad: float
    sample_count: int

    @property
    def is_calibrated(self) -> bool:
        return self.sample_count >= MIN_CALIBRATION_SAMPLES

    @classmethod
    def from_values(cls, values: list[float]) -> Calibration:
        if not values:
            return cls(median=0.0, mad=0.0, sample_count=0)
        ordered = sorted(values)
        median = _median(ordered)
        mad = _median(sorted(abs(v - median) for v in values))
        return cls(median=median, mad=mad, sample_count=len(values))

    def zscore(self, value: float) -> float:
        """Robust z-score. ``0.0`` when there is not enough data to judge."""
        if not self.is_calibrated:
            return 0.0
        scale = self.mad * _MAD_TO_SIGMA
        if scale <= 1e-9:
            # A perfectly uniform repository: any deviation at all is notable,
            # but there is no scale to express it on, so fall back to a
            # bounded constant rather than dividing by zero.
            return 0.0 if abs(value - self.median) < 1e-9 else 6.0
        return (value - self.median) / scale


def _median(ordered: list[float]) -> float:
    n = len(ordered)
    mid = n // 2
    return ordered[mid] if n % 2 else (ordered[mid - 1] + ordered[mid]) / 2
