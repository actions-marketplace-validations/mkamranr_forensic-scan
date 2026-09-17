"""Module C -- payloads hidden in files that are not code.

This is where the XZ Utils attack kept its backdoor: in test fixtures, which no
reviewer reads and no linter parses. The engine asks four questions of every
non-code file:

1. Is it what its extension claims? (``MAGIC_MISMATCH``)
2. Does it contain an executable image? (``EXECUTABLE_HEADER``)
3. Does it contain a compressed stream it has no reason to? (``EMBEDDED_ARCHIVE``)
4. Does it carry data past its own declared end? (``TRAILING_DATA``)

Each answer is a signal, not a verdict. A ``.png`` with an appended xz stream is
close to unambiguous; an opaque high-entropy fixture is merely interesting until
the correlation engine finds a build script that reads it.

False-positive discipline is concentrated in the signature search. ``MZ`` is two
bytes and occurs roughly once every 64 KB of random data, so a naive substring
scan would flag every compressed file in the repository. Every embedded
signature here is either long enough to be improbable or validated against the
format's own header fields.
"""

from __future__ import annotations

import re
import zlib
from dataclasses import dataclass
from pathlib import Path

from ..discovery.classify import ClassifiedFile, ContentCategory, FileRole
from ..models import Location, Signal, SignalKind
from .entropy import shannon_entropy, windowed_entropy

MAX_ASSET_READ = 16 * 1024 * 1024
"""Assets larger than this are analysed from their first 16 MB."""

TRAILING_BYTES_TOLERANCE = 16
"""Encoders pad to block boundaries; a handful of bytes is not a payload."""

OPAQUE_ENTROPY_THRESHOLD = 7.2
"""Bits per byte above which an unidentifiable binary is worth noting."""

MIN_OPAQUE_SIZE = 1024
"""Small blobs are too short for the entropy estimate to mean anything."""

FIXTURE_DIRECTORY_RE = re.compile(
    r"(^|/)(tests?|fixtures?|testdata|test_data|spec|specs|samples?|assets?|resources?)(/|$)",
    re.IGNORECASE,
)
"""Directories whose contents are assumed unreviewed, raising the weight of any
anomaly found there. Named after where the XZ payload actually lived."""


@dataclass(frozen=True)
class _EmbeddedSignature:
    magic: bytes
    name: str
    category: ContentCategory
    validator: str | None = None


# Only signatures long enough to be improbable in random data, or with a
# validator that checks the format's own header fields.
_EMBEDDED_SIGNATURES: tuple[_EmbeddedSignature, ...] = (
    _EmbeddedSignature(b"\x7fELF", "elf", ContentCategory.EXECUTABLE, "elf"),
    _EmbeddedSignature(b"\xfd7zXZ\x00", "xz", ContentCategory.ARCHIVE),
    _EmbeddedSignature(b"7z\xbc\xaf\x27\x1c", "7z", ContentCategory.ARCHIVE),
    _EmbeddedSignature(b"\x89PNG\r\n\x1a\n", "png", ContentCategory.IMAGE),
    _EmbeddedSignature(b"PK\x03\x04", "zip", ContentCategory.ARCHIVE),
    _EmbeddedSignature(b"\x1f\x8b\x08", "gzip", ContentCategory.ARCHIVE, "gzip"),
    _EmbeddedSignature(b"\xfe\xed\xfa\xcf", "mach-o", ContentCategory.EXECUTABLE),
    _EmbeddedSignature(b"\xcf\xfa\xed\xfe", "mach-o", ContentCategory.EXECUTABLE),
    _EmbeddedSignature(b"BZh9\x31\x41\x59\x26\x53\x59", "bzip2", ContentCategory.ARCHIVE),
)


def _valid_elf(data: bytes, offset: int) -> bool:
    """Check EI_CLASS, EI_DATA and EI_VERSION rather than trusting four bytes."""
    if len(data) < offset + 7:
        return False
    ei_class, ei_data, ei_version = data[offset + 4], data[offset + 5], data[offset + 6]
    return ei_class in (1, 2) and ei_data in (1, 2) and ei_version == 1


def _valid_gzip(data: bytes, offset: int) -> bool:
    """Check the FLG byte: bits 5-7 are reserved and must be zero."""
    return len(data) >= offset + 4 and data[offset + 3] & 0xE0 == 0


_VALIDATORS = {"elf": _valid_elf, "gzip": _valid_gzip}


def _png_payload_offset(data: bytes) -> int | None:
    """Byte offset just past the IEND chunk, or ``None`` if malformed."""
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        return None
    pos = 8
    while pos + 8 <= len(data):
        length = int.from_bytes(data[pos : pos + 4], "big")
        kind = data[pos + 4 : pos + 8]
        end = pos + 12 + length
        if end > len(data):
            return None
        if kind == b"IEND":
            return end
        pos = end
    return None


def _jpeg_payload_offset(data: bytes) -> int | None:
    """Byte offset just past the end-of-image marker."""
    if not data.startswith(b"\xff\xd8\xff"):
        return None
    marker = data.rfind(b"\xff\xd9")
    return marker + 2 if marker > 0 else None


def _gzip_payload_offset(data: bytes) -> int | None:
    """Byte offset just past the gzip stream, found by decompressing it."""
    if not data.startswith(b"\x1f\x8b"):
        return None
    try:
        decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
        decompressor.decompress(data, 1)
        while not decompressor.eof:
            if not decompressor.unconsumed_tail:
                break
            decompressor.decompress(decompressor.unconsumed_tail, 1 << 20)
        if not decompressor.eof:
            return None
        return len(data) - len(decompressor.unused_data)
    except zlib.error:
        return None


def _zip_payload_offset(data: bytes) -> int | None:
    """Byte offset just past the end-of-central-directory record."""
    eocd = data.rfind(b"PK\x05\x06")
    if eocd < 0 or eocd + 22 > len(data):
        return None
    comment_length = int.from_bytes(data[eocd + 20 : eocd + 22], "little")
    return eocd + 22 + comment_length


# Formats whose files are zip archives under another name. Without these, every
# wheel, jar and .docx in a repository reports an embedded archive.
_ZIP_CONTAINER_EXTENSIONS = frozenset(
    {
        ".jar",
        ".war",
        ".ear",
        ".apk",
        ".aar",
        ".whl",
        ".egg",
        ".nupkg",
        ".vsix",
        ".crx",
        ".xpi",
        ".docx",
        ".xlsx",
        ".pptx",
        ".odt",
        ".ods",
        ".odp",
        ".epub",
    }
)

_GZIP_CONTAINER_EXTENSIONS = frozenset({".svgz", ".tgz", ".emz", ".wmz"})

# Modern ICO files embed PNG frames; that is the format, not smuggling.
_PNG_CONTAINER_EXTENSIONS = frozenset({".ico", ".icns", ".cur"})


NATIVE_BINARY_EXTENSIONS = frozenset(
    {".so", ".dylib", ".dll", ".pyd", ".node", ".o", ".a", ".lib", ".exe", ".wasm", ".bundle"}
)
"""Compiled artefacts, which *are* executable images by definition.

Reporting "a Mach-O header was found inside a .so" is not a finding, it is a
description. Worse, a few hundred kilobytes of machine code contains arbitrary
byte sequences, so a naive signature search finds a zip header in roughly every
large binary -- CPython's own `_lzma.so` contains xz magic because it is the xz
library."""


def _explained_formats(classified: ClassifiedFile) -> frozenset[str]:
    """Every format this file's *name* licenses it to contain.

    A set rather than one value, because a name can license more than its own
    type: an `.ico` is an icon container that legitimately holds PNG frames, and
    a `.whl` is a zip. Returning only the declared type meant a modern icon
    reported an embedded image it was supposed to have.
    """
    explained: set[str] = set()
    if classified.declared:
        explained.add(classified.declared)
    suffix = classified.path.suffix.lower()
    if suffix in _ZIP_CONTAINER_EXTENSIONS:
        explained.add("zip")
    if suffix in _GZIP_CONTAINER_EXTENSIONS:
        explained.add("gzip")
    if suffix in _PNG_CONTAINER_EXTENSIONS:
        explained.update({"png", "bmp"})
    return frozenset(explained)


def _is_compiled_artifact(classified: ClassifiedFile) -> bool:
    """Whether the file's *name* declares it to be a compiled artefact.

    Extension only, deliberately. A file called `libfoo.so` that is a Mach-O
    image has explained itself. A file called `data.bin` that is an ELF has
    explained nothing, and in a fixtures directory it is exactly the finding.
    """
    return classified.path.suffix.lower() in NATIVE_BINARY_EXTENSIONS


_CONTAINER_END = {
    "png": _png_payload_offset,
    "jpeg": _jpeg_payload_offset,
    "gzip": _gzip_payload_offset,
    "zip": _zip_payload_offset,
}


class BinaryAssetEngine:
    """Inspects non-code files for smuggled content."""

    def analyze(self, classified: ClassifiedFile) -> list[Signal]:
        if classified.role is FileRole.SOURCE:
            return []
        data = self._read(classified.path)
        if not data:
            return []

        signals: list[Signal] = []
        location = Location(path=classified.path)
        in_fixtures = bool(FIXTURE_DIRECTORY_RE.search(classified.path.parent.as_posix()))

        if classified.mismatch:
            signals.append(self._mismatch_signal(classified, location, in_fixtures))

        signals.extend(self._embedded_signals(classified, data, location, in_fixtures))
        signals.extend(self._trailing_signals(classified, data, location, in_fixtures))
        signals.extend(self._opaque_signals(classified, data, location, in_fixtures))
        return signals

    # -- individual checks -------------------------------------------------

    def _mismatch_signal(
        self, classified: ClassifiedFile, location: Location, in_fixtures: bool
    ) -> Signal:
        detected = classified.detected
        return Signal(
            kind=SignalKind.MAGIC_MISMATCH,
            location=location,
            features={"in_fixtures": float(in_fixtures)},
            metadata={
                "declared": classified.declared or classified.path.suffix.lstrip("."),
                "detected": detected.name if detected else "text",
                "detected_category": detected.category.value if detected else "text",
            },
        )

    def _embedded_signals(
        self,
        classified: ClassifiedFile,
        data: bytes,
        location: Location,
        in_fixtures: bool,
    ) -> list[Signal]:
        """Signatures found anywhere in the file, including at offset zero."""
        # A compiled binary is an executable image and contains arbitrary bytes.
        # Searching it for embedded signatures produces noise proportional to its
        # size and nothing else.
        if _is_compiled_artifact(classified):
            return []

        signals: list[Signal] = []
        own_type = classified.detected.name if classified.detected else None
        explained = _explained_formats(classified)

        for sig in _EMBEDDED_SIGNATURES:
            # A .zip is full of PK headers and a .xz starts with xz magic. What
            # licenses those occurrences is the *extension*, not the content: a
            # file named .bin that happens to be an ELF has explained nothing,
            # and in a fixtures directory it is precisely the finding.
            if sig.name in explained:
                continue
            for offset in self._find_all(data, sig.magic):
                validator = _VALIDATORS.get(sig.validator or "")
                if validator and not validator(data, offset):
                    continue
                kind = (
                    SignalKind.EXECUTABLE_HEADER
                    if sig.category is ContentCategory.EXECUTABLE
                    else SignalKind.EMBEDDED_ARCHIVE
                )
                signals.append(
                    Signal(
                        kind=kind,
                        location=location,
                        features={
                            "offset": float(offset),
                            "in_fixtures": float(in_fixtures),
                            "file_size": float(classified.size),
                        },
                        metadata={
                            "format": sig.name,
                            # What the file claims to be, not what it is: "an elf
                            # header inside a png" is the sentence worth reading.
                            "carrier": classified.path.suffix.lstrip(".") or own_type or "unknown",
                        },
                    )
                )
                break  # one signal per format is enough to prompt a look
        return signals

    def _trailing_signals(
        self,
        classified: ClassifiedFile,
        data: bytes,
        location: Location,
        in_fixtures: bool,
    ) -> list[Signal]:
        detected = classified.detected
        if detected is None or detected.name not in _CONTAINER_END:
            return []
        end = _CONTAINER_END[detected.name](data)
        if end is None:
            return []
        trailing = len(data) - end
        if trailing <= TRAILING_BYTES_TOLERANCE:
            return []
        tail = data[end : end + 65536]
        return [
            Signal(
                kind=SignalKind.TRAILING_DATA,
                location=location,
                features={
                    "trailing_bytes": float(trailing),
                    "trailing_entropy": shannon_entropy(tail),
                    "offset": float(end),
                    "in_fixtures": float(in_fixtures),
                },
                metadata={"format": detected.name},
            )
        ]

    def _opaque_signals(
        self,
        classified: ClassifiedFile,
        data: bytes,
        location: Location,
        in_fixtures: bool,
    ) -> list[Signal]:
        """Unidentifiable high-entropy binaries.

        Weak on its own -- most are legitimate compiled or compressed assets --
        but it is the hook the correlation engine needs to notice that a build
        script reads one of them.
        """
        if not classified.is_binary or len(data) < MIN_OPAQUE_SIZE:
            return []

        # A recognised archive is still opaque to a human reviewer -- that is
        # what an archive is. The XZ Utils payload sat in a correctly formed .xz
        # file, so requiring an *unrecognised* format here would miss the case
        # this scanner exists for. Narrowed to fixture directories, and reported
        # as a weaker signal via `identified`.
        identified = classified.detected is not None
        if identified and not (in_fixtures and classified.is_archive):
            return []

        entropy = shannon_entropy(data)
        if not identified and entropy < OPAQUE_ENTROPY_THRESHOLD:
            return []

        windows = windowed_entropy(data, window=4096)
        return [
            Signal(
                kind=SignalKind.OPAQUE_ASSET,
                location=location,
                features={
                    "entropy": entropy,
                    "peak_entropy": max(w.entropy for w in windows),
                    "size": float(classified.size),
                    "in_fixtures": float(in_fixtures),
                },
                metadata={
                    "extension": classified.path.suffix.lstrip(".") or "none",
                    "identified": "yes" if identified else "no",
                    "format": classified.detected.name if classified.detected else "unknown",
                },
            )
        ]

    # -- helpers -----------------------------------------------------------

    @staticmethod
    def _find_all(data: bytes, needle: bytes, limit: int = 8) -> list[int]:
        offsets: list[int] = []
        start = 0
        while len(offsets) < limit:
            found = data.find(needle, start)
            if found < 0:
                break
            offsets.append(found)
            start = found + 1
        return offsets

    @staticmethod
    def _read(path: Path) -> bytes:
        try:
            with path.open("rb") as fh:
                return fh.read(MAX_ASSET_READ)
        except OSError:
            return b""
