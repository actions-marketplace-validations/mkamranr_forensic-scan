"""What is this file, and is it what it claims to be?

Two questions, answered without a system ``libmagic`` dependency -- that would
need a C library present at install time and break ``pipx install`` on Windows
and on bare CI images. The signature table below covers every format that
matters for payload smuggling, which is a far smaller set than libmagic's.

The second question is the interesting one. A ``.png`` whose bytes are an ELF
binary is the FOR-002 case, and it is one of the few signals in this scanner
with essentially no benign explanation.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path

HEADER_READ_BYTES = 4096
"""Enough for every signature here, including tar's at offset 257."""


class ContentCategory(str, Enum):
    EXECUTABLE = "executable"
    ARCHIVE = "archive"
    IMAGE = "image"
    MEDIA = "media"
    DOCUMENT = "document"
    DATA = "data"


class FileRole(str, Enum):
    SOURCE = "source"
    """Parseable by one of our tree-sitter grammars."""
    ASSET = "asset"
    """Binary or opaque; inspected by the binary-asset engine."""
    TEXT = "text"
    """Human-readable but not a language we parse."""
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class DetectedType:
    name: str
    category: ContentCategory


@dataclass(frozen=True)
class _Signature:
    magic: bytes
    offset: int
    name: str
    category: ContentCategory


# Ordered: longer and more specific signatures first, so that a prefix match
# never shadows a more precise one.
_SIGNATURES: tuple[_Signature, ...] = (
    _Signature(b"\x89PNG\r\n\x1a\n", 0, "png", ContentCategory.IMAGE),
    _Signature(b"\xfd7zXZ\x00", 0, "xz", ContentCategory.ARCHIVE),
    _Signature(b"7z\xbc\xaf\x27\x1c", 0, "7z", ContentCategory.ARCHIVE),
    _Signature(b"SQLite format 3\x00", 0, "sqlite", ContentCategory.DATA),
    _Signature(b"\x1f\x8b", 0, "gzip", ContentCategory.ARCHIVE),
    _Signature(b"BZh", 0, "bzip2", ContentCategory.ARCHIVE),
    _Signature(b"PK\x03\x04", 0, "zip", ContentCategory.ARCHIVE),
    _Signature(b"PK\x05\x06", 0, "zip", ContentCategory.ARCHIVE),
    _Signature(b"PK\x07\x08", 0, "zip", ContentCategory.ARCHIVE),
    _Signature(b"\x28\xb5\x2f\xfd", 0, "zstd", ContentCategory.ARCHIVE),
    _Signature(b"\x04\x22\x4d\x18", 0, "lz4", ContentCategory.ARCHIVE),
    _Signature(b"\x5d\x00\x00", 0, "lzma", ContentCategory.ARCHIVE),
    _Signature(b"\x7fELF", 0, "elf", ContentCategory.EXECUTABLE),
    _Signature(b"\x00asm", 0, "wasm", ContentCategory.EXECUTABLE),
    _Signature(b"\xfe\xed\xfa\xce", 0, "mach-o", ContentCategory.EXECUTABLE),
    _Signature(b"\xfe\xed\xfa\xcf", 0, "mach-o", ContentCategory.EXECUTABLE),
    _Signature(b"\xce\xfa\xed\xfe", 0, "mach-o", ContentCategory.EXECUTABLE),
    _Signature(b"\xcf\xfa\xed\xfe", 0, "mach-o", ContentCategory.EXECUTABLE),
    _Signature(b"MZ", 0, "pe", ContentCategory.EXECUTABLE),
    _Signature(b"\xff\xd8\xff", 0, "jpeg", ContentCategory.IMAGE),
    _Signature(b"GIF87a", 0, "gif", ContentCategory.IMAGE),
    _Signature(b"GIF89a", 0, "gif", ContentCategory.IMAGE),
    _Signature(b"BM", 0, "bmp", ContentCategory.IMAGE),
    _Signature(b"\x00\x00\x01\x00", 0, "ico", ContentCategory.IMAGE),
    _Signature(b"%PDF", 0, "pdf", ContentCategory.DOCUMENT),
    _Signature(b"OggS", 0, "ogg", ContentCategory.MEDIA),
    _Signature(b"ID3", 0, "mp3", ContentCategory.MEDIA),
    _Signature(b"ustar", 257, "tar", ContentCategory.ARCHIVE),
)

_CAFEBABE = b"\xca\xfe\xba\xbe"


def sniff(data: bytes) -> DetectedType | None:
    """Identify content by signature, or ``None`` if nothing matches.

    ``None`` is the common case and means only "not a known container" -- source
    code, JSON, and plain text all land here.
    """
    if not data:
        return None

    # cafebabe is shared by Java class files and Mach-O fat binaries. In a Java
    # class the next two bytes are a minor version, almost always < 0x0100; in a
    # Mach-O fat header they are the high half of an architecture count.
    if data.startswith(_CAFEBABE) and len(data) >= 8:
        name = "java-class" if data[4:6] < b"\x01\x00" else "mach-o"
        return DetectedType(name, ContentCategory.EXECUTABLE)

    for sig in _SIGNATURES:
        end = sig.offset + len(sig.magic)
        if len(data) >= end and data[sig.offset : end] == sig.magic:
            return DetectedType(sig.name, sig.category)
    return None


# Extension -> tree-sitter grammar name. v1 covers the languages where
# supply-chain attacks actually land; adding a language starts here.
LANGUAGE_BY_EXTENSION: dict[str, str] = {
    ".py": "python",
    ".pyi": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".mts": "typescript",
    ".cts": "typescript",
    ".tsx": "tsx",
    ".c": "c",
    ".h": "c",
}

# Extension -> the content signature it asserts. Only extensions that make a
# falsifiable claim belong here: ``.dat`` and ``.bin`` promise nothing, so a
# compressed blob inside one is not a lie.
_DECLARED_BY_EXTENSION: dict[str, tuple[str, ContentCategory]] = {
    ".png": ("png", ContentCategory.IMAGE),
    ".jpg": ("jpeg", ContentCategory.IMAGE),
    ".jpeg": ("jpeg", ContentCategory.IMAGE),
    ".gif": ("gif", ContentCategory.IMAGE),
    ".bmp": ("bmp", ContentCategory.IMAGE),
    ".ico": ("ico", ContentCategory.IMAGE),
    ".pdf": ("pdf", ContentCategory.DOCUMENT),
    ".gz": ("gzip", ContentCategory.ARCHIVE),
    ".tgz": ("gzip", ContentCategory.ARCHIVE),
    ".xz": ("xz", ContentCategory.ARCHIVE),
    ".bz2": ("bzip2", ContentCategory.ARCHIVE),
    ".zip": ("zip", ContentCategory.ARCHIVE),
    ".zst": ("zstd", ContentCategory.ARCHIVE),
    ".7z": ("7z", ContentCategory.ARCHIVE),
    ".tar": ("tar", ContentCategory.ARCHIVE),
    ".wasm": ("wasm", ContentCategory.EXECUTABLE),
    ".sqlite": ("sqlite", ContentCategory.DATA),
    ".db": ("sqlite", ContentCategory.DATA),
}

# Build and install entry points -- where a payload gets to run without anyone
# calling it. Matched by exact filename unless noted.
_BUILD_FILENAMES: dict[str, str] = {
    "setup.py": "python-setup",
    "setup.cfg": "python-setup",
    "conftest.py": "pytest-conftest",
    "package.json": "npm-manifest",
    "makefile": "make",
    "gnumakefile": "make",
    "cmakelists.txt": "cmake",
    "configure.ac": "autoconf",
    "configure.in": "autoconf",
    "configure": "autoconf",
    "build.rs": "cargo-build",
    "binding.gyp": "node-gyp",
    "meson.build": "meson",
    "sconstruct": "scons",
    "wscript": "waf",
    "dockerfile": "docker",
}

# npm lifecycle scripts, matched by filename. Bare `install` is excluded and the
# extensions are restricted to JavaScript and shell: `distutils/command/install.py`
# is not an npm hook, and treating it as one reported the standard library's own
# packaging machinery as an install-time attack.
_BUILD_STEMS: dict[str, str] = {
    "postinstall": "npm-lifecycle",
    "preinstall": "npm-lifecycle",
    "prepublish": "npm-lifecycle",
    "prepack": "npm-lifecycle",
}

_BUILD_STEM_EXTENSIONS = frozenset({".js", ".cjs", ".mjs", ".sh"})

_TEXT_EXTENSIONS = {
    ".md",
    ".txt",
    ".rst",
    ".json",
    ".yml",
    ".yaml",
    ".toml",
    ".ini",
    ".cfg",
    ".xml",
    ".html",
    ".css",
    ".csv",
    ".sh",
    ".bash",
    ".zsh",
    ".env",
    ".lock",
}


@dataclass(frozen=True)
class ClassifiedFile:
    """Everything the engines need to know about a file before reading it."""

    path: Path
    size: int
    role: FileRole
    language: str | None
    is_build: bool
    build_kind: str | None
    detected: DetectedType | None
    declared: str | None
    mismatch: bool
    is_binary: bool

    @property
    def is_archive(self) -> bool:
        return self.detected is not None and self.detected.category is ContentCategory.ARCHIVE

    @property
    def is_executable_image(self) -> bool:
        return self.detected is not None and self.detected.category is ContentCategory.EXECUTABLE


def _build_kind_for(path: Path) -> str | None:
    name = path.name.lower()
    if name in _BUILD_FILENAMES:
        return _BUILD_FILENAMES[name]
    if path.suffix.lower() == ".m4":
        return "autoconf-m4"
    if name.startswith("makefile."):
        return "make"
    stem = path.stem.lower()
    if stem in _BUILD_STEMS and path.suffix.lower() in _BUILD_STEM_EXTENSIONS:
        return _BUILD_STEMS[stem]
    return None


_PRINTABLE_BYTES = bytes([9, 10, 13]) + bytes(range(32, 127))
_NON_PRINTABLE_TABLE = bytes.maketrans(_PRINTABLE_BYTES, b"\x00" * len(_PRINTABLE_BYTES))


def _looks_like_text(data: bytes) -> bool:
    """A NUL byte is the reliable binary tell; beyond that, judge by control chars.

    Implemented with ``translate`` rather than a per-byte loop: this runs over
    every file's header, and the loop form was measurably expensive on a large
    tree.
    """
    if b"\x00" in data:
        return False
    if not data:
        return True
    printable = data.translate(_NON_PRINTABLE_TABLE).count(0)
    return printable / len(data) > 0.85


def classify_file(
    path: Path, header: bytes | None = None, size: int | None = None
) -> ClassifiedFile:
    """Classify one file. ``header`` and ``size`` may be supplied to avoid re-reading."""
    if header is None:
        try:
            with path.open("rb") as fh:
                header = fh.read(HEADER_READ_BYTES)
        except OSError:
            header = b""
    if size is None:
        try:
            size = path.stat().st_size
        except OSError:
            size = len(header)

    suffix = path.suffix.lower()
    language = LANGUAGE_BY_EXTENSION.get(suffix)
    build_kind = _build_kind_for(path)
    detected = sniff(header)
    is_text = _looks_like_text(header)

    declared_name: str | None = None
    mismatch = False
    if suffix in _DECLARED_BY_EXTENSION:
        declared_name, declared_category = _DECLARED_BY_EXTENSION[suffix]
        if detected is None:
            # The extension promises a binary container and the bytes are not
            # one. Text in a .png is still a lie, just a less alarming one.
            mismatch = True
        else:
            mismatch = detected.name != declared_name and detected.category is not declared_category

    if language:
        role = FileRole.SOURCE
    elif detected is not None or not is_text:
        role = FileRole.ASSET
    elif suffix in _TEXT_EXTENSIONS or build_kind or is_text:
        role = FileRole.TEXT
    else:
        role = FileRole.UNKNOWN

    return ClassifiedFile(
        path=path,
        size=size,
        role=role,
        language=language,
        is_build=build_kind is not None,
        build_kind=build_kind,
        detected=detected,
        declared=declared_name,
        mismatch=mismatch,
        is_binary=not is_text,
    )
