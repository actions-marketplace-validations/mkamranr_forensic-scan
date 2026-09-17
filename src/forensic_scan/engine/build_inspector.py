"""Module D -- what happens during build and install.

Install hooks are the most attacked files in the open-source ecosystem for one
reason: they run without anyone calling them, on machines whose owners never
read them. ``npm install`` executes ``postinstall``; ``pip install`` executes
``setup.py``; ``./configure`` executes whatever ``.m4`` files happen to be
lying around. That last one is how the XZ Utils backdoor got in.

Phase context is what makes these signals worth anything. ``subprocess.run`` in
application code is Tuesday. ``subprocess.run`` in ``setup.py`` is a question.
The same call, the same arguments -- only the file it sits in differs, and that
is the entire detection.

Two analysis styles, chosen per file:

*Parsed* -- ``setup.py`` and ``postinstall.js`` are real source, so they go
through tree-sitter and the same signature table the obfuscation engine uses.

*Textual* -- Makefiles, CMake, m4 and shell fragments have no grammar here and
mostly do not need one. What matters in them is which commands appear, and a
careful set of patterns reads that directly.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import TYPE_CHECKING

from ..discovery.classify import ClassifiedFile
from ..models import Location, Signal, SignalKind
from ..parser.registry import ParsedFile, ParserRegistry
from .signatures import LANGUAGE_FAMILY, STRING_NODE_TYPES, match_signature

if TYPE_CHECKING:  # pragma: no cover
    import tree_sitter as ts

NPM_LIFECYCLE_HOOKS = frozenset(
    {
        "preinstall",
        "install",
        "postinstall",
        "prepare",
        "prepublish",
        "prepublishOnly",
        "prepack",
        "postpack",
        "preuninstall",
        "postuninstall",
        "prerestart",
    }
)
"""Hooks npm runs on its own. ``build`` and ``test`` are omitted deliberately --
they run only when someone types them, which is a different threat model."""

# Shell commands that execute code. Word-bounded so `bashrc` and `system.log`
# do not match.
_SHELL_EXEC_RE = re.compile(
    r"""\b(
        sh|bash|zsh|dash|ksh|cmd|powershell|pwsh
      | eval|exec|source
      | node\s+-e|python\d?\s+-c|perl\s+-e|ruby\s+-e
      | chmod\s+\+x
    )\b""",
    re.VERBOSE | re.IGNORECASE,
)

# Network *commands* only. A bare URL is not network access: CPython's own
# Makefile contains https:// in comments and variables, and matching it reported
# the standard library as reaching out during its build.
_NETWORK_RE = re.compile(
    r"""(
        \bcurl\b | \bwget\b | \bncat\b | \bnetcat\b
      | \bscp\b | \bsftp\b | \brsync\b | \bgit\s+clone\b
      | \bInvoke-WebRequest\b | \bStart-BitsTransfer\b
    )""",
    re.VERBOSE | re.IGNORECASE,
)

# Flag clusters (`xz -dc`, `tar -xzf`) must not be anchored by a trailing \b:
# the boundary would have to fall between two word characters and never matches.
_DECOMPRESS_RE = re.compile(
    r"""(
        \bbase64\s+-{1,2}[A-Za-z]*(?:d|decode)[A-Za-z]*
      | \bxz\s+-[A-Za-z]*d[A-Za-z]*
      | \bgzip\s+-[A-Za-z]*d[A-Za-z]*
      | \bzstd\s+-[A-Za-z]*d[A-Za-z]*
      | \btar\s+-?[A-Za-z]*x[A-Za-z]*
      | \bopenssl\s+enc\b | \bxxd\s+-r | \buudecode\b
      | \b(?:unxz|gunzip|zcat|xzcat|bzcat|bunzip2|unzip|uncompress)\b
    )""",
    re.VERBOSE | re.IGNORECASE,
)

# Byte-substitution pipelines: the XZ backdoor's `tr` trick and its relatives.
#
# `sed` is deliberately absent. Substituting text in a build is what build
# systems do -- CPython's Makefile alone has dozens -- and including it reported
# every one of them as an obfuscated pipeline. `tr` with two character *sets*
# is the narrower and far more telling construct.
_OBFUSCATED_PIPELINE_RE = re.compile(
    r"""(
        \btr\s+["'][^"']{2,}["']\s+["'][^"']{2,}["']
      | \brev\b
      | \bawk\s+["'][^"']*printf[^"']*["']
    )""",
    re.VERBOSE,
)

_CMAKE_EXEC_RE = re.compile(
    r"\b(execute_process|add_custom_command|add_custom_target)\s*\(", re.IGNORECASE
)
_CMAKE_DOWNLOAD_RE = re.compile(r"\bfile\s*\(\s*DOWNLOAD\b", re.IGNORECASE)

_M4_EVAL_RE = re.compile(r"\b(eval|m4_esyscmd|esyscmd|AC_CONFIG_COMMANDS|syscmd)\b")

# Quoted or bare tokens that look like a path to a real file. Requires either a
# directory separator or a recognisable extension, so bare words are not
# harvested as paths.
_PATH_RE = re.compile(
    r"""["'`]?
    (?P<path>
      (?:[\w.$(){}-]+/)+[\w.$(){}-]+\.[A-Za-z0-9]{1,8}   # a/b/c.ext
      | [\w.-]+\.(?:xz|gz|bz2|zst|tar|zip|bin|dat|so|dll|dylib|png|jpg|pyc)
    )
    ["'`]?""",
    re.VERBOSE,
)

_PYTHON_DECOMPRESS = frozenset(
    {"zlib", "gzip", "bz2", "lzma", "tarfile", "zipfile", "base64", "binascii", "codecs"}
)
_PYTHON_NETWORK = frozenset(
    {"urllib", "requests", "httpx", "http", "socket", "ftplib", "urlopen", "aiohttp"}
)
_JS_NETWORK = frozenset({"http", "https", "fetch", "axios", "node-fetch", "got", "request"})

KNOWN_BUILD_TOOLS = frozenset(
    {
        "pkg-config",
        "pkgconf",
        "cmake",
        "make",
        "gmake",
        "ninja",
        "meson",
        "gcc",
        "g++",
        "cc",
        "c++",
        "clang",
        "clang++",
        "ld",
        "ar",
        "ranlib",
        "swig",
        "cython",
        "protoc",
        "flex",
        "bison",
        "autoreconf",
        "libtool",
        "git",
        "hg",
        "svn",
        "npm",
        "yarn",
        "pnpm",
        "cargo",
        "go",
        "rustc",
        "python",
        "python3",
        "pip",
        "pip3",
        "node",
        "java",
        "javac",
        "mvn",
    }
)
"""Commands whose appearance in a build script is the ordinary case.

``subprocess.check_output(["pkg-config", "--cflags", "zlib"])`` is in thousands
of legitimate ``setup.py`` files. Reporting it at HIGH teaches maintainers to
ignore the scanner, which costs more than the detection is worth."""

# Build phases that run without anyone asking. `pip install` executes setup.py
# and `npm install` executes postinstall; `make test` is something you type.
AUTO_RUN_KINDS = frozenset(
    {"python-setup", "npm-manifest", "npm-lifecycle", "autoconf", "autoconf-m4"}
)

_MAX_TEXT_BYTES = 2 * 1024 * 1024


class BuildInspector:
    """Finds code that runs during build or install, and what it reaches for."""

    def __init__(self, registry: ParserRegistry | None = None) -> None:
        self.registry = registry or ParserRegistry()

    def analyze(self, classified: ClassifiedFile, source: bytes) -> list[Signal]:
        if not classified.is_build or not source:
            return []
        kind = classified.build_kind
        text = source[:_MAX_TEXT_BYTES].decode("utf-8", errors="replace")

        if kind == "npm-manifest":
            return self._npm_manifest(classified.path, source)
        if kind in {"python-setup", "pytest-conftest"} and classified.language == "python":
            return self._parsed_source(classified.path, source, "python", text)
        if kind == "npm-lifecycle" and classified.language in {"javascript", "typescript"}:
            return self._parsed_source(classified.path, source, classified.language, text)
        return self._textual(classified, text, kind or "unknown")

    # -- parsed build scripts ---------------------------------------------

    def _parsed_source(self, path: Path, source: bytes, language: str, text: str) -> list[Signal]:
        """setup.py and postinstall.js: real code, analysed as such."""
        signals: list[Signal] = []
        parsed = self.registry.parse(path, source, language)
        if parsed is None:
            return self._scan_text(path, text, hook=None)

        family = LANGUAGE_FAMILY.get(language, "")
        string_types = STRING_NODE_TYPES.get(family, frozenset())

        for callee in parsed.captures("calls").get("callee", []):
            name = parsed.text(callee)
            location = parsed.location(callee)
            root = name.split(".")[0]
            signature = match_signature(name, language)
            base = {
                "what": name,
                "phase": "install",
                "context": "",
                "auto_run": "yes",
                "known_tool": self._known_tool(parsed, callee),
            }

            if signature is not None and signature.kind in {
                SignalKind.DYNAMIC_EXEC_SINK,
                SignalKind.DYNAMIC_IMPORT,
            }:
                signals.append(
                    self._signal(
                        SignalKind.BUILD_SHELL_EXEC,
                        location,
                        {**base, "note": signature.note},
                    )
                )
            elif root in _PYTHON_NETWORK or root in _JS_NETWORK or "urlopen" in name:
                signals.append(self._signal(SignalKind.BUILD_NETWORK_ACCESS, location, base))
            elif root in _PYTHON_DECOMPRESS or (
                signature is not None and signature.kind is SignalKind.DECODE_CALL
            ):
                signals.append(self._signal(SignalKind.BUILD_DECOMPRESSION, location, base))

        # Every string literal that names a file, so the correlation engine can
        # ask whether the build reaches for an asset it has flagged.
        for node in parsed.captures("strings").get("string", []):
            if node.type not in string_types:
                continue
            literal = parsed.text(node).strip("bruBRUfF").strip("\"'`")
            for reference in self._paths_in(literal):
                signals.append(
                    self._signal(
                        SignalKind.BUILD_FILE_REFERENCE,
                        parsed.location(node),
                        {
                            "path": reference,
                            "phase": "install",
                            "what": reference,
                            "context": "",
                            "auto_run": "yes",
                            "known_tool": "no",
                        },
                    )
                )
        return signals

    def _known_tool(self, parsed: ParsedFile, callee: ts.Node) -> str:
        """Whether this call names a recognised build tool in its arguments."""
        call = callee.parent
        arguments = call.child_by_field_name("arguments") if call is not None else None
        if arguments is None:
            return "no"
        text = parsed.text(arguments)
        for quote in ("'", '"'):
            for fragment in text.split(quote)[1::2]:
                first = fragment.strip().split()[0] if fragment.strip() else ""
                if first.rsplit("/", 1)[-1] in KNOWN_BUILD_TOOLS:
                    return "yes"
        return "no"

    # -- package.json ------------------------------------------------------

    def _npm_manifest(self, path: Path, source: bytes) -> list[Signal]:
        try:
            manifest = json.loads(source.decode("utf-8", errors="replace"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return []
        if not isinstance(manifest, dict):
            return []
        scripts = manifest.get("scripts")
        if not isinstance(scripts, dict):
            return []

        signals: list[Signal] = []
        for hook, command in scripts.items():
            if hook not in NPM_LIFECYCLE_HOOKS or not isinstance(command, str):
                continue
            signals.extend(self._scan_text(path, command, hook=hook))
        return signals

    # -- textual build files ----------------------------------------------

    def _textual(self, classified: ClassifiedFile, text: str, kind: str) -> list[Signal]:
        path = classified.path
        auto_run = "yes" if kind in AUTO_RUN_KINDS else "no"
        common = {
            "phase": _phase_for(kind),
            "context": "",
            "auto_run": auto_run,
            "known_tool": "no",
        }
        signals: list[Signal] = []

        if kind == "cmake":
            signals.extend(
                self._line_matches(path, text, _CMAKE_EXEC_RE, SignalKind.BUILD_SHELL_EXEC, common)
            )
            signals.extend(
                self._line_matches(
                    path, text, _CMAKE_DOWNLOAD_RE, SignalKind.BUILD_NETWORK_ACCESS, common
                )
            )
        if kind in {"autoconf", "autoconf-m4"}:
            signals.extend(
                self._line_matches(
                    path,
                    text,
                    _M4_EVAL_RE,
                    SignalKind.BUILD_MACRO_ANOMALY,
                    {**common, "why": "macro executes a computed command"},
                )
            )
            signals.extend(
                self._line_matches(
                    path,
                    text,
                    _OBFUSCATED_PIPELINE_RE,
                    SignalKind.BUILD_MACRO_ANOMALY,
                    {**common, "why": "byte-substitution pipeline"},
                )
            )

        signals.extend(
            self._scan_text(path, text, hook=None, phase=_phase_for(kind), auto_run=auto_run)
        )
        return signals

    def _scan_text(
        self,
        path: Path,
        text: str,
        hook: str | None,
        phase: str = "install",
        auto_run: str = "yes",
    ) -> list[Signal]:
        """Command-level inspection of a shell fragment or recipe."""
        recipe = _recipe_lines(text) if hook is None else text
        metadata = {
            "phase": phase,
            "context": f" (from the {hook} hook)" if hook else "",
            "auto_run": auto_run,
            "known_tool": "no",
            "why": "byte-substitution pipeline",
        }
        if hook:
            metadata["hook"] = hook

        signals: list[Signal] = []
        for pattern, kind in (
            (_NETWORK_RE, SignalKind.BUILD_NETWORK_ACCESS),
            (_DECOMPRESS_RE, SignalKind.BUILD_DECOMPRESSION),
            (_SHELL_EXEC_RE, SignalKind.BUILD_SHELL_EXEC),
            (_OBFUSCATED_PIPELINE_RE, SignalKind.BUILD_MACRO_ANOMALY),
        ):
            signals.extend(self._line_matches(path, recipe, pattern, kind, metadata, text))

        for reference in self._paths_in(recipe):
            signals.append(
                Signal(
                    kind=SignalKind.BUILD_FILE_REFERENCE,
                    location=Location(
                        path=path,
                        line=_line_of(text, reference),
                        snippet=_snippet(text, reference),
                    ),
                    metadata={**metadata, "path": reference, "what": reference},
                )
            )
        return signals

    # -- helpers -----------------------------------------------------------

    def _line_matches(
        self,
        path: Path,
        haystack: str,
        pattern: re.Pattern[str],
        kind: SignalKind,
        metadata: dict[str, str],
        line_source: str | None = None,
    ) -> list[Signal]:
        source = line_source if line_source is not None else haystack
        signals: list[Signal] = []
        seen: set[str] = set()
        for found in pattern.finditer(haystack):
            token = found.group(0).strip()
            if token in seen:
                continue
            seen.add(token)
            signals.append(
                Signal(
                    kind=kind,
                    location=Location(
                        path=path,
                        line=_line_of(source, token),
                        snippet=_snippet(source, token),
                    ),
                    metadata={**metadata, "match": token[:120], "what": token[:120]},
                )
            )
        return signals

    @staticmethod
    def _signal(kind: SignalKind, location: Location, metadata: dict[str, str]) -> Signal:
        return Signal(kind=kind, location=location, metadata=metadata)

    @staticmethod
    def _paths_in(text: str) -> list[str]:
        seen: dict[str, None] = {}
        for found in _PATH_RE.finditer(text):
            candidate = found.group("path")
            if "://" in candidate or candidate.startswith("-"):
                continue
            seen[candidate] = None
        return list(seen)


def _phase_for(kind: str) -> str:
    return {
        "make": "build",
        "cmake": "configure",
        "autoconf": "configure",
        "autoconf-m4": "configure",
        "cargo-build": "build",
        "node-gyp": "build",
        "docker": "image build",
    }.get(kind, "install")


def _recipe_lines(text: str) -> str:
    """Makefile recipe bodies -- the tab-indented lines that actually run.

    Variable definitions and comments are excluded so that ``CC=gcc`` and a
    ``# curl ...`` note do not register as build activity.
    """
    lines = text.splitlines()
    if not any(line.startswith("\t") for line in lines):
        return "\n".join(line for line in lines if not line.lstrip().startswith("#"))
    return "\n".join(line for line in lines if line.startswith("\t"))


def _line_of(text: str, token: str) -> int:
    index = text.find(token)
    return text.count("\n", 0, index) + 1 if index >= 0 else 1


def _snippet(text: str, token: str) -> str:
    index = text.find(token)
    if index < 0:
        return ""
    start = text.rfind("\n", 0, index) + 1
    end = text.find("\n", index)
    return text[start : end if end >= 0 else len(text)].strip()
