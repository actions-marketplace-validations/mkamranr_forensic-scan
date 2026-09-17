"""The names that matter, as data.

Every dynamic-execution sink, decoder and dynamic-import function the scanner
knows about lives in this one table. Keeping it declarative means a contributor
can teach the scanner a new attack surface by adding a row, and means the same
definitions serve both the obfuscation engine (which finds sinks) and the data
flow analyser (which traces literals into them).

Match modes exist because of false positives, and one case in particular: pandas
``DataFrame.eval`` is extremely common in legitimate Python, so ``eval`` is
matched as a bare name only. A pattern that would fire on ordinary library
method calls is worse than no pattern.
"""

from __future__ import annotations

import functools
from dataclasses import dataclass
from enum import Enum

from ..models import SignalKind

PYTHON = "python"
JAVASCRIPT = "javascript"
C = "c"

# typescript and tsx share JavaScript's sinks.
LANGUAGE_FAMILY: dict[str, str] = {
    "python": PYTHON,
    "javascript": JAVASCRIPT,
    "typescript": JAVASCRIPT,
    "tsx": JAVASCRIPT,
    "c": C,
}

STRING_NODE_TYPES: dict[str, frozenset[str]] = {
    PYTHON: frozenset({"string", "concatenated_string"}),
    JAVASCRIPT: frozenset({"string", "template_string"}),
    C: frozenset({"string_literal", "concatenated_string"}),
}

STRING_CONTENT_TYPES = frozenset({"string_content", "string_fragment"})

IDENTIFIER_NODE_TYPE = "identifier"
"""Deliberately excludes ``property_identifier`` and ``field_identifier``:
``obj.decoded`` is an attribute access, not a reference to a local named
``decoded``."""


class MatchMode(str, Enum):
    BARE = "bare"
    """Exact match only. For names that are also common library methods."""
    MEMBER = "member"
    """Matches the bare name or any dotted access ending in it."""


@dataclass(frozen=True)
class Signature:
    """One callable worth noticing."""

    pattern: str
    kind: SignalKind
    language: str
    note: str
    mode: MatchMode = MatchMode.MEMBER
    severity_hint: str = "medium"

    def matches(self, callee: str) -> bool:
        if callee == self.pattern:
            return True
        if self.mode is MatchMode.BARE:
            return False
        return callee.endswith("." + self.pattern)


def _sig(
    pattern: str,
    kind: SignalKind,
    language: str,
    note: str,
    mode: MatchMode = MatchMode.MEMBER,
    severity_hint: str = "medium",
) -> Signature:
    return Signature(pattern, kind, language, note, mode, severity_hint)


EXEC = SignalKind.DYNAMIC_EXEC_SINK
DECODE = SignalKind.DECODE_CALL
DYNIMPORT = SignalKind.DYNAMIC_IMPORT
DYNSYM = SignalKind.DYNAMIC_SYMBOL_RESOLUTION
READ = SignalKind.FILE_READ

SIGNATURES: tuple[Signature, ...] = (
    # ---- Python: execution ----
    _sig("eval", EXEC, PYTHON, "evaluates an expression at runtime", MatchMode.BARE, "high"),
    _sig("exec", EXEC, PYTHON, "executes arbitrary code at runtime", MatchMode.BARE, "high"),
    _sig("compile", EXEC, PYTHON, "compiles source to a code object", MatchMode.BARE),
    _sig("os.system", EXEC, PYTHON, "runs a shell command", severity_hint="high"),
    _sig("os.popen", EXEC, PYTHON, "runs a shell command"),
    _sig("subprocess.call", EXEC, PYTHON, "spawns a process"),
    _sig("subprocess.run", EXEC, PYTHON, "spawns a process"),
    _sig("subprocess.Popen", EXEC, PYTHON, "spawns a process"),
    _sig("subprocess.check_output", EXEC, PYTHON, "spawns a process"),
    _sig("subprocess.check_call", EXEC, PYTHON, "spawns a process"),
    _sig("subprocess.getoutput", EXEC, PYTHON, "runs a shell command"),
    _sig("subprocess.getstatusoutput", EXEC, PYTHON, "runs a shell command"),
    _sig("os.execv", EXEC, PYTHON, "replaces the process image"),
    _sig("os.execve", EXEC, PYTHON, "replaces the process image"),
    _sig("os.spawnv", EXEC, PYTHON, "spawns a process"),
    _sig("marshal.loads", EXEC, PYTHON, "loads a code object from bytes", severity_hint="high"),
    _sig("pickle.loads", EXEC, PYTHON, "deserialises arbitrary objects", severity_hint="high"),
    _sig(
        "types.FunctionType",
        EXEC,
        PYTHON,
        "builds a function from a code object",
        severity_hint="high",
    ),
    _sig("ctypes.CDLL", EXEC, PYTHON, "loads a native library", severity_hint="high"),
    _sig("ctypes.string_at", EXEC, PYTHON, "reads arbitrary memory", severity_hint="high"),
    _sig("ctypes.memmove", EXEC, PYTHON, "writes arbitrary memory", severity_hint="high"),
    # ---- Python: decoding ----
    _sig("b64decode", DECODE, PYTHON, "base64 decode"),
    _sig("b32decode", DECODE, PYTHON, "base32 decode"),
    _sig("b16decode", DECODE, PYTHON, "base16 decode"),
    _sig("a85decode", DECODE, PYTHON, "ascii85 decode"),
    _sig("urlsafe_b64decode", DECODE, PYTHON, "base64 decode"),
    _sig("codecs.decode", DECODE, PYTHON, "generic codec decode"),
    _sig("zlib.decompress", DECODE, PYTHON, "zlib decompress"),
    _sig("gzip.decompress", DECODE, PYTHON, "gzip decompress"),
    _sig("bz2.decompress", DECODE, PYTHON, "bzip2 decompress"),
    _sig("lzma.decompress", DECODE, PYTHON, "lzma decompress"),
    _sig("binascii.unhexlify", DECODE, PYTHON, "hex decode"),
    _sig("binascii.a2b_base64", DECODE, PYTHON, "base64 decode"),
    _sig("bytes.fromhex", DECODE, PYTHON, "hex decode"),
    # ---- Python: dynamic resolution ----
    _sig("__import__", DYNIMPORT, PYTHON, "imports a module named at runtime", MatchMode.BARE),
    _sig("importlib.import_module", DYNIMPORT, PYTHON, "imports a module named at runtime"),
    # `getattr`, `globals` and `vars` are deliberately absent. They occur 1362
    # times in the Python standard library alone -- they are how the language is
    # written, not a sign of anything. A signal that fires that often is not a
    # signal, and shipping it would bury everything that matters.
    # ---- JavaScript: execution ----
    _sig("eval", EXEC, JAVASCRIPT, "evaluates source at runtime", MatchMode.BARE, "high"),
    _sig("Function", EXEC, JAVASCRIPT, "builds a function from a string", MatchMode.BARE, "high"),
    _sig("vm.runInThisContext", EXEC, JAVASCRIPT, "evaluates source in a VM", severity_hint="high"),
    _sig("vm.runInNewContext", EXEC, JAVASCRIPT, "evaluates source in a VM", severity_hint="high"),
    _sig("vm.runInContext", EXEC, JAVASCRIPT, "evaluates source in a VM", severity_hint="high"),
    _sig("vm.compileFunction", EXEC, JAVASCRIPT, "compiles a function from a string"),
    _sig("child_process.exec", EXEC, JAVASCRIPT, "runs a shell command", severity_hint="high"),
    _sig("child_process.execSync", EXEC, JAVASCRIPT, "runs a shell command", severity_hint="high"),
    _sig("child_process.spawn", EXEC, JAVASCRIPT, "spawns a process"),
    _sig("execSync", EXEC, JAVASCRIPT, "runs a shell command", MatchMode.BARE, "high"),
    _sig("spawnSync", EXEC, JAVASCRIPT, "spawns a process", MatchMode.BARE),
    # ---- JavaScript: decoding ----
    _sig("atob", DECODE, JAVASCRIPT, "base64 decode", MatchMode.BARE),
    _sig("Buffer.from", DECODE, JAVASCRIPT, "decodes bytes from a string encoding"),
    _sig("zlib.gunzipSync", DECODE, JAVASCRIPT, "gzip decompress"),
    _sig("zlib.inflateSync", DECODE, JAVASCRIPT, "zlib decompress"),
    _sig("zlib.brotliDecompressSync", DECODE, JAVASCRIPT, "brotli decompress"),
    _sig("decodeURIComponent", DECODE, JAVASCRIPT, "percent decode", MatchMode.BARE),
    _sig("unescape", DECODE, JAVASCRIPT, "legacy percent decode", MatchMode.BARE),
    _sig("String.fromCharCode", DECODE, JAVASCRIPT, "builds a string from character codes"),
    _sig("fromCharCode", DECODE, JAVASCRIPT, "builds a string from character codes"),
    # ---- JavaScript: dynamic resolution ----
    _sig("require", DYNIMPORT, JAVASCRIPT, "loads a module named at runtime", MatchMode.BARE),
    _sig("import", DYNIMPORT, JAVASCRIPT, "loads a module named at runtime", MatchMode.BARE),
    # ---- C: execution ----
    _sig("system", EXEC, C, "runs a shell command", MatchMode.BARE, "high"),
    _sig("popen", EXEC, C, "runs a shell command", MatchMode.BARE, "high"),
    _sig("execl", EXEC, C, "replaces the process image", MatchMode.BARE),
    _sig("execv", EXEC, C, "replaces the process image", MatchMode.BARE),
    _sig("execve", EXEC, C, "replaces the process image", MatchMode.BARE),
    _sig("execvp", EXEC, C, "replaces the process image", MatchMode.BARE),
    _sig(
        "mprotect",
        EXEC,
        C,
        "changes page permissions to make data executable",
        severity_hint="high",
    ),
    # ---- C: dynamic resolution ----
    _sig("dlopen", DYNIMPORT, C, "loads a shared object at runtime", MatchMode.BARE, "high"),
    _sig("dlsym", DYNSYM, C, "resolves a symbol named at runtime", MatchMode.BARE, "high"),
    _sig("dlmopen", DYNIMPORT, C, "loads a shared object at runtime", MatchMode.BARE, "high"),
    _sig("GetProcAddress", DYNSYM, C, "resolves a symbol named at runtime", MatchMode.BARE),
    _sig("LoadLibraryA", DYNIMPORT, C, "loads a DLL at runtime", MatchMode.BARE),
    # ---- File reads ----
    # Not suspicious in themselves. They exist so the correlation engine can ask
    # the question that matters: does anything actually *read* that opaque
    # fixture, and what does it do with the bytes?
    _sig("open", READ, PYTHON, "opens a file", MatchMode.BARE, "info"),
    _sig("io.open", READ, PYTHON, "opens a file", severity_hint="info"),
    _sig("read_bytes", READ, PYTHON, "reads a file", severity_hint="info"),
    _sig("read_text", READ, PYTHON, "reads a file", severity_hint="info"),
    _sig("tarfile.open", READ, PYTHON, "opens a tar archive", severity_hint="info"),
    _sig("zipfile.ZipFile", READ, PYTHON, "opens a zip archive", severity_hint="info"),
    _sig("gzip.open", READ, PYTHON, "opens a gzip stream", severity_hint="info"),
    _sig("lzma.open", READ, PYTHON, "opens an xz stream", severity_hint="info"),
    _sig("bz2.open", READ, PYTHON, "opens a bzip2 stream", severity_hint="info"),
    _sig("readFileSync", READ, JAVASCRIPT, "reads a file", severity_hint="info"),
    _sig("readFile", READ, JAVASCRIPT, "reads a file", severity_hint="info"),
    _sig("createReadStream", READ, JAVASCRIPT, "opens a file stream", severity_hint="info"),
    _sig("fopen", READ, C, "opens a file", MatchMode.BARE, "info"),
    _sig("freopen", READ, C, "opens a file", MatchMode.BARE, "info"),
    _sig("mmap", READ, C, "maps a file into memory", MatchMode.BARE, "info"),
)


@functools.cache
def signatures_for(language: str) -> tuple[Signature, ...]:
    family = LANGUAGE_FAMILY.get(language)
    if family is None:
        return ()
    return tuple(s for s in SIGNATURES if s.language == family)


@functools.cache
def _index(
    language: str,
) -> tuple[dict[str, tuple[Signature, ...]], dict[str, tuple[Signature, ...]]]:
    """Two lookup tables, built once per language.

    Scanning the whole table per call cost 25 seconds on a 2,267-file scan --
    308,883 lookups against roughly eighty signatures each. Almost every callee
    matches nothing, so the fix is to make "nothing" a dictionary miss:
    ``exact`` holds full patterns, ``tail`` groups member patterns by their last
    segment so ``foo.os.system`` only ever compares against signatures ending in
    ``system``.
    """
    exact: dict[str, list[Signature]] = {}
    tail: dict[str, list[Signature]] = {}
    for sig in signatures_for(language):
        exact.setdefault(sig.pattern, []).append(sig)
        if sig.mode is MatchMode.MEMBER:
            tail.setdefault(sig.pattern.rsplit(".", 1)[-1], []).append(sig)
    return (
        {k: tuple(v) for k, v in exact.items()},
        {k: tuple(v) for k, v in tail.items()},
    )


def match_signature(
    callee: str, language: str, kinds: frozenset[SignalKind] | None = None
) -> Signature | None:
    """The signature matching ``callee``, or ``None``. Exact match wins."""
    if LANGUAGE_FAMILY.get(language) is None:
        return None
    exact, tail = _index(language)

    for sig in exact.get(callee, ()):
        if kinds is None or sig.kind in kinds:
            return sig
    for sig in tail.get(callee.rsplit(".", 1)[-1], ()):
        if (kinds is None or sig.kind in kinds) and callee.endswith("." + sig.pattern):
            return sig
    return None


DECODER_KINDS = frozenset({SignalKind.DECODE_CALL})
EXEC_KINDS = frozenset({SignalKind.DYNAMIC_EXEC_SINK})
READ_KINDS = frozenset({SignalKind.FILE_READ})
TRANSFORM_KINDS = frozenset(
    {SignalKind.DECODE_CALL, SignalKind.BITWISE_DECODE_LOOP, SignalKind.CHARCODE_CONSTRUCTION}
)
EXECUTION_KINDS = frozenset(
    {
        SignalKind.DYNAMIC_EXEC_SINK,
        SignalKind.DYNAMIC_IMPORT,
        SignalKind.DYNAMIC_SYMBOL_RESOLUTION,
    }
)
