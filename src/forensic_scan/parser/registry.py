"""Tree-sitter access, wrapped so engines never touch the raw API.

Engines ask for *named query kinds* ("strings", "calls", "assignments") rather
than writing queries inline. The queries live in ``queries/<language>/<kind>.scm``
so that adding a language is a matter of dropping in a directory of ``.scm``
files, and so that a contributor can improve a detector without reading Python.

Parsing is deliberately failure-tolerant: tree-sitter produces a usable tree for
broken input, and a file that cannot be parsed at all is downgraded to
byte-level analysis rather than aborting the scan. Obfuscated code is often
syntactically odd, so giving up on a hard parse would lose exactly the files
worth looking at.
"""

from __future__ import annotations

import functools
from dataclasses import dataclass
from pathlib import Path

import tree_sitter as ts
from tree_sitter_language_pack import get_language, get_parser

from ..models import Location

QUERIES_DIR = Path(__file__).parent / "queries"

QUERY_KINDS: tuple[str, ...] = (
    "strings",
    "calls",
    "identifiers",
    "functions",
    "assignments",
    "imports",
    "bitwise",
    "loops",
    "arrays",
    "macros",
)

# Grammars whose node types match another language's queries closely enough to
# share them. TypeScript is a superset of JavaScript for everything we capture.
QUERY_ALIASES: dict[str, str] = {
    "typescript": "javascript",
    "tsx": "javascript",
}

SUPPORTED_LANGUAGES: frozenset[str] = frozenset({"python", "javascript", "typescript", "tsx", "c"})

Captures = dict[str, list[ts.Node]]


@dataclass
class ParsedFile:
    """A parsed source file plus the query access engines need."""

    path: Path
    language: str
    source: bytes
    tree: ts.Tree
    _registry: ParserRegistry
    _lines: list[bytes] | None = None

    @property
    def root(self) -> ts.Node:
        return self.tree.root_node

    @property
    def has_error(self) -> bool:
        return self.root.has_error

    def text(self, node: ts.Node) -> str:
        return self.source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")

    def raw(self, node: ts.Node) -> bytes:
        return self.source[node.start_byte : node.end_byte]

    def line_of(self, node: ts.Node) -> int:
        return node.start_point[0] + 1

    def source_line(self, line: int) -> str:
        """One 1-indexed source line, for report snippets.

        The split is cached: every signal asks for its own line, so re-splitting
        the whole file each time made snippet lookup cost O(file x signals).
        """
        if self._lines is None:
            self._lines = self.source.split(b"\n")
        if 1 <= line <= len(self._lines):
            return self._lines[line - 1].decode("utf-8", errors="replace").strip()
        return ""

    def location(self, node: ts.Node) -> Location:
        line = self.line_of(node)
        return Location(
            path=self.path,
            line=line,
            end_line=node.end_point[0] + 1,
            column=node.start_point[1] + 1,
            byte_start=node.start_byte,
            byte_end=node.end_byte,
            snippet=self.source_line(line),
        )

    def captures(self, kind: str, node: ts.Node | None = None) -> Captures:
        """All captures for a query kind, keyed by capture name.

        Returns ``{}`` when the language has no query of that kind -- only C has
        macros, and asking Python for them is a legitimate no-op, not an error.
        """
        query = self._registry.query(self.language, kind)
        if query is None:
            return {}
        cursor = ts.QueryCursor(query)
        return dict(cursor.captures(node or self.root))

    def matches(self, kind: str, node: ts.Node | None = None) -> list[Captures]:
        """Captures grouped per match, for queries where structure matters.

        ``assignments`` needs target and value paired; ``captures`` would flatten
        them into two unrelated lists.
        """
        query = self._registry.query(self.language, kind)
        if query is None:
            return []
        cursor = ts.QueryCursor(query)
        return [dict(caps) for _, caps in cursor.matches(node or self.root)]

    def enclosing_function(self, node: ts.Node) -> Captures | None:
        """The innermost function definition containing ``node``, if any.

        Data flow in v1 is intra-procedural, so this is what bounds it.
        """
        best: Captures | None = None
        best_span = None
        for match in self.matches("functions"):
            fn = match.get("function")
            if not fn:
                continue
            candidate = fn[0]
            if candidate.start_byte <= node.start_byte and node.end_byte <= candidate.end_byte:
                span = candidate.end_byte - candidate.start_byte
                if best_span is None or span < best_span:
                    best, best_span = match, span
        return best


class GrammarUnavailable(RuntimeError):
    """A grammar the scan needs could not be loaded.

    Not a normal condition. `tree-sitter-language-pack` fetches grammars on
    first use and caches them, so this means an air-gapped or offline
    environment, a blocked proxy, or an unwarmed container image. A scanner that
    treats it as "no findings" is worse than one that crashes: it reports safety
    it did not establish.
    """


class ParserRegistry:
    """Lazily loads grammars and compiles queries, caching both."""

    def __init__(self) -> None:
        self._parsers: dict[str, ts.Parser] = {}
        self._languages: dict[str, ts.Language] = {}
        self.grammar_errors: dict[str, str] = {}
        """Languages that failed to load, and why. Checked by the scan preflight."""

    def supports(self, language: str | None) -> bool:
        return language is not None and language in SUPPORTED_LANGUAGES

    def ensure(self, language: str) -> bool:
        """Load a grammar now, recording why if it cannot be loaded.

        Called before analysis rather than during it, so that a missing grammar
        is reported as a scan failure instead of silently yielding an empty
        result for every file in that language.
        """
        if not self.supports(language):
            return False
        return self._parser(language) is not None and self._language(language) is not None

    def _language(self, language: str) -> ts.Language | None:
        if language not in self._languages:
            try:
                self._languages[language] = get_language(language)
            except Exception as exc:
                self.grammar_errors[language] = f"{type(exc).__name__}: {exc}"
                return None
        return self._languages[language]

    def _parser(self, language: str) -> ts.Parser | None:
        if language not in self._parsers:
            try:
                self._parsers[language] = get_parser(language)
            except Exception as exc:
                self.grammar_errors[language] = f"{type(exc).__name__}: {exc}"
                return None
        return self._parsers[language]

    @functools.lru_cache(maxsize=256)  # noqa: B019 - registry is process-scoped
    def query(self, language: str, kind: str) -> ts.Query | None:
        """Compile ``queries/<language>/<kind>.scm``, or ``None`` if absent."""
        if kind not in QUERY_KINDS:
            raise KeyError(f"unknown query kind: {kind!r}; expected one of {QUERY_KINDS}")
        source_dir = QUERIES_DIR / QUERY_ALIASES.get(language, language)
        path = source_dir / f"{kind}.scm"
        if not path.is_file():
            return None
        lang = self._language(language)
        if lang is None:
            return None
        try:
            query: ts.Query = ts.Query(lang, path.read_text(encoding="utf-8"))
            return query
        except Exception as exc:  # a broken .scm is a bug in this repo, not user input
            raise ValueError(f"invalid query {path}: {exc}") from exc

    def parse(self, path: Path, source: bytes, language: str) -> ParsedFile | None:
        """Parse ``source``. Returns ``None`` only if the grammar is unavailable."""
        if not self.supports(language):
            return None
        parser = self._parser(language)
        if parser is None:
            return None
        try:
            tree = parser.parse(source)
        except Exception:
            return None
        return ParsedFile(path=path, language=language, source=source, tree=tree, _registry=self)
