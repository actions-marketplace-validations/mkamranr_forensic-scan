"""Module B -- dynamic execution and structural obfuscation.

Two families of detector live here.

*Named* detectors match calls against the signature table: ``eval``, ``dlopen``,
``Buffer.from``. These are cheap and precise, and on their own they are close to
worthless -- every large codebase calls something on that list for a good
reason. Their value is as endpoints for the data flow analyser.

*Structural* detectors look at shape rather than names: a loop that XORs a
buffer, an array of two hundred integers, identifiers that look machine-
generated. These survive renaming, which is the point -- an attacker can avoid
the word ``eval``, but concealment has a shape that is harder to hide.

Every threshold here is set where a legitimate construct stops and a suspicious
one starts, and the tests name the benign case each one protects:
``String.fromCharCode(10)`` is a newline, ``[255, 128, 0]`` is a colour, and
``flags & O_RDONLY`` is ordinary C.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING

from ..models import Location, Signal, SignalKind
from ..parser.registry import ParsedFile, ParserRegistry
from .dataflow import DataFlowAnalyzer
from .entropy import MIN_PAYLOAD_LENGTH, profile_string
from .signatures import (
    EXEC_KINDS,
    IDENTIFIER_NODE_TYPE,
    LANGUAGE_FAMILY,
    STRING_NODE_TYPES,
    match_signature,
)

if TYPE_CHECKING:  # pragma: no cover
    import tree_sitter as ts

MIN_CHARCODE_ARGUMENTS = 8
"""``String.fromCharCode(10)`` is a newline. Eight codes is a string."""

MIN_NUMERIC_ARRAY = 24
"""``[255, 128, 0]`` is a colour and ``[1, 2, 3, 4]`` is test data."""

MIN_CONCAT_CHAIN = 8
"""``"hello " + name + "!"`` is formatting. Eight segments is assembly."""

MIN_IDENTIFIERS_TO_JUDGE = 20
"""Below this, an identifier-naming verdict is noise."""

MANGLED_IDENTIFIER_RATIO = 0.3
"""Share of machine-generated-looking names before a file is called obfuscated."""

BITWISE_OPERATORS = frozenset({"^", "^=", ">>", "<<", ">>=", "<<=", "&", "|", "~", ">>>"})
DECODE_OPERATORS = frozenset({"^", "^="})
"""XOR only.

`&` and `|` are how flags are tested. Shifts are how numbers are packed --
`(hi << 8) | lo` appears in every binary format parser ever written. XOR over a
buffer is the one bitwise operation whose usual purpose is to make bytes
unreadable and then readable again."""

_MANGLED_RE = re.compile(
    r"""
    ^(
        _+0x[0-9a-fA-F]{3,}      # js-obfuscator: _0x3a2f
      | _{2,}[0-9a-fA-F]{4,}     # __deadbeef
      | [A-Za-z]?[0-9a-fA-F]{8,} # bare hex runs
      | [bcdfghjklmnpqrstvwxz]{5,}  # five consonants, no vowel: not a word
    )$
    """,
    re.VERBOSE,
)

_CALL_TYPES = frozenset({"call", "call_expression", "new_expression"})
_LOOP_TYPES = frozenset(
    {
        "for_statement",
        "while_statement",
        "do_statement",
        "for_in_statement",
        "for_of_statement",
        "list_comprehension",
        "generator_expression",
        "set_comprehension",
        "dictionary_comprehension",
    }
)
_NUMBER_TYPES = frozenset({"number", "integer", "number_literal", "float"})
_ASM_RE = re.compile(r"\b(__asm__|__asm|asm)\s*(volatile\s*)?[({]")

_MODE_STRINGS = frozenset(
    {
        "r",
        "w",
        "a",
        "rb",
        "wb",
        "ab",
        "r+",
        "w+",
        "a+",
        "rb+",
        "wb+",
        "utf-8",
        "utf8",
        "ascii",
        "latin-1",
        "base64",
        "hex",
        "binary",
    }
)


def _looks_like_path(text: str) -> bool:
    """Whether a literal plausibly names a file rather than a mode or encoding.

    ``open(path, "rb")`` puts two literals in reach; only one of them is a file.
    """
    if not text or len(text) > 512 or text in _MODE_STRINGS:
        return False
    return "/" in text or "\\" in text or "." in text


class ObfuscationEngine:
    """Finds dynamic execution and the structural residue of concealment."""

    def __init__(self, registry: ParserRegistry | None = None) -> None:
        self.registry = registry or ParserRegistry()

    def analyze(self, path: Path, source: bytes, language: str) -> list[Signal]:
        parsed = self.registry.parse(path, source, language)
        if parsed is None or not source:
            return []
        family = LANGUAGE_FAMILY.get(language)
        if family is None:
            return []

        signals: list[Signal] = []
        signals.extend(self._call_signals(parsed))
        signals.extend(self._literal_signals(parsed, family))
        signals.extend(self._charcode_signals(parsed, family))
        signals.extend(self._bitwise_loop_signals(parsed))
        signals.extend(self._identifier_signals(parsed))
        signals.extend(self._concat_chain_signals(parsed, family))
        signals.extend(self._inline_asm_signals(parsed, family))
        return signals

    # -- named detectors ---------------------------------------------------

    def _call_signals(self, parsed: ParsedFile) -> list[Signal]:
        """Signature matches, plus the taint paths that make them matter."""
        signals: list[Signal] = []
        flow: DataFlowAnalyzer | None = None
        callees = parsed.captures("calls").get("callee", [])

        for callee in callees:
            text = parsed.text(callee)
            signature = match_signature(text, parsed.language)
            if signature is None:
                continue
            call = callee.parent
            if call is None or call.type not in _CALL_TYPES:
                continue

            if signature.kind is SignalKind.FILE_READ:
                flow = flow or DataFlowAnalyzer(parsed)
                signals.extend(self._file_read_signal(parsed, flow, call, text))
            elif signature.kind is SignalKind.DYNAMIC_IMPORT:
                # `require('fs')` is not dynamic. Only the specialised check,
                # which inspects the argument, may emit for this kind.
                signals.extend(self._dynamic_import_signal(parsed, call, text))
            else:
                signals.append(
                    Signal(
                        kind=signature.kind,
                        location=parsed.location(callee),
                        features={"line": float(parsed.line_of(callee))},
                        metadata={
                            "sink": text,
                            "note": signature.note,
                            "severity_hint": signature.severity_hint,
                        },
                    )
                )

            if signature.kind in EXEC_KINDS:
                flow = flow or DataFlowAnalyzer(parsed)
                signals.extend(self._taint_signals(parsed, flow, call, text))
        return signals

    def _dynamic_import_signal(self, parsed: ParsedFile, call: ts.Node, text: str) -> list[Signal]:
        """A module name computed at runtime, as opposed to ``require('fs')``."""
        arguments = call.child_by_field_name("arguments")
        if arguments is None:
            return []
        string_types = STRING_NODE_TYPES.get(LANGUAGE_FAMILY.get(parsed.language, ""), frozenset())
        meaningful = [c for c in arguments.children if c.type not in {"(", ")", ","}]
        if meaningful and all(c.type in string_types for c in meaningful):
            return []  # a literal module name is not dynamic
        return [
            Signal(
                kind=SignalKind.DYNAMIC_IMPORT,
                location=parsed.location(call),
                metadata={"sink": text, "argument": parsed.text(arguments)[:120]},
            )
        ]

    def _file_read_signal(
        self, parsed: ParsedFile, flow: DataFlowAnalyzer, call: ts.Node, text: str
    ) -> list[Signal]:
        """A file read, with the path it names.

        The path is resolved through constants and C macros, because real code
        writes ``fopen(FIXTURE, "rb")`` rather than inlining the string. Without
        that resolution the correlation engine loses the link between a build
        script and the code that consumes what it names -- which is most of the
        value of having one.
        """
        candidates = flow.literal_arguments(call)
        paths = [c for c in candidates if _looks_like_path(c)]
        if not paths:
            return []
        return [
            Signal(
                kind=SignalKind.FILE_READ,
                location=parsed.location(call),
                metadata={"function": text, "path": paths[0]},
            )
        ]

    def _taint_signals(
        self, parsed: ParsedFile, flow: DataFlowAnalyzer, call: ts.Node, sink: str
    ) -> list[Signal]:
        signals = []
        for path in flow.paths_into(call):
            profile = path.source_profile
            signals.append(
                Signal(
                    kind=SignalKind.TAINT_FLOW,
                    location=parsed.location(call),
                    features={
                        "source_entropy": profile.entropy,
                        "source_length": float(profile.length),
                        "source_normalized_entropy": profile.normalized_entropy,
                        "source_looks_encoded": float(profile.looks_encoded),
                        "through_decoder": float(path.through_decoder),
                        "hops": float(len(path.steps)),
                    },
                    metadata={
                        "sink": sink,
                        "alphabet": profile.alphabet.value,
                        "decoders": ", ".join(path.decoders),
                        "source_line": str(path.steps[0].location.line),
                    },
                )
            )
            # The trace itself travels on the signal so the reporter can render
            # it without re-running the analysis.
            signals[-1].metadata["trace"] = " -> ".join(
                f"{s.location.line}: {s.description}" for s in path.steps
            )
        return signals

    # -- structural detectors ---------------------------------------------

    def _literal_signals(self, parsed: ParsedFile, family: str) -> list[Signal]:
        """String literals that look like encoded data rather than text."""
        signals = []
        for node in parsed.captures("strings").get("string", []):
            text = self._literal_text(parsed, node)
            # The length gate first: profiling every short literal in a
            # repository costs more than every other string check combined, and
            # a string under the gate is discarded by the next line anyway.
            if len(text.strip()) < MIN_PAYLOAD_LENGTH:
                continue
            profile = profile_string(text)
            if not profile.looks_encoded:
                continue
            signals.append(
                Signal(
                    kind=SignalKind.ENCODED_ALPHABET_STRING,
                    location=parsed.location(node),
                    features={
                        "entropy": profile.entropy,
                        "normalized_entropy": profile.normalized_entropy,
                        "length": float(profile.length),
                        "word_ratio": profile.word_ratio,
                    },
                    metadata={"alphabet": profile.alphabet.value},
                )
            )
        return signals

    def _charcode_signals(self, parsed: ParsedFile, family: str) -> list[Signal]:
        """Strings assembled from numbers instead of written as strings."""
        signals: list[Signal] = []

        for callee in parsed.captures("calls").get("callee", []):
            text = parsed.text(callee)
            if not (text.endswith("fromCharCode") or text in {"chr", "unichr"}):
                continue
            call = callee.parent
            arguments = call.child_by_field_name("arguments") if call else None
            values = self._numeric_values(parsed, arguments) if arguments else []
            # Explicit codes only. `chr(c)` inside a loop is how every
            # string-building loop in the language is written, and the payload
            # form of it is already covered by the numeric-array and
            # bitwise-loop detectors.
            if len(values) < MIN_CHARCODE_ARGUMENTS:
                continue
            signals.append(
                self._charcode_signal(
                    parsed.location(callee),
                    values,
                    form=f"{len(values)} arguments to {text}",
                )
            )

        for array in parsed.captures("arrays").get("array", []):
            values = self._numeric_values(parsed, array)
            if len(values) < MIN_NUMERIC_ARRAY:
                continue
            signals.append(
                self._charcode_signal(
                    parsed.location(array),
                    values,
                    form=f"a {len(values)}-element numeric array",
                )
            )
        return signals

    @staticmethod
    def _charcode_signal(location: Location, values: list[int], form: str) -> Signal:
        printable = sum(1 for v in values if 32 <= v <= 126 or v in (9, 10, 13))
        return Signal(
            kind=SignalKind.CHARCODE_CONSTRUCTION,
            location=location,
            features={
                "elements": float(len(values)),
                # The discriminator that separates a hidden string from a lookup
                # table. Character codes are printable ASCII almost by
                # definition; a CRC table is 32-bit words and a colour palette
                # is uniform over 0-255. Length alone cannot tell them apart.
                "printable_ratio": printable / len(values) if values else 0.0,
            },
            metadata={"form": form},
        )

    @staticmethod
    def _numeric_values(parsed: ParsedFile, node: ts.Node) -> list[int]:
        values: list[int] = []
        for child in node.children:
            if child.type not in _NUMBER_TYPES:
                continue
            try:
                values.append(int(parsed.text(child).rstrip("uUlL"), 0))
            except ValueError:
                continue
        return values

    def _bitwise_loop_signals(self, parsed: ParsedFile) -> list[Signal]:
        """XOR and shift arithmetic inside a loop -- the shape of a decoder.

        Restricted to XOR and shifts: ``&`` and ``|`` are how flags are tested,
        and including them would fire on most C ever written.
        """
        signals = []
        seen_loops: set[int] = set()
        for match in parsed.matches("bitwise"):
            operators, expressions = match.get("operator"), match.get("expression")
            if not operators or not expressions:
                continue
            if parsed.text(operators[0]) not in DECODE_OPERATORS:
                continue
            loop = self._enclosing_loop(expressions[0])
            if loop is None or loop.start_byte in seen_loops:
                continue
            seen_loops.add(loop.start_byte)
            signals.append(
                Signal(
                    kind=SignalKind.BITWISE_DECODE_LOOP,
                    location=parsed.location(expressions[0]),
                    features={
                        "loop_span_lines": float(loop.end_point[0] - loop.start_point[0] + 1)
                    },
                    metadata={
                        "operator": parsed.text(operators[0]),
                        "expression": parsed.text(expressions[0])[:120],
                    },
                )
            )
        return signals

    def _identifier_signals(self, parsed: ParsedFile) -> list[Signal]:
        """Names that look generated rather than chosen."""
        # One query, one key. This previously ran the query twice under two
        # spellings of the same capture name, doubling both the work and the
        # identifier counts the ratio is computed from.
        captures = parsed.captures("identifiers")
        unique = sorted({parsed.text(n) for n in captures.get(IDENTIFIER_NODE_TYPE, [])})
        if len(unique) < MIN_IDENTIFIERS_TO_JUDGE:
            return []
        mangled = [n for n in unique if _MANGLED_RE.match(n)]
        ratio = len(mangled) / len(unique)
        if ratio < MANGLED_IDENTIFIER_RATIO:
            return []
        return [
            Signal(
                kind=SignalKind.HIGH_ENTROPY_IDENTIFIERS,
                location=parsed.location(parsed.root),
                features={
                    "mangled_ratio": ratio,
                    "mangled_count": float(len(mangled)),
                    "identifier_count": float(len(unique)),
                },
                metadata={"examples": ", ".join(mangled[:5])},
            )
        ]

    def _concat_chain_signals(self, parsed: ParsedFile, family: str) -> list[Signal]:
        """Long ``+`` chains over string literals -- a string written sideways."""
        string_types = STRING_NODE_TYPES.get(family, frozenset())
        signals: list[Signal] = []
        seen: set[int] = set()
        for match in parsed.matches("bitwise"):
            operators, expressions = match.get("operator"), match.get("expression")
            if not operators or not expressions or parsed.text(operators[0]) != "+":
                continue
            root = self._concat_root(expressions[0])
            if root.start_byte in seen:
                continue
            seen.add(root.start_byte)
            segments = self._count_descendants(root, string_types)
            if segments < MIN_CONCAT_CHAIN:
                continue
            signals.append(
                Signal(
                    kind=SignalKind.STRING_CONCAT_CHAIN,
                    location=parsed.location(root),
                    features={"segments": float(segments)},
                    metadata={"preview": parsed.text(root)[:120]},
                )
            )
        return signals

    def _inline_asm_signals(self, parsed: ParsedFile, family: str) -> list[Signal]:
        if family != "c":
            return []
        signals = []
        text = parsed.source.decode("utf-8", errors="replace")
        for found in _ASM_RE.finditer(text):
            line = text.count("\n", 0, found.start()) + 1
            signals.append(
                Signal(
                    kind=SignalKind.INLINE_ASSEMBLY,
                    location=parsed.location(parsed.root).__class__(
                        path=parsed.path, line=line, snippet=parsed.source_line(line)
                    ),
                    metadata={"construct": found.group(0)},
                )
            )
        return signals

    # -- helpers -----------------------------------------------------------

    @staticmethod
    def _enclosing_loop(node: ts.Node) -> ts.Node | None:
        current = node.parent
        while current is not None:
            if current.type in _LOOP_TYPES:
                return current
            current = current.parent
        return None

    @staticmethod
    def _concat_root(node: ts.Node) -> ts.Node:
        """The outermost expression of a left-nested ``a + b + c`` chain."""
        current = node
        while current.parent is not None and current.parent.type == current.type:
            current = current.parent
        return current

    @staticmethod
    def _count_descendants(node: ts.Node, types: frozenset[str]) -> int:
        count, stack = 0, [node]
        while stack:
            current = stack.pop()
            if current.type in types:
                count += 1
                continue
            stack.extend(current.children)
        return count

    @staticmethod
    def _literal_text(parsed: ParsedFile, node: ts.Node) -> str:
        contents = [c for c in node.children if c.type in {"string_content", "string_fragment"}]
        if contents:
            return "".join(parsed.text(c) for c in contents)
        return parsed.text(node).strip("bruBRUfF").strip("\"'`")
