"""Intra-procedural data flow: does this literal reach that sink?

A high-entropy string is not interesting. ``eval`` is not interesting. A
high-entropy string that reaches ``eval`` through a base64 decode is the whole
point -- it is the PRD's FOR-001, and it is what separates this scanner from a
grep for dangerous function names.

**Scope, stated plainly.** Tree-sitter produces concrete syntax trees with no
symbol resolution and no scope information, so this is not a semantic analysis.
What it does:

* resolves local and module-level variable definitions within a single file
* honours function boundaries, so a local in one function is invisible in another
* follows assignment chains up to ``MAX_DEPTH`` hops
* annotates hops that pass through a known decoder

What it does not do: cross files, cross function calls, track aliases, reason
about attributes or containers, or understand control flow. A determined
attacker can evade it by passing the payload through a function argument. It
catches what real-world install-script malware actually does, which is
overwhelmingly the straight-line form above.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ..models import Location, TraceStep
from .entropy import MIN_PAYLOAD_LENGTH, StringProfile, profile_string
from .signatures import (
    DECODER_KINDS,
    IDENTIFIER_NODE_TYPE,
    LANGUAGE_FAMILY,
    STRING_CONTENT_TYPES,
    STRING_NODE_TYPES,
    match_signature,
)

if TYPE_CHECKING:  # pragma: no cover
    import tree_sitter as ts

    from ..parser.registry import ParsedFile

MAX_DEPTH = 8
"""Assignment hops followed before giving up.

Deliberately low. Real payload plumbing is two or three hops; a forty-link chain
is either generated code or an attempt to exhaust the analyser, and neither
deserves the time."""

MAX_FUNCTION_SPANS = 5000
"""Above this, scope resolution falls back to file scope.

Minified bundles define tens of thousands of functions, and precise scoping for
them costs more than it is worth -- they are flagged as minified anyway."""


@dataclass(frozen=True)
class Definition:
    """One assignment: ``name`` takes the value of ``value`` at ``line``."""

    name: str
    value: ts.Node
    assign: ts.Node
    scope_start: int
    scope_end: int
    line: int

    @property
    def scope_size(self) -> int:
        return self.scope_end - self.scope_start

    def in_scope(self, position: int) -> bool:
        return self.scope_start <= position <= self.scope_end


@dataclass
class TaintPath:
    """A literal that reaches a sink, and the route it took."""

    source: ts.Node
    source_profile: StringProfile
    sink: ts.Node
    steps: list[TraceStep] = field(default_factory=list)
    through_decoder: bool = False
    decoders: list[str] = field(default_factory=list)


class DataFlowAnalyzer:
    """Answers "which string literals reach this call?" for one parsed file."""

    def __init__(self, parsed: ParsedFile) -> None:
        self.parsed = parsed
        self.language = parsed.language
        self.family = LANGUAGE_FAMILY.get(parsed.language, parsed.language)
        self._string_types = STRING_NODE_TYPES.get(self.family, frozenset())
        self._function_spans = self._collect_function_spans()
        self._definitions = self._collect_definitions()

    # -- construction ------------------------------------------------------

    def _collect_function_spans(self) -> list[tuple[int, int]]:
        spans = [
            (m["function"][0].start_byte, m["function"][0].end_byte)
            for m in self.parsed.matches("functions")
            if m.get("function")
        ]
        return [] if len(spans) > MAX_FUNCTION_SPANS else spans

    def _scope_of(self, node: ts.Node) -> tuple[int, int]:
        """The innermost function containing ``node``, else the whole file."""
        best: tuple[int, int] | None = None
        for start, end in self._function_spans:
            contains = start <= node.start_byte and node.end_byte <= end
            if contains and (best is None or (end - start) < (best[1] - best[0])):
                best = (start, end)
        return best if best is not None else (0, len(self.parsed.source))

    def _collect_definitions(self) -> dict[str, list[Definition]]:
        definitions: dict[str, list[Definition]] = {}

        # Object-like C macros. Full macro *expansion* needs a preprocessor and
        # is out of scope, but `#define FIXTURE "tests/blob.dat"` is a
        # definition by any reading, and following it is what lets the
        # correlation engine see through `fopen(FIXTURE, "rb")`.
        for match in self.parsed.matches("macros"):
            names, values, macros = match.get("name"), match.get("value"), match.get("macro")
            if not names or not values or not macros:
                continue
            name = self.parsed.text(names[0])
            definitions.setdefault(name, []).append(
                Definition(
                    name=name,
                    value=values[0],
                    assign=macros[0],
                    scope_start=0,
                    scope_end=len(self.parsed.source),
                    line=self.parsed.line_of(macros[0]),
                )
            )

        for match in self.parsed.matches("assignments"):
            targets, values, assigns = (
                match.get("target"),
                match.get("value"),
                match.get("assign"),
            )
            if not targets or not values or not assigns:
                continue
            assign = assigns[0]
            scope_start, scope_end = self._scope_of(assign)
            name = self.parsed.text(targets[0])
            definitions.setdefault(name, []).append(
                Definition(
                    name=name,
                    value=values[0],
                    assign=assign,
                    scope_start=scope_start,
                    scope_end=scope_end,
                    line=self.parsed.line_of(assign),
                )
            )
        return definitions

    # -- resolution --------------------------------------------------------

    def resolve(self, name: str, position: int) -> Definition | None:
        """The definition of ``name`` visible at byte ``position``.

        Innermost scope wins, so a local shadows a module-level name; among
        equals the latest definition before the use wins, so reassignment is
        respected.
        """
        candidates = [
            d
            for d in self._definitions.get(name, [])
            if d.assign.start_byte < position and d.in_scope(position)
        ]
        if not candidates:
            return None
        return min(candidates, key=lambda d: (d.scope_size, -d.assign.start_byte))

    # -- traversal ---------------------------------------------------------

    def _descendants(self, node: ts.Node, types: frozenset[str] | str) -> list[ts.Node]:
        wanted = {types} if isinstance(types, str) else types
        found: list[ts.Node] = []
        stack = [node]
        while stack:
            current = stack.pop()
            if current.type in wanted:
                found.append(current)
                continue  # a nested string inside a string is not a separate source
            stack.extend(reversed(current.children))
        return found

    def _literal_text(self, node: ts.Node) -> str:
        """The content of a string literal, without its quotes or prefix."""
        contents = [c for c in node.children if c.type in STRING_CONTENT_TYPES]
        if contents:
            return "".join(self.parsed.text(c) for c in contents)
        raw = self.parsed.text(node)
        return raw.strip("bruBRUfF").strip("\"'`")

    def literal_arguments(self, call: ts.Node, max_depth: int = 3) -> list[str]:
        """String literals reaching ``call``'s arguments, however indirectly.

        Unlike ``paths_into`` this applies no length floor: a file path is a
        short string, and resolving it is the whole point. Used to answer "which
        file does this ``open()`` actually read" when the answer is behind a
        constant or a macro.
        """
        arguments = call.child_by_field_name("arguments")
        if arguments is None:
            return []
        found: list[str] = []
        for literal in self._descendants(arguments, self._string_types):
            found.append(self._literal_text(literal))
        for identifier in self._descendants(arguments, IDENTIFIER_NODE_TYPE):
            definition = self.resolve(self.parsed.text(identifier), identifier.start_byte)
            if definition is None:
                continue
            found.extend(self._literals_under(definition.value, max_depth))
        return [text for text in dict.fromkeys(found) if text]

    def _literals_under(self, node: ts.Node, depth: int) -> list[str]:
        if depth <= 0:
            return []
        literals = [self._literal_text(n) for n in self._descendants(node, self._string_types)]
        if literals:
            return literals
        # A macro body is a `preproc_arg` holding raw text, not a parsed string.
        raw = self.parsed.text(node).strip()
        if raw.startswith(('"', "'")) and raw.endswith(('"', "'")) and len(raw) > 1:
            return [raw[1:-1]]
        return []

    def _decoders_in(self, node: ts.Node) -> list[str]:
        """Names of known decoders called anywhere inside ``node``."""
        found: list[str] = []
        for call in self._descendants(node, frozenset({"call", "call_expression"})):
            callee = call.child_by_field_name("function")
            if callee is None:
                continue
            text = self.parsed.text(callee)
            if match_signature(text, self.language, DECODER_KINDS):
                found.append(text)
        return found

    def paths_into(
        self, call: ts.Node, min_source_length: int = MIN_PAYLOAD_LENGTH
    ) -> list[TaintPath]:
        """Every string literal of consequence that reaches ``call``'s arguments.

        Literals shorter than ``min_source_length`` are dropped. They are not
        merely uninteresting -- they are unjudgeable, since entropy over a short
        string says nothing -- and they are abundant: ``Buffer.from(raw,
        'base64')`` puts the literal ``'base64'`` on the path to the sink, and
        reporting it would bury the payload it decodes.

        The consequence is that a short plaintext command reaching ``exec`` is
        not reported *here*. The sink itself still is, by the obfuscation
        engine; this analyser exists to find concealment, not injection.
        """
        arguments = call.child_by_field_name("arguments")
        if arguments is None:
            return []
        paths: list[TaintPath] = []
        for literal, hops, decoders in self._explore(arguments, 0, set()):
            path = self._build_path(literal, call, hops, decoders)
            if path.source_profile.length >= min_source_length:
                paths.append(path)
        return paths

    def _explore(
        self, node: ts.Node, depth: int, visited: set[tuple[str, int]]
    ) -> list[tuple[ts.Node, list[Definition], list[str]]]:
        """Reachable literals from ``node``, with the definitions traversed."""
        if depth > MAX_DEPTH:
            return []

        results: list[tuple[ts.Node, list[Definition], list[str]]] = []
        decoders = self._decoders_in(node)

        for literal in self._descendants(node, self._string_types):
            results.append((literal, [], list(decoders)))

        for identifier in self._descendants(node, IDENTIFIER_NODE_TYPE):
            name = self.parsed.text(identifier)
            definition = self.resolve(name, identifier.start_byte)
            if definition is None:
                continue
            key = (name, definition.assign.start_byte)
            if key in visited:
                continue
            for literal, hops, inner in self._explore(definition.value, depth + 1, visited | {key}):
                results.append((literal, [definition, *hops], decoders + inner))
        return results

    def _build_path(
        self,
        literal: ts.Node,
        sink: ts.Node,
        hops: list[Definition],
        decoders: list[str],
    ) -> TaintPath:
        profile = profile_string(self._literal_text(literal))
        literal_line = self.parsed.line_of(literal)

        steps = [
            TraceStep(
                location=self.parsed.location(literal),
                description=f"string literal (length {profile.length}, "
                f"entropy {profile.entropy:.2f}, {profile.alphabet.value})",
                snippet=self.parsed.source_line(literal_line),
            )
        ]
        for definition in reversed(hops):
            if definition.line == literal_line:
                continue  # the assignment that holds the literal, already shown
            hop_decoders = self._decoders_in(definition.value)
            what = f"decoded via {', '.join(hop_decoders)}" if hop_decoders else "assigned"
            steps.append(
                TraceStep(
                    location=Location(
                        path=self.parsed.path,
                        line=definition.line,
                        snippet=self.parsed.source_line(definition.line),
                    ),
                    description=f"{what} into '{definition.name}'",
                )
            )

        sink_line = self.parsed.line_of(sink)
        callee = sink.child_by_field_name("function") or sink.child_by_field_name("constructor")
        unique_decoders = list(dict.fromkeys(decoders))
        sink_name = self.parsed.text(callee) if callee else "sink"

        # A decoder applied inline in the sink's own arguments -- `exec(
        # b64decode(BLOB))` -- produces no intermediate assignment to hang the
        # annotation on, so it belongs on the sink step itself.
        already_described = any("decoded via" in step.description for step in steps)
        prefix = (
            f"decoded via {', '.join(unique_decoders)}, "
            if unique_decoders and not already_described
            else ""
        )
        steps.append(
            TraceStep(
                location=self.parsed.location(sink),
                description=f"{prefix}reaches {sink_name}()",
                snippet=self.parsed.source_line(sink_line),
            )
        )

        return TaintPath(
            source=literal,
            source_profile=profile,
            sink=sink,
            steps=steps,
            through_decoder=bool(unique_decoders),
            decoders=unique_decoders,
        )
