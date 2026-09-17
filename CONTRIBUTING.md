# Contributing

The most valuable contribution to this project is a **rule with two fixtures**.

## The two-fixture rule

Every new detection must arrive with:

1. a sample in `corpus/malicious/` that it catches, and
2. a sample in `corpus/benign/` that it must **not** catch.

The second one is the point. Detection rate is easy to inflate — flag everything
and it reaches 100%. The false-positive rate on a corpus of deliberately hard
benign code is the honest half, and it is the number that decides whether anyone
leaves this scanner switched on.

When you add a detector, ask yourself what legitimate construct most resembles
it, then write that construct down as a benign fixture. The existing ones were
found this way: a CRC-32 table looks exactly like a character-code payload until
you notice that character codes are printable ASCII and CRC words are not.

## Adding a rule without writing Python

Most detections are YAML. Add a file under `src/forensic_scan/rules/builtin/`:

```yaml
version: "1.0"
rules:
  - id: FOR-0XX
    name: Short noun phrase describing the finding
    severity: HIGH
    detail: "{what} was found during the {phase} phase"
    remediation: >-
      What the reader should do, in the imperative. Assume they have two
      minutes and a pull request to decide about.
    match:
      signal: build_shell_exec
      metadata:
        auto_run: {equals: "yes"}
```

Then:

```bash
uv run forensic-scan rules validate src/forensic_scan/rules/builtin/your-file.yml
uv run pytest tests/benchmark          # detection and false-positive gates
```

The full schema is in [`docs/rules.md`](docs/rules.md). Available signal kinds
come from `SignalKind` in `src/forensic_scan/models.py`; the schema rejects
unknown names with the valid list in the error.

## Adding a detector that needs Python

A new *signal* means touching an engine. The contract:

- Engines emit `Signal`s. They never decide anything and never produce a
  `Finding` — severity and phrasing belong in a rule.
- A signal carries **numeric features** and **string metadata**. Put every
  number a rule might want to threshold on in `features`, even if no rule uses
  it yet.
- Feature names must be consistent across every signal of a kind. A rule
  template writing `{elements:.0f}` should never encounter a signal without an
  `elements` feature.

## Adding a language

1. Add the extension to `LANGUAGE_BY_EXTENSION` in `discovery/classify.py`.
2. Add `parser/queries/<language>/*.scm` — one file per query kind in
   `QUERY_KINDS`. Copy an existing language's directory and adjust node names;
   `tests/unit/test_parser_registry.py` asserts every kind compiles.
3. Add sinks to `engine/signatures.py`.
4. Add a fixture pair.

Grammars come from `tree-sitter-language-pack`, so no build step is involved.

## Working on the code

```bash
uv sync
uv run pytest                 # 519 tests
uv run ruff check src tests
uv run ruff format src tests
uv run mypy                   # strict
```

Tests are written first. The test name states the behaviour in a sentence —
`test_a_short_fromcharcode_call_is_ignored`, not `test_charcode_2` — and where a
threshold exists, a test names the benign construct it protects.

## Corpus safety

Samples in `corpus/malicious/` reproduce attack **structure**, never payloads:

- No working exploit, shellcode, or real malware sample.
- Where a real attack would run a backdoor, the fixture writes a marker file.
- Nothing reaches the network or touches a path outside its own directory.

A detection corpus that shipped live payloads would make this repository a
distribution vector for the thing it exists to stop. `tests/benchmark/` asserts
this, and a pull request that weakens it will not be merged.

## Reporting a miss

If you have a real attack this scanner fails to catch, that is the most useful
issue you can file. Please include a *structural* reproduction rather than the
original sample — the same rules apply to issues as to the corpus.
