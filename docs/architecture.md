# Architecture

```
[ files ]
    │
    ▼
[ discovery ]  walk or git-diff  →  classify (magic bytes, language, build role)
    │
    ▼
[ engines ]    entropy · obfuscation · binary assets · build inspector
    │               each emits typed Signals; none decides anything
    ▼
[ SignalStore ]
    │
    ├──▶ [ linkage ]    joins signals across files      →  Findings
    └──▶ [ rules ]      predicates over single signals  →  Findings
                         │
                         ▼
              [ suppression → baseline → scoring ]
                         │
                         ▼
              [ markdown · json · sarif ]
```

## The central decision: signals are not findings

An engine emits a `Signal`: *"this literal has entropy 5.84"*, *"this call is
`eval`"*, *"this asset is opaque"*. Signals are cheap, numerous, and on their own
mean nothing. They are never shown to a user.

A `Finding` is a conclusion drawn from signals by a rule. Findings are what a
user sees and what a baseline suppresses.

Everything else follows from keeping these apart:

- **Entropy can be a feature without being a tripwire.** The original
  specification for this tool called for `H > 5.2` to raise a finding. That
  threshold fires on every embedded certificate in existence and misses every
  hex-encoded payload, because hex draws from 16 symbols and cannot exceed 4.0
  bits per character. As a *feature* on a signal that some other detector
  qualified, entropy is genuinely useful.
- **Rules can be YAML.** A predicate over a signal's numeric features and string
  metadata does not need to be Python, so contributing a detection does not
  require reading the engine.
- **Correlation becomes expressible.** Signals from four different engines about
  four different files can be joined, which is the only way to see the XZ
  pattern.

## Components

### `discovery/`

`walker.py` selects files — a full tree walk honouring `.gitignore`, or
`git diff --name-only` against a ref. Diff mode is the default posture for pull
requests and the most effective false-positive control in the tool.

`classify.py` answers two questions per file: what is it, and is it what it
claims? The second is `MAGIC_MISMATCH` — a `.png` whose bytes are an ELF — and
is close to the only signal here with no benign explanation. Magic-byte
detection is implemented in-tree rather than through `python-magic`, which needs
a `libmagic` system library and would break `pipx install` on Windows.

### `parser/`

`registry.py` wraps tree-sitter so engines never touch the raw API. Engines ask
for named *query kinds* — `strings`, `calls`, `assignments` — and the queries
live in `queries/<language>/<kind>.scm`. Adding a language is a directory of
`.scm` files.

Parsing is failure-tolerant: obfuscated code is often syntactically odd, so
giving up on a hard parse would lose exactly the files worth looking at.

**Grammar availability is not failure-tolerant, deliberately.** Grammars are
fetched on first use, and an earlier version of this scanner swallowed a failed
fetch, parsed nothing, and reported no findings. That is the one bug class a
security tool cannot ship. The scan now loads every grammar it needs *before*
analysing anything, and an unavailable one is a scan error with its own exit
code — see `Scanner._preflight_grammars`.

### `engine/`

| Module | Question it answers |
|---|---|
| `entropy.py` | how random is this, on what alphabet, relative to this repository |
| `obfuscation.py` | does this call a dangerous function, or have the shape of hiding |
| `dataflow.py` | does that literal actually reach that sink |
| `binary_assets.py` | is this non-code file carrying something |
| `build_inspector.py` | what runs during build or install |
| `linkage.py` | do these four unremarkable facts describe one attack |

`signatures.py` holds every sink, decoder and file-read function as one
declarative table, indexed by name at load time.

### `linkage.py` — the correlation engine

The one detector that cannot be expressed in the rule schema, because it is a
join rather than a predicate. Four links:

| | |
|---|---|
| **A** | a build or install script names the asset |
| **B** | the asset is anomalous (opaque, mismatched, or carrying hidden content) |
| **C** | code reads the asset and transforms the bytes |
| **D** | the transformed result reaches an execution sink |

**B** is required. Two links raise HIGH, three or more CRITICAL. One link alone
is left to the ordinary rules — "there is an opaque file in `tests/`" describes
most repositories rather than a finding.

### `scoring/`

`suppress.py` is the false-positive budget. It does not ask "is this
suspicious"; it asks *"did a human write this"*. Minified, generated, vendored
and lockfile content is held to a different standard because a reviewer was
never going to read it — its provenance, not its contents, is what should be
checked. Detection is by shape as well as name, since an attacker can rename
`app.min.js` but cannot make a 20 KB single line look hand-written.

`baseline.py` records accepted findings by a line-independent fingerprint.
`score.py` aggregates with saturation, so fifty low-severity observations cannot
outrank one smuggled executable.

## Concurrency

Files are analysed independently, in a process pool above
`PARALLEL_THRESHOLD` files. Below it — which is where diff mode usually lands —
the pool is skipped, because process startup costs more than it saves for three
files.

Suppression is decided inside the worker so that file contents never cross a
process boundary, and never accumulate in the parent. Correlation and rule
evaluation run afterwards in the main process, over the collected signals.
Worker count changes speed and nothing else; `tests/integration/` asserts
sequential and parallel runs produce identical fingerprints.

## Performance notes

The profile is dominated by tree-sitter itself — parse plus query execution is
roughly two thirds of a large scan. The Python-level costs that mattered, and
were fixed:

- Signature matching scanned the whole table per call (309k calls against ~80
  signatures). Now two dictionaries built once per language.
- Every string literal was profiled before the length gate rejected it. The gate
  moved first.
- `source_line()` re-split the whole file per lookup. Now cached per file.

Scanning the Python standard library — 2,267 files — takes about 10 seconds on
eight cores.
