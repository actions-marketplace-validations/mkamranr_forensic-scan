# forensic-scan

**A static analyser that looks for concealment rather than vulnerabilities.**

Conventional linters and SAST tools match patterns for *accidental* insecurity —
SQL injection, unsafe deserialisation, hardcoded credentials. They are blind to
code that is deliberately shaped to look boring, because an attacker reads the
same rule sets the defender does.

What an attacker cannot easily hide is the *structural residue* of hiding: a
string with the wrong entropy for its neighbourhood, a build step that reaches
for an opaque asset, a loop that XORs a buffer read from a test fixture. This
tool measures that residue.

```bash
uvx forensic-scan ./                      # audit a dependency
forensic-scan --diff origin/main          # gate a pull request
```

---

## The attack it was built for

The [XZ Utils backdoor](https://www.openwall.com/lists/oss-security/2024/03/29/4)
put no suspicious strings in any source file. It worked like this:

1. `m4/build-to-host.m4` — a file nobody reads — named a test fixture.
2. The fixture was a "corrupt" archive in a directory full of deliberately
   corrupt archives.
3. A byte substitution turned it into a shell script.
4. That script patched the build and produced a backdoored binary.

Every step is individually unremarkable. Build scripts name files. Test suites
contain broken fixtures. Code applies byte transformations. What is *not*
unremarkable is all four happening to the same file — and that is a graph query,
not a pattern match.

`forensic-scan` runs that query. It is rule **FOR-010**, and it is the reason
the tool exists.

```
🚨 FOR-010: Build-time payload extraction chain            CRITICAL
   tests/files/bad-3-corrupt_lzma2.xz

   4 of 4 links hold for this asset:

   1. Makefile:5             build script references this asset (build phase)
   2. tests/files/…lzma2.xz  asset is anomalous: opaque asset
   3. src/loader.c:10        read by fopen, then transformed (bitwise_decode_loop)
   4. src/loader.c:26        same file reaches execution sink dlopen
```

## Measured behaviour

Both numbers are produced by `tests/benchmark/` and enforced as a release gate,
so they move only when someone decides they should.

| Metric | Result |
|---|---|
| **Detection rate** | **100%** (7/7 attack samples flagged at HIGH or above) |
| **False-positive rate** | **0%** (0/9 hard benign samples producing a finding at MEDIUM or above) |
| Python standard library (2,267 files) | 165 findings, **2 at HIGH**, none CRITICAL, 10 s |

The false-positive corpus is chosen to be hard, not easy: minified bundles,
generated protobuf, embedded PEM certificates, a CRC-32 lookup table, real
compressed test fixtures, and a `setup.py` that genuinely shells out to
`pkg-config`. Each one trips a detector that a naive implementation would ship.

Publishing a false-positive rate is unusual in this space. It is the number that
decides whether a maintainer leaves the scanner switched on, so it is treated as
a release gate rather than a footnote.

## Try it

The repository ships the attack corpus the benchmark runs against. Every sample
is inert — where a real attack would run a backdoor, these write a marker file —
so the fastest way to see the tool work is to point it at them:

```bash
git clone https://github.com/mkamranr/forensic-scan && cd forensic-scan
uvx forensic-scan corpus/malicious     # 7 samples, 4 CRITICAL
uvx forensic-scan corpus/benign        # hard negatives: nothing above LOW
```

Because `corpus/malicious/` is *meant* to be detected, scanning the repository
root reports it. CI scans `src/` — the scanner must not flag its own source,
which is a harder test than it sounds: it contains every dangerous function name
there is, in a table, as strings.

## Install

```bash
uv tool install forensic-scan      # or: pipx install forensic-scan
docker run --rm -v "$PWD:/src" ghcr.io/mkamranr/forensic-scan:latest /src
```

### Offline and air-gapped use

Tree-sitter grammars are downloaded on first use and cached. On an air-gapped
runner or behind a blocked proxy, warm the cache once while online:

```bash
forensic-scan prefetch
```

The container image has grammars baked in and works with `--network none`.

If a grammar cannot be loaded, the scan **exits 2 and says so** rather than
reporting no findings. An incomplete scan that looks clean is the one failure
mode a security tool must never have, so the three exit codes are kept distinct:

| Exit | Meaning |
|---|---|
| `0` | scan completed, nothing at or above `--fail-on` |
| `1` | scan completed, findings at or above `--fail-on` |
| `2` | scan could **not** be completed — do not read this as clean |

### GitHub Action

Findings appear as inline pull-request annotations and in the Security tab.

```yaml
name: Forensic scan
on: pull_request

permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0          # required for diff mode
      - uses: mkamranr/forensic-scan@v1
        with:
          fail-on: HIGH
```

## Two ways to run it

**Pull-request gate** — the default posture, and the one tuned hardest.

```bash
forensic-scan --diff origin/main --fail-on HIGH
```

Scanning only what changed is the single most effective false-positive control
in the tool. A vendored minified bundle is noise in a full scan and a real
question when it appears in a pull request that claims to fix a typo.

**Dependency audit** — everything, ranked, nothing hidden.

```bash
forensic-scan ./vendor/suspicious-package --include-vendored --fail-on none
```

### Accepting what is already there

Nobody adopts a scanner that opens with four hundred findings about code they
did not write. Record the current state and only new anomalies fire:

```bash
forensic-scan baseline write .        # writes .forensic-baseline.json
```

Fingerprints deliberately exclude line numbers, so adding an import at the top
of a file does not silently un-accept everything below it. Changing the flagged
code does.

## What it detects

| Area | Examples |
|---|---|
| **Payload execution** | a high-entropy literal decoded and passed to `eval`, `Function`, `exec` — traced hop by hop |
| **Smuggled binaries** | an ELF wearing a `.png` extension, an xz stream appended past a PNG's `IEND` chunk |
| **Install-time execution** | `postinstall` hooks, `setup.py` side effects, `.m4` macros that run computed commands |
| **Obfuscation** | character-code string tables, XOR decode loops, machine-generated identifiers |
| **Correlation** | the four-link chain above, which no single detector can see |

Run `forensic-scan rules list` for the full set. Languages in v1: **Python,
JavaScript/TypeScript, C**. Rust, Go and C++ share the parser abstraction and
are a matter of writing rules.

## Configuration

Drop a `.forensic-rules.yml` in the repository root. Rules are predicates over
signals, so a new detection is YAML rather than Python:

```yaml
version: "1.0"
rules:
  - id: FOR-013          # redefining a built-in id replaces it
    name: Opaque high-entropy fixture
    severity: LOW
    enabled: false       # too noisy for this repository

  - id: ACME-001
    name: Base64 blob in our handlers
    severity: HIGH
    remediation: "Store payloads in config, not in source."
    match:
      signal: encoded_alphabet_string
      paths: ["src/handlers/**"]
      metadata:
        alphabet: {in: [base64]}
      features:
        length: {min: 256}
```

See [`docs/rules.md`](docs/rules.md) for the full schema.

## Limitations

Stated plainly, because a security tool that overstates its reach is worse than
one that admits its edges.

- **Data flow is intra-procedural and single-file.** Local variables and C
  object-like macros are resolved within one function body. Passing a payload
  through a function argument, an attribute, or another module defeats it.
- **C macros are not expanded.** Real expansion needs a preprocessor. The
  scanner flags suspicious macro *definitions* and build-system injection
  points, which is what the XZ attack actually used.
- **Entropy is never a verdict.** It is a feature feeding other detectors. A
  fixed threshold would fire on every embedded certificate in existence, and
  would miss every hex-encoded payload — hex tops out at 4.0 bits/character,
  below the threshold the PRD for this tool originally specified.
- **Findings are anomalies, not conclusions.** This scanner measures
  concealment, so a true positive can still be legitimate code that happens to
  look concealed. Every finding is a question, not an accusation.
- **Absence of findings is not evidence of absence.** A sufficiently patient
  attacker who knows these rules can avoid all of them.
- **Grammars are fetched on first run.** The scanner needs network access once,
  or a warmed cache (`forensic-scan prefetch`), or the container image. It
  refuses to report a clean result when it could not parse — see the exit codes
  above.

## How it works

```
files → classify → engines → signals → correlation → rules → findings
```

Engines emit typed `Signal` objects — cheap, numerous, and meaningless alone.
Rules are declarative predicates *over signals*. Correlation joins signals
across files. This indirection is the central design decision: it is what lets
entropy be a feature rather than a tripwire, and what makes rule authoring a
YAML exercise.

See [`docs/architecture.md`](docs/architecture.md).

## Contributing

Every new rule needs one malicious fixture and one benign fixture. That
requirement is the reason the false-positive rate stays where it is. See
[`CONTRIBUTING.md`](CONTRIBUTING.md).

## License

Apache-2.0. See [`LICENSE`](LICENSE).
