<div align="center">

# forensic-scan

**A static analyser that hunts for concealment, not vulnerabilities.**

[![CI](https://github.com/mkamranr/forensic-scan/actions/workflows/ci.yml/badge.svg)](https://github.com/mkamranr/forensic-scan/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue.svg)](https://www.python.org)
[![Detection](https://img.shields.io/badge/detection-100%25-brightgreen.svg)](#measured-behaviour)
[![False positives](https://img.shields.io/badge/false%20positives-0%25-brightgreen.svg)](#measured-behaviour)

[Install](docs/installation.md) · [Deploy](docs/deployment.md) · [CLI](docs/cli.md) · [Rules](docs/rules.md) · [Architecture](docs/architecture.md)

</div>

---

Conventional linters and SAST tools match patterns for *accidental* insecurity —
SQL injection, unsafe deserialisation, hardcoded credentials. They are blind to
code deliberately shaped to look boring, because an attacker reads the same rule
sets the defender does.

What an attacker cannot easily hide is the **structural residue of hiding**: a
string with the wrong entropy for its neighbourhood, a build step reaching for an
opaque asset, a loop XOR-ing a buffer read from a test fixture. This tool
measures that residue.

```bash
uv tool install forensic-scan

forensic-scan --diff origin/main     # gate a pull request
forensic-scan ./vendor/some-package  # audit a dependency
```

---

## The attack this was built for

The [XZ Utils backdoor](https://www.openwall.com/lists/oss-security/2024/03/29/4)
(CVE-2024-3094) put no suspicious strings in any source file. It worked like this:

1. `m4/build-to-host.m4` — a file nobody reads — named a test fixture.
2. That fixture was a "corrupt" archive, in a directory full of deliberately
   corrupt archives.
3. A byte substitution turned it into a shell script.
4. That script patched the build and produced a backdoored binary.

Every step is individually unremarkable. Build scripts name files. Test suites
contain broken fixtures. Code applies byte transformations. What is *not*
unremarkable is all four happening to the same file — and that is a **graph
query**, not a pattern match.

`forensic-scan` runs that query. It is rule **FOR-010**, and it is the reason
this project exists:

```
🚨 CRITICAL  FOR-010: Build-time payload extraction chain
             tests/files/bad-3-corrupt_lzma2.xz

             4 of 4 links hold for this asset:

  1. Makefile:5              build script references this asset (build phase)
  2. tests/files/…lzma2.xz   asset is anomalous: opaque asset
  3. src/loader.c:10         read by fopen, then transformed (bitwise_decode_loop)
  4. src/loader.c:26         same file reaches execution sink dlopen
```

## Measured behaviour

Both numbers are produced by `tests/benchmark/` and enforced as a release gate,
so they move only when someone decides they should.

| Metric | Result |
| --- | --- |
| **Detection rate** | **100%** — 7/7 attack samples flagged at HIGH or above |
| **False-positive rate** | **0%** — 0/9 hard benign samples producing a finding at MEDIUM or above |
| Python standard library (2,267 files) | 165 findings, **2 at HIGH**, none CRITICAL, **≈9 s** on 8 cores |

The benign corpus is chosen to be *hard*, not easy — every sample trips a
detector a naive implementation would ship:

| Benign sample | What it trips |
| --- | --- |
| `minified-bundle/` | high entropy, mangled identifiers, `Function()` calls |
| `generated-code/` | unnatural identifier distribution |
| `embedded-cert/` | a 1.6 KB base64 literal, entropy above every threshold |
| `lookup-tables/` | a CRC-32 table — 256 numeric literals, like a charcode payload |
| `crypto-code/` | XOR and shift loops over a buffer |
| `legit-setup/` | a `setup.py` that genuinely shells out to `pkg-config` |
| `real-fixtures/` | high-entropy compressed binaries in a fixtures directory |

Publishing a false-positive rate is unusual in this space. It is the number that
decides whether a maintainer leaves the scanner switched on, so it is treated as
a release gate rather than a footnote.

## Try it in 30 seconds

The repository ships the corpus the benchmark runs against. Every malicious
sample is **inert** — where a real attack would run a backdoor, these write a
marker file — so the fastest way to see the tool work is to point it at them:

```bash
git clone https://github.com/mkamranr/forensic-scan && cd forensic-scan
uv sync && uv run forensic-scan prefetch

uv run forensic-scan corpus/malicious   # 7 samples, 4 CRITICAL
uv run forensic-scan corpus/benign      # hard negatives: nothing above LOW
```

## What it detects

23 built-in rules across five areas. Run `forensic-scan rules list` for the
current set.

| Area | Examples | Rules |
| --- | --- | --- |
| **Payload execution** | a high-entropy literal decoded and passed to `eval` / `Function` / `exec`, traced hop by hop | FOR-001, FOR-004, FOR-014 |
| **Smuggled binaries** | an ELF wearing a `.png` extension; an xz stream appended past a PNG's `IEND` chunk | FOR-002, FOR-009, FOR-011, FOR-012 |
| **Install-time execution** | `postinstall` hooks, `setup.py` side effects, `.m4` macros running computed commands | FOR-005…FOR-008, FOR-021…FOR-024 |
| **Obfuscation** | character-code string tables, XOR decode loops, machine-generated identifiers | FOR-003, FOR-015…FOR-020 |
| **Correlation** | the four-link chain above, which no single detector can see | **FOR-010** |

**Languages:** Python, JavaScript, TypeScript, TSX, C. Rust, Go and C++ share the
parser abstraction and are a matter of writing rules.

## Two ways to run it

### Pull-request gate — the default posture

```bash
forensic-scan --diff origin/main --fail-on HIGH
```

Scanning only what changed is the single most effective false-positive control in
the tool. A vendored minified bundle is noise in a full scan and a real question
when it appears in a pull request that claims to fix a typo.

As a GitHub Action, findings become inline PR annotations:

```yaml
- uses: actions/checkout@v4
  with: { fetch-depth: 0 }
- uses: mkamranr/forensic-scan@v1
  with:
    fail-on: HIGH
```

See [the deployment guide](docs/deployment.md) for GitLab CI, Jenkins, pre-commit
and container usage.

### Dependency audit — everything, ranked

```bash
forensic-scan ./vendor/suspicious-package --include-vendored --fail-on none
```

### Adopting on an existing codebase

Nobody adopts a scanner that opens with four hundred findings about code they did
not write. Record the current state so only *new* anomalies fire:

```bash
forensic-scan baseline write .    # writes .forensic-baseline.json
```

Fingerprints deliberately exclude line numbers, so adding an import at the top of
a file does not silently un-accept everything below it. Changing the flagged code
does.

## Exit codes

An incomplete scan must never be mistaken for a clean one, so three states are
kept distinct:

| Code | Meaning |
| --- | --- |
| `0` | scan completed; nothing at or above `--fail-on` |
| `1` | scan completed; findings at or above `--fail-on` |
| `2` | scan could **not** be completed — do not read this as clean |

## Documentation

| Guide | What's in it |
| --- | --- |
| [Installation](docs/installation.md) | every install path, platform notes, air-gapped setup, verification, troubleshooting |
| [Deployment](docs/deployment.md) | GitHub Actions, GitLab CI, Jenkins, pre-commit, Docker, rollout strategy, release runbook |
| [CLI reference](docs/cli.md) | every command and flag, with worked examples |
| [Rules](docs/rules.md) | the YAML schema, writing and tuning rules, the full rule table |
| [Architecture](docs/architecture.md) | how signals, correlation and scoring fit together, and why |
| [Contributing](CONTRIBUTING.md) | the two-fixture rule, adding a language, house style |
| [Security policy](SECURITY.md) | threat model, what counts as a vulnerability here |

## Limitations

Stated plainly, because a security tool that overstates its reach is worse than
one that admits its edges.

- **Data flow is intra-procedural and single-file.** Local variables and C
  object-like macros resolve within one function body. Passing a payload through
  a function argument, an attribute, or another module defeats it.
- **C macros are not expanded.** Real expansion needs a preprocessor. The scanner
  flags suspicious macro *definitions* and build-system injection points — which
  is what the XZ attack actually used.
- **Entropy is never a verdict.** It is a feature feeding other detectors. A fixed
  threshold would fire on every embedded certificate in existence and would miss
  every hex-encoded payload, since hex tops out at 4.0 bits/character.
- **Findings are anomalies, not conclusions.** This scanner measures concealment,
  so a true positive can still be legitimate code that happens to look concealed.
  Every finding is a question, not an accusation.
- **Absence of findings is not evidence of absence.** A patient attacker who knows
  these rules can avoid all of them.
- **Grammars are fetched on first run.** The scanner needs network access once, a
  warmed cache (`forensic-scan prefetch`), or the container image. It refuses to
  report a clean result when it could not parse.

## How it works

```
files → classify → engines → signals → correlation → rules → findings
```

Engines emit typed `Signal` objects — cheap, numerous, meaningless alone. Rules
are declarative predicates *over signals*. Correlation joins signals across
files. That indirection is the central design decision: it is what lets entropy
be a feature rather than a tripwire, and what makes rule authoring a YAML
exercise rather than a Python one.

Details in [docs/architecture.md](docs/architecture.md).

## Contributing

Every new rule needs one malicious fixture and one benign fixture. That
requirement is why the false-positive rate stays where it is. See
[CONTRIBUTING.md](CONTRIBUTING.md).

## License

[Apache-2.0](LICENSE).
