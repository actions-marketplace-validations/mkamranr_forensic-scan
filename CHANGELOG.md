# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
follows [semantic versioning](docs/deployment.md#versioning) — with one
clarification: **a new detection rule is a minor bump, not a patch**, because new
rules can fail a build that previously passed.

## [Unreleased]

## [0.1.0] — 2026-09-17

First release.

### Added

**Detection engines**

- Entropy analysis with alphabet detection and per-repository calibration.
  Entropy is a scoring feature, never a standalone rule.
- Binary asset inspection: magic-byte mismatch, embedded executables and
  archives, data appended past a container's declared end, opaque fixtures.
- Dynamic execution and obfuscation detection for Python, JavaScript/TypeScript
  and C: execution sinks, decoders, character-code construction, XOR decode
  loops, machine-generated identifiers, inline assembly.
- Intra-procedural, single-file data flow linking high-entropy literals to
  execution sinks, resolving local variables and C object-like macros.
- Build and install script inspection for `setup.py`, `package.json` lifecycle
  hooks, `Makefile`, `CMakeLists.txt`, `configure.ac` and `.m4`.
- **The correlation engine (FOR-010)** — joins a build-script reference, an
  anomalous asset, a read-and-transform, and an execution sink into one finding.
  This is the XZ Utils pattern, and it is the reason the project exists.

**Rules and configuration**

- 23 built-in rules, authored as YAML.
- `.forensic-rules.yml` for project rules; redefining a built-in id replaces it.
- Strict schema validation — an unknown field is an error, not a silently ignored
  key.
- `.forensic-baseline.json` with line-independent fingerprints.
- Suppression for generated, minified, vendored and lockfile content, by shape as
  well as by name.

**Interface**

- `scan`, `baseline write`, `rules list`, `rules validate`, `prefetch`, `version`.
- Diff mode (`--diff REF`) scanning only changed files — the default CI posture.
- Markdown, JSON and SARIF 2.1.0 output, with taint traces rendered as SARIF
  `codeFlows`.
- Parallel scanning, with identical results at any worker count.
- Three distinct exit codes: `0` clean, `1` findings, `2` scan incomplete.

**Distribution**

- Apache-2.0 licensed, Python 3.10–3.13, Linux/macOS/Windows.
- Container image with grammars baked in, running unprivileged and needing no
  network.
- Composite GitHub Action publishing inline PR annotations and SARIF.
- PyPI publishing via trusted publishing (OIDC).

**Quality gates**

- 519 tests; ruff, `ruff format` and mypy `--strict` all enforced in CI.
- A measured detection rate (100%) and false-positive rate (0%) enforced as a
  release gate, both published in the README.
- The scanner scans its own source in CI.

### Notes on design

- **Entropy thresholds were deliberately not implemented as specified.** A fixed
  `H > 5.2` rule fires on every embedded certificate in existence and misses
  every hex-encoded payload, since hex cannot exceed 4.0 bits per character.
  Entropy contributes a feature to signals that other engines qualify.
- **A grammar that cannot be loaded is a scan failure, not an empty result.**
  Grammars are fetched on first use; an earlier build swallowed that failure,
  parsed nothing, and reported no findings. The scan now loads grammars in a
  preflight and exits `2` if any are unavailable.

[Unreleased]: https://github.com/mkamranr/forensic-scan/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/mkamranr/forensic-scan/releases/tag/v0.1.0
