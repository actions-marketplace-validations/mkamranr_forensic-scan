# CLI reference

```
forensic-scan [COMMAND] [OPTIONS]
```

A bare path is treated as an implicit `scan`, so `forensic-scan ./` and
`forensic-scan scan ./` are the same command.

| Command | Purpose |
| --- | --- |
| [`scan`](#forensic-scan-scan) | scan a repository (the default) |
| [`baseline write`](#forensic-scan-baseline-write) | accept the current findings |
| [`rules list`](#forensic-scan-rules-list) | show the active rule set |
| [`rules validate`](#forensic-scan-rules-validate) | check a rule file |
| [`prefetch`](#forensic-scan-prefetch) | cache grammars for offline use |
| [`version`](#forensic-scan-version) | print the version |

---

## `forensic-scan scan`

```
forensic-scan scan [OPTIONS] [PATH]
```

Scan a repository for concealment, obfuscation and smuggled payloads. `PATH`
defaults to `.` and may be a directory or a single file.

### Options

| Flag | Default | Description |
| --- | --- | --- |
| `-d`, `--diff REF` | — | Scan only files changed against this git ref. The most useful flag in the tool. |
| `-f`, `--format FMT` | `markdown` | `markdown`, `json` or `sarif`. |
| `-o`, `--output PATH` | stdout | Write the report to a file. |
| `--fail-on SEVERITY` | `HIGH` | Exit `1` at this severity or above. `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `none`. |
| `-r`, `--rules PATH` | — | Extra rule file, merged over the built-ins. |
| `-b`, `--baseline PATH` | `.forensic-baseline.json` | Baseline file, if present. |
| `--no-baseline` | off | Report findings even if the baseline accepts them. |
| `-e`, `--exclude GLOB` | — | Skip paths matching this glob. Repeatable. |
| `--include-vendored` | off | Scan `node_modules`, `vendor`, `third_party`. |
| `--no-gitignore` | off | Also scan files `.gitignore` excludes. |
| `--no-suppress` | off | Do not hold back findings in generated, minified or vendored files. |
| `-j`, `--jobs N` | cores (max 8) | Worker processes. `1` forces sequential. |
| `-q`, `--quiet` | off | Suppress the progress summary on stderr. |

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Scan completed; nothing at or above `--fail-on`. |
| `1` | Scan completed; findings at or above `--fail-on`. |
| `2` | Scan could **not** be completed. Never read this as clean. |

Exit `2` means a bad path, an unreadable rule file, a git failure in diff mode,
or a grammar that could not be loaded.

### Examples

```bash
# Gate a pull request: only what changed, fail on HIGH and above
forensic-scan --diff origin/main

# Audit a dependency: everything, nothing hidden, never fail
forensic-scan ./vendor/some-package --include-vendored --fail-on none

# SARIF for a code-scanning platform
forensic-scan . --format sarif --output forensic.sarif --fail-on none

# Machine-readable, quiet, for a script
forensic-scan . --format json --quiet | jq '.summary.risk_score'

# A single file
forensic-scan suspicious.js

# Skip directories that are not yours
forensic-scan . -e "docs/**" -e "examples/**"

# Deterministic, single-threaded (useful when debugging)
forensic-scan . --jobs 1
```

### Output formats

**`markdown`** — for humans. Findings grouped by severity, worst first, each with
a location, an explanation, what to do about it, and a numbered trace where one
exists. Rendered with syntax highlighting when stdout is a terminal.

**`json`** — for tooling. Stable schema; see [below](#json-schema).

**`sarif`** — SARIF 2.1.0, for GitHub code scanning and other SARIF consumers.
Taint traces become `codeFlows`, so a reader can step through a payload decoded
on one line and executed on another. `partialFingerprints` are line-independent,
so a triaged finding is not re-reported after an unrelated edit above it.

### JSON schema

```jsonc
{
  "version": 1,
  "tool": "forensic-scan",
  "summary": {
    "files_analyzed": 128,
    "files_parsed": 96,
    "findings": 2,
    "suppressed": 5,
    "baselined": 0,
    "risk_score": 88,              // 0-100, saturating
    "risk_band": "CRITICAL",       // severity of the worst finding
    "counts": { "CRITICAL": 1, "HIGH": 1 },
    "duration_seconds": 1.42,
    "diff_ref": "origin/main",     // null for a full scan
    "complete": true,              // false => the scan could not parse everything
    "files_unanalyzed": 0,
    "unavailable_languages": {}
  },
  "findings": [
    {
      "rule": "FOR-001",
      "name": "High-entropy payload reaches dynamic execution",
      "severity": "CRITICAL",
      "path": "scripts/postinstall.js",
      "line": 14,
      "end_line": 14,
      "column": 3,
      "snippet": "new Function(decoded)();",
      "detail": "A string literal of 512 characters flows into Function.",
      "remediation": "Decode the literal and read what it does.",
      "fingerprint": "a1b2c3d4e5f60718",   // stable, line-independent
      "metadata": { "confidence": 1.0 },
      "trace": [
        { "path": "scripts/postinstall.js", "line": 1,
          "description": "string literal (length 512, entropy 5.84, base64)" }
      ],
      "signals": [
        { "kind": "taint_flow", "path": "scripts/postinstall.js", "line": 14,
          "features": { "source_entropy": 5.84 }, "metadata": { "sink": "Function" },
          "confidence": 1.0 }
      ]
    }
  ],
  "errors": [],
  "skipped": [ { "path": "big.bin", "reason": "too_large", "detail": "..." } ]
}
```

**Always check `summary.complete`.** `false` means some files could not be
parsed and the absence of findings for them means nothing.

---

## `forensic-scan baseline write`

```
forensic-scan baseline write [PATH] [-o OUTPUT]
```

Scan, then record every current finding as accepted. Subsequent scans report only
findings absent from the file.

```bash
forensic-scan baseline write .              # -> .forensic-baseline.json
forensic-scan baseline write . -o ci.json   # somewhere else
```

The file is JSON, sorted, and readable in a diff — each entry names its rule,
path, severity and summary, so deleting one in a pull request is a visible
decision. Commit it.

Fingerprints deliberately exclude line numbers: an unrelated edit above a finding
must not silently un-accept it, while changing the flagged code itself must.

---

## `forensic-scan rules list`

```
forensic-scan rules list [PATH]
```

Print every rule that would be applied, including project overrides from
`.forensic-rules.yml` in `PATH`. Use it to confirm a local override took effect.

```
┏━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━┓
┃ ID      ┃ Severity ┃ Name                               ┃ Signals       ┃
┡━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━┩
│ FOR-001 │ CRITICAL │ High-entropy payload reaches …     │ taint_flow    │
```

---

## `forensic-scan rules validate`

```
forensic-scan rules validate PATH
```

Check a rule file for errors without running a scan. Exits `0` if valid, `2`
with a specific message if not.

```bash
forensic-scan rules validate .forensic-rules.yml
# valid: 3 rule(s) in .forensic-rules.yml
```

---

## `forensic-scan prefetch`

```
forensic-scan prefetch [LANGUAGES...]
```

Download and cache the tree-sitter grammars. Grammars are fetched on first use,
so run this once while online for air-gapped or offline environments — and as an
explicit CI step, so a network failure fails a named step rather than silently
changing your results.

```bash
forensic-scan prefetch                  # every supported language
forensic-scan prefetch python javascript
```

Prints the cache location on completion. Exits `2` if any grammar failed.

---

## `forensic-scan version`

```
forensic-scan version
# forensic-scan 0.1.0 (23 built-in rules)
```

---

## Configuration files

Both are optional, and both live at the repository root.

| File | Purpose |
| --- | --- |
| `.forensic-rules.yml` | Project rules, merged over the built-ins. Redefining a built-in id replaces it. See [rules.md](rules.md). |
| `.forensic-baseline.json` | Accepted findings, written by `baseline write`. |

Precedence for rules, lowest to highest: built-ins → `.forensic-rules.yml` →
`--rules FILE`.

## Environment variables

| Variable | Effect |
| --- | --- |
| `XDG_CACHE_HOME` | Where grammars are cached. Useful for a shared or read-only cache. |
| `HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY` | Honoured during `prefetch`. |
| `NO_COLOR` | Disables coloured terminal output. |
