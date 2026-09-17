# Rule schema

Rules are predicates over **signals**, not over source code. An engine has
already done the work of noticing things; a rule decides which noticings are
worth telling a human about, and how loudly.

Put your rules in `.forensic-rules.yml` at the repository root. They are merged
over the built-ins, and **redefining a built-in id replaces it** — including
setting `enabled: false`.

## A complete rule

```yaml
version: "1.0"
rules:
  - id: FOR-001                       # required, unique
    name: High-entropy payload reaches dynamic execution
    severity: CRITICAL                # INFO | LOW | MEDIUM | HIGH | CRITICAL
    remediation: >-                   # required: what the reader should do
      Decode the literal and read what it does before anything else.
    detail: >-                        # optional template, see below
      A literal of {source_length:.0f} characters flows into {sink}.
    enabled: true                     # optional, default true
    confidence: 1.0                   # optional, scales the risk contribution
    match:
      signal: taint_flow              # required: one kind or a list
      languages: [python, javascript] # optional
      paths: ["src/**"]               # optional, gitignore syntax
      exclude_paths: ["tests/**"]     # optional
      also_in_file: [dynamic_exec_sink]  # optional co-occurrence
      min_count: 1                    # optional repetition threshold
      features:                       # optional numeric predicates
        source_length: {min: 40}
        printable_ratio: {min: 0.8, max: 1.0}
      metadata:                       # optional string predicates
        alphabet: {in: [base64, hex]}
        sink: {not-equals: "compile"}
```

Validation is strict: an unknown field is an error rather than a silently
ignored key, because a typo would otherwise disable a detection without anyone
noticing. Check a file without running a scan:

```bash
forensic-scan rules validate .forensic-rules.yml
```

## Predicates

**`features`** — numeric, on the signal's measurements.

| Key | Meaning |
|---|---|
| `min` | value must be present and `>= min` |
| `max` | value must be present and `<= max` |

A missing feature never satisfies a threshold. Absence is not evidence.

**`metadata`** — string, on the signal's context.

| Key | Meaning |
|---|---|
| `equals` / `not-equals` | exact match / mismatch |
| `in` / `not-in` | membership in a list |
| `contains` | substring |
| `matches` | regular expression (validated at load time) |

A missing key never satisfies a predicate, negated ones included.

**`also_in_file`** — every listed signal kind must also appear somewhere in the
same file. Co-occurrence rather than data flow: cheap, and enough to express
"an encoded blob in a file that also calls `eval`".

**`min_count`** — a file must carry at least this many matching signals before
any of them are reported.

## `detail` templates

`{name}` interpolates from the signal's metadata and features; `{value:.0f}`
and other format specs work on numbers. Two authoring mistakes are absorbed
rather than raised, because a scan is worth more than a perfect sentence:

- a placeholder naming something the signal does not carry renders as `{name}`
- a numeric format spec on a non-number renders the value as-is

Omit `detail` and a readable default is generated from the signal.

## Signal kinds

Run `forensic-scan rules list` to see which rule consumes each. The
authoritative list is `SignalKind` in `src/forensic_scan/models.py`; the schema
rejects unknown names and prints the valid set.

| Group | Kinds |
|---|---|
| Entropy | `high_entropy_string`, `high_entropy_identifiers`, `encoded_alphabet_string` |
| Obfuscation | `dynamic_exec_sink`, `decode_call`, `charcode_construction`, `bitwise_decode_loop`, `dynamic_import`, `dynamic_symbol_resolution`, `inline_assembly`, `string_concat_chain` |
| Binary assets | `magic_mismatch`, `executable_header`, `embedded_archive`, `trailing_data`, `opaque_asset` |
| Build scripts | `build_shell_exec`, `build_network_access`, `build_decompression`, `build_file_reference`, `build_macro_anomaly` |
| Data flow | `taint_flow`, `file_read` |

## The built-in rules

23 rules ship with the scanner, plus **FOR-010**, which is emitted in
code because it joins signals across files rather than testing one.
`forensic-scan rules list` prints the set actually in effect, including your
overrides.

### FOR-010 — Build-time payload extraction chain

| | |
| --- | --- |
| **Severity** | CRITICAL at 3+ links, HIGH at 2 |
| **Signals** | joined across `build_file_reference`, the asset anomalies, `file_read`, the transforms and the execution sinks |
| **Configurable** | no — it is a graph query, which the schema does not express |

The detector this project exists for. See
[architecture.md](architecture.md#linkagepy--the-correlation-engine).

### Payload execution

| Rule | Severity | Detects | Signal |
| --- | --- | --- | --- |
| `FOR-001` | CRITICAL | High-entropy payload reaches dynamic execution | `taint_flow` |
| `FOR-004` | CRITICAL | Encoded payload reaches execution after decoding | `taint_flow` |
| `FOR-014` | MEDIUM | Encoded blob in a file that executes code | `encoded_alphabet_string` |

### Smuggled binaries and assets

| Rule | Severity | Detects | Signal |
| --- | --- | --- | --- |
| `FOR-002` | CRITICAL | Hidden executable or archive in a non-code asset | `magic_mismatch` |
| `FOR-009` | CRITICAL | Executable image embedded in an asset | `executable_header` |
| `FOR-011` | HIGH | Compressed archive embedded in a non-archive asset | `embedded_archive` |
| `FOR-012` | HIGH | Data appended past the end of a container file | `trailing_data` |
| `FOR-013` | LOW | Opaque high-entropy fixture | `opaque_asset` |
| `FOR-023` | LOW | Asset contents do not match its extension | `magic_mismatch` |

### Build and install scripts

| Rule | Severity | Detects | Signal |
| --- | --- | --- | --- |
| `FOR-005` | HIGH | Shell or dynamic execution during install | `build_shell_exec` |
| `FOR-006` | HIGH | Network access during install | `build_network_access` |
| `FOR-007` | MEDIUM | Decompression or decoding during build or install | `build_decompression` |
| `FOR-008` | HIGH | Build macro executes a computed command | `build_macro_anomaly` |
| `FOR-021` | LOW | Shell execution during build | `build_shell_exec` |
| `FOR-022` | INFO | Recognised build tool invoked during install | `build_shell_exec` |
| `FOR-024` | MEDIUM | Network access during build | `build_network_access` |

### Obfuscation

| Rule | Severity | Detects | Signal |
| --- | --- | --- | --- |
| `FOR-003` | HIGH | String constructed from character codes | `charcode_construction` |
| `FOR-015` | MEDIUM | Machine-generated identifier naming | `high_entropy_identifiers` |
| `FOR-016` | MEDIUM | Bitwise decoding loop over file contents | `bitwise_decode_loop` |
| `FOR-017` | LOW | Module loaded under a computed name | `dynamic_import` |
| `FOR-018` | LOW | Symbol resolved at runtime | `dynamic_symbol_resolution` |
| `FOR-019` | LOW | Inline assembly | `inline_assembly` |
| `FOR-020` | LOW | String assembled from many fragments | `string_concat_chain` |

### Severity, and what it means for CI

The default `--fail-on HIGH` means LOW and INFO findings never block a build.
They exist because they are worth *seeing* — a runtime symbol lookup is
unremarkable alone and interesting next to an encoded blob in the same file.

| Severity | Typical meaning | Blocks a default CI run |
| --- | --- | --- |
| CRITICAL | Close to no benign explanation | yes |
| HIGH | Needs a person to look before merging | yes |
| MEDIUM | Worth a glance; often legitimate | no |
| LOW | Context for other findings | no |
| INFO | Expected, recorded for completeness | no |

## What the schema cannot express

**FOR-010**, the build-time payload extraction chain, is emitted in code. It
joins signals from four engines across four files, and a predicate over one
signal cannot describe a graph. See [`architecture.md`](architecture.md).

## Tuning a built-in

```yaml
version: "1.0"
rules:
  # Too noisy in this repository: we ship hundreds of compressed fixtures.
  - id: FOR-013
    name: Opaque high-entropy fixture
    severity: LOW
    remediation: "n/a"
    enabled: false
    match: {signal: opaque_asset}

  # We accept install-time shelling out, but want to know about it.
  - id: FOR-005
    name: Shell or dynamic execution during install
    severity: MEDIUM
    remediation: "Confirm the command is one of ours."
    match:
      signal: build_shell_exec
      metadata:
        auto_run: {equals: "yes"}
        known_tool: {equals: "no"}
```
