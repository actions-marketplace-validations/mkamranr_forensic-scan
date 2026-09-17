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
