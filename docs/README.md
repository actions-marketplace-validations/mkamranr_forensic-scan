# Documentation

| Guide | Read it when |
| --- | --- |
| [Installation](installation.md) | installing, setting up an air-gapped environment, or something went wrong |
| [Deployment](deployment.md) | wiring the scanner into CI, rolling it out to a team, or cutting a release |
| [CLI reference](cli.md) | you need a flag, an exit code, or the JSON schema |
| [Rules](rules.md) | writing a detection, tuning a built-in, or reading the rule table |
| [Architecture](architecture.md) | changing an engine, or understanding why it is built this way |

Also at the repository root:

- [README](../README.md) — what the tool is and why
- [CONTRIBUTING](../CONTRIBUTING.md) — the two-fixture rule and house style
- [SECURITY](../SECURITY.md) — threat model and reporting
- [CHANGELOG](../CHANGELOG.md) — what changed

## Where things live

```
src/forensic_scan/
├── models.py          Signal, Finding, Location, Severity — the shared vocabulary
├── scanner.py         the pipeline: select → analyse → correlate → rule → score
├── cli.py             typer command line
├── discovery/         which files to scan, and what each one is
├── parser/            tree-sitter access + queries/<language>/<kind>.scm
├── engine/            the detectors; each emits Signals and decides nothing
│   └── linkage.py     the correlation engine — FOR-010, the reason this exists
├── rules/             YAML schema, evaluator, and builtin/*.yml
├── scoring/           suppression, baselining, risk score
└── report/            markdown, json, sarif

corpus/malicious/      inert attack reproductions (detection rate)
corpus/benign/         hard negatives (false-positive rate)
tests/benchmark/       enforces both rates as a release gate
```

## The one idea worth knowing

Engines emit **signals** — cheap, numerous observations that mean nothing alone.
Rules are declarative predicates *over signals*. Correlation joins signals across
files.

Keeping signals and findings apart is what lets entropy be a scoring feature
rather than a tripwire, what makes rule authoring a YAML exercise, and what makes
[FOR-010](architecture.md#linkagepy--the-correlation-engine) expressible at all.
