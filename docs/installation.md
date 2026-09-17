# Installation

- [Requirements](#requirements)
- [Install](#install)
- [First run: grammars](#first-run-grammars)
- [Verify the installation](#verify-the-installation)
- [Air-gapped and offline environments](#air-gapped-and-offline-environments)
- [Platform notes](#platform-notes)
- [From source](#from-source)
- [Upgrading and uninstalling](#upgrading-and-uninstalling)
- [Troubleshooting](#troubleshooting)

## Requirements

| | |
| --- | --- |
| **Python** | 3.10, 3.11, 3.12 or 3.13 |
| **Operating system** | Linux, macOS, Windows |
| **git** | required only for `--diff` mode |
| **Network** | once, to fetch tree-sitter grammars — see [below](#first-run-grammars) |
| **Disk** | ≈120 MB (≈40 MB package and dependencies, ≈80 MB grammar cache) |

No compiler or system library is needed. Magic-byte detection is implemented
in-tree rather than through `libmagic`, precisely so that installation never
depends on a system package.

## Install

### uv (recommended)

```bash
uv tool install forensic-scan
```

Or run it without installing at all:

```bash
uvx forensic-scan ./
```

### pipx

```bash
pipx install forensic-scan
```

### pip

Prefer `uv` or `pipx`, which keep the tool isolated from your project's
environment. If you do use pip, use a virtual environment:

```bash
python -m venv .venv && source .venv/bin/activate
pip install forensic-scan
```

### Docker

The image ships its grammars, runs unprivileged, and needs no network:

```bash
docker run --rm --network none -v "$PWD:/src:ro" \
  ghcr.io/mkamranr/forensic-scan:latest /src
```

| Detail | Value |
| --- | --- |
| Image | `ghcr.io/mkamranr/forensic-scan` |
| Tags | `latest`, `1`, `1.2`, `1.2.3` |
| Platforms | `linux/amd64`, `linux/arm64` |
| User | `scanner` (uid 1000), non-root |
| Working directory | `/src` — mount your repository here |
| Entrypoint | `forensic-scan`, so pass flags directly |

Mount read-only (`:ro`) when scanning untrusted code. Add `--network none` to
remove any possibility of egress.

### GitHub Action

No installation required. See the [deployment guide](deployment.md#github-actions).

## First run: grammars

`forensic-scan` parses with [tree-sitter](https://tree-sitter.github.io/), and
the grammars are **downloaded on first use** and cached, not bundled in the
wheel. The first scan on a new machine therefore needs network access.

Warm the cache explicitly:

```bash
forensic-scan prefetch
```

```
ok      c
ok      javascript
ok      python
ok      tsx
ok      typescript

Cache: /Users/you/Library/Caches/tree-sitter-language-pack/v1.20.0/libs
```

Cache locations:

| Platform | Path |
| --- | --- |
| Linux | `$XDG_CACHE_HOME/tree-sitter-language-pack/` or `~/.cache/tree-sitter-language-pack/` |
| macOS | `~/Library/Caches/tree-sitter-language-pack/` |
| Windows | `%LOCALAPPDATA%\tree-sitter-language-pack\` |

**If a grammar cannot be loaded, the scan exits `2` and says so.** It does not
report "no findings". An incomplete scan that looks clean is the one failure mode
a security tool must never have.

## Verify the installation

```bash
forensic-scan version
# forensic-scan 0.1.0 (23 built-in rules)

forensic-scan rules list        # the active rule set
forensic-scan prefetch          # grammars are cached
```

End-to-end check against a known-bad input:

```bash
mkdir -p /tmp/fs-check && cd /tmp/fs-check
printf 'import base64\nB = "%s"\nexec(base64.b64decode(B))\n' "$(head -c 200 /dev/urandom | base64 | tr -d '\n')" > payload.py

forensic-scan . --fail-on none
echo "exit: $?"     # expect findings, and exit 0 because --fail-on none
```

You should see `FOR-001` or `FOR-004` reported at CRITICAL.

## Air-gapped and offline environments

Three options, in order of preference.

**1. Use the container image.** Grammars are baked in at build time, so it works
with `--network none` and needs nothing else.

**2. Warm the cache on a connected machine, then copy it.**

```bash
# On a connected machine
forensic-scan prefetch
CACHE=$(forensic-scan prefetch | grep '^Cache:' | cut -d' ' -f2-)
tar czf grammars.tgz -C "$(dirname "$(dirname "$CACHE")")" .

# On the air-gapped machine, extract to the cache path for that platform
mkdir -p ~/.cache/tree-sitter-language-pack
tar xzf grammars.tgz -C ~/.cache/tree-sitter-language-pack
forensic-scan prefetch   # should report ok for every language, offline
```

**3. Point `XDG_CACHE_HOME` at a shared read-only location:**

```bash
export XDG_CACHE_HOME=/opt/shared-cache
forensic-scan ./
```

In CI, run `forensic-scan prefetch` as an explicit step so a network problem
fails a named step rather than silently changing your results.

## Platform notes

### Linux

Nothing special. `glibc` and `musl` are both fine — grammars are loaded as
prebuilt shared objects matching your platform.

### macOS

Works on both Apple Silicon and Intel. If you installed Python from
python.org and see TLS errors during `prefetch`, run the bundled
`Install Certificates.command` from your Python installation directory.

### Windows

Works under PowerShell and WSL. Two notes:

- Path globs in `--exclude` use forward slashes regardless of platform:
  `--exclude "tests/**"`.
- `--diff` mode requires `git` on `PATH`.

### CI runners

Use the [deployment guide](deployment.md). The short version: check out with
`fetch-depth: 0` so diff mode has history, and run `prefetch` as its own step.

## From source

```bash
git clone https://github.com/mkamranr/forensic-scan
cd forensic-scan

uv sync                       # creates .venv and installs dev dependencies
uv run forensic-scan prefetch
uv run forensic-scan --help
```

Development commands:

```bash
uv run pytest                     # full suite (519 tests)
uv run pytest tests/unit -q       # fast: unit only
uv run pytest tests/benchmark     # detection and false-positive gates
uv run ruff check src tests
uv run ruff format src tests
uv run mypy                       # strict
```

Build a distribution:

```bash
uv build                          # dist/*.whl and dist/*.tar.gz
```

## Upgrading and uninstalling

```bash
uv tool upgrade forensic-scan     # or: pipx upgrade forensic-scan
uv tool uninstall forensic-scan   # or: pipx uninstall forensic-scan
```

Removing the grammar cache is separate — delete the directory that
`forensic-scan prefetch` prints, or:

```python
python -c "import tree_sitter_language_pack as p; p.clean_cache()"
```

Baselines (`.forensic-baseline.json`) and rule files (`.forensic-rules.yml`)
live in your repository and are unaffected.

## Troubleshooting

### `scan incomplete — N source file(s) were not analysed`

A grammar could not be loaded. The scan exited `2` rather than reporting a
misleading clean result.

```bash
forensic-scan prefetch     # while online
```

If you are offline, see [air-gapped setup](#air-gapped-and-offline-environments).

### `DownloadError: Failed to fetch manifest`

The grammar download was blocked — a proxy, a firewall, or no network. Set proxy
variables and retry:

```bash
export HTTPS_PROXY=http://proxy.internal:8080
forensic-scan prefetch
```

### `<path> is not a git repository; diff mode requires one`

`--diff` needs a git repository. Use a plain path scan instead, or run from
inside the repository.

### `unknown git ref: origin/main`

The ref is not present locally. In CI this usually means a shallow checkout:

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0
```

Locally: `git fetch origin main`.

### The scan is slow on a large repository

```bash
forensic-scan ./ --jobs 8            # default is core count, capped at 8
forensic-scan --diff origin/main     # far faster, and the right default for CI
```

Vendored directories (`node_modules`, `vendor`, `third_party`) are skipped by
default; `--include-vendored` opts back in and will be much slower.

### Too many findings on first run

Expected on an existing codebase, and the reason baselines exist:

```bash
forensic-scan baseline write .
```

See [Adopting on an existing codebase](../README.md#adopting-on-an-existing-codebase)
and [rule tuning](rules.md#tuning-a-built-in).

### A finding I believe is wrong

That is a bug worth reporting — the false-positive rate is a published release
gate. Open an issue with the code that triggered it. See
[CONTRIBUTING.md](../CONTRIBUTING.md).
