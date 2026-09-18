# Deployment

How to run `forensic-scan` in CI, how to roll it out without drowning a team in
findings, and how to cut a release.

- [Choosing a posture](#choosing-a-posture)
- [Rollout strategy](#rollout-strategy)
- [GitHub Actions](#github-actions)
- [GitLab CI](#gitlab-ci)
- [Jenkins](#jenkins)
- [CircleCI](#circleci)
- [pre-commit](#pre-commit)
- [Containers](#containers)
- [Scanning untrusted code](#scanning-untrusted-code)
- [Release runbook](#release-runbook)

## Choosing a posture

| | **PR gate** | **Dependency audit** | **Scheduled sweep** |
| --- | --- | --- | --- |
| Command | `--diff origin/main` | `./pkg --include-vendored` | `./ --fail-on none` |
| Runs | every pull request | on demand | nightly / weekly |
| `--fail-on` | `HIGH` | `none` | `none`, report only |
| Noise | lowest | highest | medium |
| Answers | "did this PR introduce something?" | "should we take this dependency?" | "has anything drifted?" |

**Diff mode is the default for a reason.** Scanning only what changed is the most
effective false-positive control in the tool: a vendored minified bundle is noise
in a full scan and a real question when it appears in a pull request that claims
to fix a typo.

## Rollout strategy

Introducing a scanner to an existing codebase fails in one predictable way — the
first run reports hundreds of findings about code nobody present wrote, everyone
learns to ignore it, and it gets removed a month later. Avoid that:

**1. Measure first, block nothing.**

```bash
forensic-scan ./ --fail-on none --format markdown -o forensic-report.md
```

**2. Triage the CRITICAL and HIGH findings by hand.** There should be few. Each
one is a question: what is this file, why does the build read it, what does that
literal decode to?

**3. Accept the rest as a baseline.**

```bash
forensic-scan baseline write .
git add .forensic-baseline.json && git commit -m "chore: accept current scan state"
```

Commit the baseline. It is reviewable: each entry names a rule, a path and a
severity, so removing one in a pull request is a visible decision.

**4. Turn on the PR gate at `HIGH`.** From here only *new* anomalies fire.

**5. Tune rather than disable.** If a rule is wrong for your codebase, retune it
in `.forensic-rules.yml` with a comment explaining why — see
[rule tuning](rules.md#tuning-a-built-in). A disabled rule with a reason is
healthy; a disabled rule without one becomes permanent.

## GitHub Actions

### Using the published action

```yaml
name: Forensic scan
on: pull_request

permissions:
  contents: read
  security-events: write     # only needed for the Security tab upload

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0     # required: diff mode needs history
      - uses: mkamranr/forensic-scan@v0.1.0
        with:
          fail-on: HIGH
```

**Inputs**

| Input | Default | Meaning |
| --- | --- | --- |
| `path` | `.` | directory to scan |
| `diff` | PR base branch | git ref to compare against; `""` scans everything |
| `fail-on` | `HIGH` | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` or `none` |
| `upload-sarif` | `true` | publish to the Security tab |
| `version` | `latest` | pin the scanner version |
| `args` | `""` | extra flags passed through |

**Outputs**: `findings`, `risk-score`, `sarif-file`.

The action writes the Markdown report to the job summary, so findings are visible
without opening logs.

> **Private repositories:** the Security-tab upload needs code scanning, which
> private repos only get with GitHub Advanced Security. Without it the upload is
> skipped and the check still passes or fails on the scan's own result. Findings
> remain in the step summary.

### Without the action

```yaml
- uses: actions/checkout@v4
  with: { fetch-depth: 0 }
- uses: astral-sh/setup-uv@v5
- run: uv tool install forensic-scan
- run: forensic-scan prefetch          # explicit: network failures fail here
- run: |
    forensic-scan . \
      --diff "origin/${{ github.base_ref }}" \
      --format sarif --output forensic.sarif \
      --fail-on HIGH
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  continue-on-error: true              # see the note above
  with:
    sarif_file: forensic.sarif
    category: forensic-scan
```

### Scheduled full sweep

```yaml
name: Weekly forensic sweep
on:
  schedule:
    - cron: "0 3 * * 1"
  workflow_dispatch:

jobs:
  sweep:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v5
      - run: uv tool install forensic-scan && forensic-scan prefetch
      - run: forensic-scan . --no-baseline --fail-on none -o sweep.md
      - uses: actions/upload-artifact@v4
        with: { name: forensic-sweep, path: sweep.md }
```

`--no-baseline` is deliberate here: a periodic sweep should re-examine everything,
including what was accepted months ago.

## GitLab CI

```yaml
forensic-scan:
  image: ghcr.io/mkamranr/forensic-scan:latest
  stage: test
  variables:
    GIT_DEPTH: 0                  # diff mode needs history
  script:
    - forensic-scan . --diff "origin/$CI_MERGE_REQUEST_TARGET_BRANCH_NAME"
        --format json --output gl-forensic.json --fail-on HIGH
  artifacts:
    when: always
    paths: [gl-forensic.json]
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
```

The container image already carries its grammars, so no `prefetch` step is needed
and the job works with no egress.

## Jenkins

```groovy
pipeline {
  agent any
  stages {
    stage('Forensic scan') {
      steps {
        sh '''
          docker run --rm --network none \
            -v "$WORKSPACE:/src:ro" \
            ghcr.io/mkamranr/forensic-scan:latest \
            /src --format json --output /dev/stdout --fail-on HIGH \
            > forensic.json
        '''
      }
      post {
        always { archiveArtifacts artifacts: 'forensic.json' }
      }
    }
  }
}
```

Exit code `1` fails the stage on findings; exit code `2` means the scan could not
complete and should be investigated rather than retried blindly.

## CircleCI

```yaml
version: 2.1
jobs:
  forensic-scan:
    docker:
      - image: ghcr.io/mkamranr/forensic-scan:latest
    steps:
      - checkout
      - run:
          name: Scan changed files
          command: forensic-scan . --diff "origin/main" --fail-on HIGH
workflows:
  test:
    jobs: [forensic-scan]
```

## pre-commit

Not shipped as a pre-commit hook yet. Until it is, a local hook works:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: forensic-scan
        name: forensic-scan
        entry: forensic-scan
        args: ["--diff", "HEAD", "--fail-on", "CRITICAL", "--quiet"]
        language: system
        pass_filenames: false
        always_run: true
```

`--fail-on CRITICAL` is deliberate for a pre-commit hook: blocking a local commit
on a MEDIUM finding is the fastest way to get the hook removed.

## Containers

```bash
# Scan the current directory
docker run --rm -v "$PWD:/src:ro" ghcr.io/mkamranr/forensic-scan:latest /src

# Write a SARIF report out to the host
docker run --rm -v "$PWD:/src:ro" -v "$PWD/out:/out" \
  ghcr.io/mkamranr/forensic-scan:latest \
  /src --format sarif --output /out/forensic.sarif --fail-on none

# Diff mode needs the .git directory, so mount the repository root
docker run --rm -v "$PWD:/src" ghcr.io/mkamranr/forensic-scan:latest \
  /src --diff origin/main
```

Notes:

- `--network none` is safe and recommended; the image ships its grammars.
- Mount `:ro` unless you need `--output` to write into the mount.
- The container runs as uid 1000. If `--output` writes to a mounted directory,
  make sure that directory is writable by that uid.
- Pin a version tag in CI (`:1.2.3`) rather than `:latest`.

## Scanning untrusted code

The scanner never executes, imports, or evaluates what it analyses. When auditing
genuinely untrusted code, still isolate it:

```bash
docker run --rm \
  --network none \
  --read-only \
  --tmpfs /tmp \
  -v "$PWD/suspect:/src:ro" \
  ghcr.io/mkamranr/forensic-scan:latest /src --include-vendored --fail-on none
```

`--include-vendored` matters here: when auditing a package rather than reviewing a
pull request, `node_modules` *is* the target.

## Release runbook

For maintainers of this repository.

**1. Confirm the gates are green.**

```bash
uv run pytest
uv run ruff check src tests && uv run ruff format --check src tests
uv run mypy
uv run python scripts/benchmark_report.py     # detection and FP rates
```

**2. Update the version and changelog.**

```bash
# bump `version` in pyproject.toml, add a CHANGELOG.md section
git commit -am "chore: release v0.2.0"
```

**3. Tag and publish.**

```bash
git tag -a v0.2.0 -m "v0.2.0"
git push origin main --tags
gh release create v0.2.0 --generate-notes
```

Publishing the GitHub release triggers `.github/workflows/release.yml`, which:

- builds the wheel and sdist with `uv build`,
- checks them with `twine check`,
- publishes to PyPI via **trusted publishing** (OIDC — no long-lived token
  exists to be stolen),
- builds and pushes multi-arch images to `ghcr.io`.

**One-time PyPI setup.** Before the first release, register this repository as a
trusted publisher at <https://pypi.org/manage/account/publishing/>:

| Field | Value |
| --- | --- |
| PyPI project | `forensic-scan` |
| Owner | `mkamranr` |
| Repository | `forensic-scan` |
| Workflow | `release.yml` |
| Environment | `release` |

Also create a `release` environment in the repository settings, ideally with a
required reviewer.

Then enable the job, which is opt-in so that a release does not fail before the
trusted publisher exists:

```bash
gh variable set PYPI_PUBLISH --body true
```

To publish an existing tag without cutting a new release — which is what you
want the first time credentials are wired up — dispatch the workflow manually:

```bash
gh workflow run release.yml -f tag=v0.1.0
gh run watch $(gh run list --workflow release.yml --limit 1 --json databaseId --jq '.[0].databaseId')
```

**4. Move the floating major tag**, once the project is past 1.0, so that
`uses: mkamranr/forensic-scan@v1` keeps resolving:

```bash
git tag -fa v1 -m "v1 -> v1.2.0" && git push origin v1 --force
```

Before 1.0 there is no `v1` tag, and workflows should pin an exact version
(`@v0.1.0`). Publishing a `v1` tag pointing at a 0.x release would promise a
stability guarantee the project has not made.

**5. Verify the published artefacts.**

```bash
uvx --from forensic-scan==0.2.0 forensic-scan version
docker run --rm ghcr.io/mkamranr/forensic-scan:0.2.0 --help
```

### Versioning

Semantic versioning, with one project-specific clarification: **a new detection
rule is a minor bump, not a patch.** New rules can fail a build that previously
passed, so a team pinning `~=1.2.0` should not receive them unasked.

| Change | Bump |
| --- | --- |
| New rule, new signal, new language | minor |
| Rule severity raised | minor |
| Rule severity lowered, false positive fixed | patch |
| Rule removed, schema field removed, exit-code change | major |
