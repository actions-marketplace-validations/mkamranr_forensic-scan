# Security policy

## Reporting a vulnerability

Report vulnerabilities in `forensic-scan` itself through
[GitHub private vulnerability reporting](https://github.com/mkamranr/forensic-scan/security/advisories/new).
Please do not open a public issue first.

We aim to acknowledge within 3 working days and to ship a fix or a mitigation
within 30 days for anything exploitable.

## What counts as a vulnerability here

This tool parses hostile input by design — that is its job — so the threat model
is specific:

**In scope**

- Code execution, file writes, or network access triggered by scanning a
  repository. The scanner must never execute, import, or evaluate anything it
  analyses.
- Path traversal: a scanned repository causing reads or writes outside the
  scanned tree (for example through symlinks or crafted paths in a rule file).
- Denial of service that is disproportionate — a small input causing unbounded
  memory or time.
- Secrets or absolute host paths leaking into reports that get uploaded to CI.

**Out of scope**

- **A missed detection is not a vulnerability.** This scanner measures
  concealment heuristically; evading it is expected and is a detection gap.
  Please file those as issues, with a structural reproduction.
- A false positive, for the same reason.
- Slowness on a very large repository, absent a disproportion as above.

## Reporting a detection gap

If you have a real attack the scanner misses, open a normal issue. Include a
*structural* reproduction — the shape of the attack — not a working payload or a
real malware sample. See the corpus safety rules in
[`CONTRIBUTING.md`](CONTRIBUTING.md).

## Scanning untrusted code

The scanner never executes what it analyses. It does read files and shells out
to `git` in `--diff` mode. When auditing genuinely untrusted code, run it in the
container, which is unprivileged and ships its grammars, so it needs no network
at all:

```bash
docker run --rm --network none -v "$PWD:/src:ro" \
  ghcr.io/mkamranr/forensic-scan:latest /src
```

Running the *pip-installed* scanner with no network requires a warmed grammar
cache (`forensic-scan prefetch`, once, while online). Without one it exits 2 and
reports the scan as incomplete — it will not return a clean result it could not
establish.

## Supply chain

- Releases are published to PyPI via GitHub Actions trusted publishing (OIDC).
  No long-lived token exists to be stolen.
- Container images are built and published from tagged releases only.
- The project scans itself on every pull request; results appear in the Security
  tab.
