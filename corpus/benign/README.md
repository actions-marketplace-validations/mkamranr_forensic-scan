# Benign corpus

Real-world constructs that *look* like the things this scanner hunts for, and
are not. Every finding produced here is a false positive and a bug.

These are chosen to be hard, not easy. Each one trips a detector that a naive
implementation would ship:

| Sample | Trips |
|---|---|
| `minified-bundle/` | high entropy, mangled identifiers, `Function` calls |
| `generated-code/` | unnatural identifier distribution, machine-generated shape |
| `embedded-cert/` | a 1.6 KB base64 literal, entropy above every threshold |
| `real-fixtures/` | high-entropy binaries in a fixtures directory |
| `legit-setup/` | `subprocess` and a compiler invocation in `setup.py` |
| `legit-makefile/` | shell commands and file references in build recipes |
| `crypto-code/` | XOR and shift loops over a buffer — a hash function |
| `lookup-tables/` | long numeric arrays — a CRC table and a colour palette |

The false-positive rate measured against this corpus is published in the README.
It is the number that decides whether a maintainer leaves the scanner switched
on, so it is treated as a release gate rather than a nice-to-have.
