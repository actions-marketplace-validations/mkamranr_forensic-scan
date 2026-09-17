# Malicious corpus

Synthetic reproductions of real attack *structures*, used to measure detection
rate. Every sample here is **inert**:

- No sample contains a working payload, exploit, or shellcode.
- Where a real attack would execute a backdoor, these write a marker file or
  print a line. Nothing reaches the network, touches a real path, or persists.
- No sample is copied from real malware. They reproduce the *shape* of published
  attacks — what a scanner must recognise — not their contents.

This distinction matters: a detection corpus that shipped live payloads would
make this repository a distribution vector for the thing it exists to stop.

Each directory contains an `EXPECTED.md` naming the rules that should fire.
`tests/benchmark/` asserts that they do.
