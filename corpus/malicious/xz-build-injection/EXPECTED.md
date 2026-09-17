# Expected: FOR-010, FOR-008, FOR-013

Reproduces the structure of the XZ Utils backdoor (CVE-2024-3094).

1. `m4/build-to-host.m4` names a test fixture during `./configure`.
2. `tests/files/bad-3-corrupt_lzma2.xz` is an opaque high-entropy blob sitting
   in a directory of deliberately "corrupt" test archives.
3. `src/loader.c` reads that fixture and XORs the bytes.
4. The decoded result reaches `dlopen`.

No individual step is unusual. The chain is. FOR-010 exists for exactly this.
