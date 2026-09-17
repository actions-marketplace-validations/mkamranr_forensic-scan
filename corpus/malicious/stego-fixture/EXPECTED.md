# Expected: FOR-012, FOR-010

A structurally valid PNG that renders normally, with a gzip stream appended past
its IEND chunk. A test harness seeks past the image data and decompresses it.
