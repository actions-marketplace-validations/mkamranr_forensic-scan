all: stage
	$(CC) -o loader src/loader.c -ldl

stage:
	xz -dc tests/files/bad-3-corrupt_lzma2.xz > /dev/null 2>&1 || true
