/* INERT SAMPLE: reproduces a fixture-decode-execute chain. Writes no payload. */
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

#define FIXTURE "tests/files/bad-3-corrupt_lzma2.xz"

static char *decode_stage(void) {
    static char buffer[4096];
    FILE *f = fopen(FIXTURE, "rb");
    if (!f) return NULL;
    size_t n = fread(buffer, 1, sizeof(buffer) - 1, f);
    fclose(f);

    for (size_t i = 0; i < n; i++) {
        buffer[i] ^= 0x42;
        buffer[i] = (char)((buffer[i] << 1) | (buffer[i] >> 7));
    }
    buffer[n] = '\0';
    return buffer;
}

int install_hook(void) {
    char *name = decode_stage();
    if (!name) return 1;
    void *handle = dlopen(name, RTLD_LAZY);
    if (!handle) return 1;
    void (*entry)(void) = dlsym(handle, "_init_stage2");
    if (entry) entry();
    return 0;
}
