/* FNV-1a and a small block mixer. Both are loops that XOR and shift over a
 * buffer -- structurally identical to a payload decoder, and entirely normal.
 * This is the hard case the bitwise-loop detector has to live with. */
#include <stdint.h>
#include <stddef.h>

uint64_t fnv1a(const uint8_t *data, size_t len) {
    uint64_t hash = 1469598103934665603ULL;
    for (size_t i = 0; i < len; i++) {
        hash ^= (uint64_t)data[i];
        hash *= 1099511628211ULL;
    }
    return hash;
}

uint32_t rotl32(uint32_t x, int r) {
    return (x << r) | (x >> (32 - r));
}

void mix_block(uint32_t state[4], const uint32_t input[4]) {
    for (int i = 0; i < 4; i++) {
        state[i] ^= input[i];
        state[i] = rotl32(state[i], 7 + i);
        state[i] += state[(i + 1) & 3];
    }
}

uint32_t checksum(const uint8_t *data, size_t len) {
    uint32_t acc = 0;
    for (size_t i = 0; i < len; i++) {
        acc = (acc << 5) ^ (acc >> 27) ^ data[i];
    }
    return acc;
}
