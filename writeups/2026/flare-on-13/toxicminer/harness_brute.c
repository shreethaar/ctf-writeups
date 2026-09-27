#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

typedef void (*derive_key_fn)(uint32_t serial, uint32_t magic, void *out16);
typedef void (*rc4_fn)(const uint8_t *key, uint32_t keylen, const uint8_t *in, uint32_t inlen, uint8_t *out);

static int looks_like_flag(const uint8_t *p, int n) {
    static const char suffix[] = "@flare-on.com";
    int sl = (int)strlen(suffix);
    for (int start = 0; start + sl <= n; start++) {
        if (memcmp(p + start, suffix, sl) == 0) {
            int ok = 1;
            for (int i = 0; i < start + sl; i++) {
                uint8_t c = p[i];
                if (c < 0x20 || c > 0x7e) { ok = 0; break; }
            }
            if (ok) return 1;
        }
    }
    return 0;
}

int main(int argc, char **argv) {
    HMODULE h = LoadLibraryA("ToxicMiner.exe");
    if (!h) { printf("LoadLibrary failed: %lu\n", GetLastError()); return 1; }
    uintptr_t base = (uintptr_t)h;
    derive_key_fn derive_key = (derive_key_fn)(base + 0x134ca0);
    rc4_fn rc4 = (rc4_fn)(base + 0x134d70);
    uint8_t *ct = (uint8_t*)(base + (0x1401bd3b0 - 0x140000000));
    uint32_t magic = 0x0b501e7e;

    // sanity check against the known-correct ground truth first
    uint8_t key[32], out[52] = {0};
    derive_key(0xb2c74207, magic, key);
    rc4(key, 16, ct, 51, out);
    printf("sanity (serial=0xb2c74207): ");
    for (int i = 0; i < 51; i++) printf("%02x", out[i]);
    printf("\n");
    printf("expected:                   4181695ead650f169597effea99fc57d0b73fc7784be1cd4d7d7f4bcb9cf308e1fddc51b61acdbda57142a1e61de1d1af61d1c\n\n");

    uint64_t start = 0, end = 0xffffffffULL;
    if (argc >= 3) { start = strtoull(argv[1], NULL, 16); end = strtoull(argv[2], NULL, 16); }
    printf("scanning 0x%08llx .. 0x%08llx\n", (unsigned long long)start, (unsigned long long)end);
    fflush(stdout);

    for (uint64_t s = start; s <= end; s++) {
        derive_key((uint32_t)s, magic, key);
        rc4(key, 16, ct, 51, out);
        if (looks_like_flag(out, 51)) {
            printf("FOUND serial=0x%08llx  flag=%s\n", (unsigned long long)s, out);
            fflush(stdout);
        }
        if ((s & 0xFFFFFF) == 0) { printf("."); fflush(stdout); }
        if (s == 0xffffffffULL) break; // avoid wraparound on uint64_t loop at max
    }
    printf("\ndone\n");
    return 0;
}
