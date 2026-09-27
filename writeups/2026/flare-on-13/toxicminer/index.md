# ToxicMiner

- Category: rev

"We've chained your terminal to a rogue CPU miner that has zero interest in the blockchain and every interest in turning your processor into weapons-grade slag. Dissect the binary before you bake alive."

`ToxicMiner.exe` is a static build of **cpuminer-multi 1.3.7** (MSVC, with libcurl/OpenSSL/jansson/pthreads-win32) carrying a few author patches. It is not packed and has no TLS-callback trickery — the whole thing is a real miner with one hijacked function, and the flag is gated behind a fake "proof-of-work" whose only real input is your disk's volume serial number.

### Solution

##### 1. Find the patch under the miner

The patched `main` forces algorithm #39 (`sha256d`), sets the default pool to `127.0.0.1`, and ships a Base64 **decoy** pool password `m1n3_y0ur_0wn_bus1n3ss@flare.com` — note the wrong domain (`.com`, not `flare-on.com`), so it is a trap, not the flag. The real logic is the hijacked scan-hash routine at `sub_140134f70`:

- It reads the current drive's **volume serial number** via `GetVolumeInformationA`.
- If the pool **username is 64 hex characters**, it is parsed as a 32-byte target.
- For each nonce it computes `SHA256d(serial ‖ nonce)`; when that equals the target it calls `derive_key(serial, 0x0b501e7e)` (`sub_140134ca0`), uses the result to RC4-decrypt a 51-byte blob at `0x1401bd3b0` (`sub_140134d70`), prints `Accepted: <flag>`, and exits.

The username/nonce mining is just there to *reach* the code path. `derive_key` depends only on the volume serial and the constant `0x0b501e7e` — **the sole unknown is a 32-bit serial**, so this is a 2³² search with the `@flare-on.com` suffix as the oracle.

##### 2. The trap: "SHA-256" is not SHA-256

`derive_key` computes `SHA256d(serial ‖ 0x0b501e7e)` and takes the first 16 bytes of the digest as the RC4 key. The compression function `sub_140135240` looks exactly like textbook SHA-256 — correct IV, correct round constants, correct message schedule — so it is tempting to reimplement it and brute-force offline. That is the trap, and it cost two full 40-minute searches that could never have hit.

Reading the function all the way to its `ret` reveals one extra step *after* the standard Davies-Meyer feed-forward (traced from `0x140136230`–`0x140136264`):

```c
state[0] += a; ... state[7] += h;          // normal SHA-256 feed-forward
uint32_t w0 = state[0], w1 = state[1];
uint8_t  tval = MIXTAB[w0 & 0xff];         // 256-byte table @ 0x1401bd270
uint32_t off  = w1 % 28;                    // computed via a magic-multiply divide
uint32_t mixval; memcpy(&mixval, (uint8_t*)state + off, 4);  // UNALIGNED read into state
state[0] = (uint32_t)tval ^ mixval ^ w0;    // word 0 only; words 1..7 stay standard
```

Only word 0 is corrupted, unconditionally, on every call — so it applies to both compressions of the double hash. Getting this bit-exact (the `% 28` is a `0x24924925` magic-multiply, the read into `state` is unaligned) is fiddly and error-prone.

##### 3. Skip the reimplementation — call the binary's own code

Rather than perfectly clone a deliberately-mutated hash, the robust move is to let the binary compute it. `ToxicMiner.exe` maps cleanly with `LoadLibraryA`, so a tiny Windows harness resolves `derive_key` and `rc4` by RVA and brute-forces the serial by calling the *real* functions — no crypto modelling at all. A sanity check against a known-good decrypt (the analysis VM's own serial `0xB2C74207`) confirms the harness before the sweep:

```c
HMODULE h = LoadLibraryA("ToxicMiner.exe");
uintptr_t base = (uintptr_t)h;
derive_key_fn derive_key = (derive_key_fn)(base + 0x134ca0);
rc4_fn        rc4        = (rc4_fn)(base + 0x134d70);
uint8_t *ct = (uint8_t*)(base + 0x1bd3b0);   // 51-byte ciphertext

for (uint64_t s = 0; s <= 0xffffffff; s++) {
    uint8_t key[32], out[52] = {0};
    derive_key((uint32_t)s, 0x0b501e7e, key);
    rc4(key, 16, ct, 51, out);
    if (looks_like_flag(out, 51))            // printable & ends "@flare-on.com"
        printf("FOUND serial=0x%08llx  flag=%s\n", s, out);
}
```

Full harness: [`harness_brute.c`](harness_brute.c). The 2³² sweep finds a single match at serial `0x01CEC01D`.

**Flag:** `cpu_m3lt3d_4nd_all_i_g0t_w4s_th1s_fl4g@flare-on.com`

### Takeaways

- A matching IV, K-table, and message schedule are **not** proof a function is stock SHA-256. Read it to the final `ret` — the mutation here was a single extra XOR into word 0, invisible unless you trace past the feed-forward.
- When a primitive is only *slightly* non-standard and it is embedded in a loadable binary, calling the binary's own function via `LoadLibrary` + RVA is faster and more reliable than reimplementing it. You brute-force against ground truth instead of against your own possibly-wrong model.
