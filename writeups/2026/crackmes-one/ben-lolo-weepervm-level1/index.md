---
title: "WeeperVM -- Level 1"
layout: default
---

# WeeperVM -- Level 1

Delve into the world of virtualized code to recover a sacred phrase. Various obstacles hinder static and dynamic analysis, but can be overcome using normal reversing techniques.

- Category: rev
- Difficulty: 5.0
- Challenge author: Ben_Lolo
- Challenge link: [crackmes.one](https://crackmes.one/crackme/67f9bdc38f555589f3530a85)

The description advertises encrypted strings, anti-debug, anti-breakpoint, anti-thread-suspension, anti-patch, and a custom VM — and suggests writing a Ghidra processor module or a Binary Ninja architecture plugin. None of that turns out to be necessary. The VM is small enough that a 120-line Python emulator covers the whole ISA, and once the checker is understood it is a **Feistel network**, which means the answer can be *decrypted* rather than searched for. Every protection in that list is defeated by simply never running the binary.

### Solution:

##### 1. Two sections that should not exist

```bash
$ file WeeperVM--Level_1
WeeperVM--Level_1: ELF 64-bit LSB executable, x86-64, version 1 (SYSV),
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, stripped
```

Non-PIE, so everything sits at fixed addresses off `0x10000`. The section table is where the challenge announces itself:

```bash
$ readelf -SW WeeperVM--Level_1 | grep -E 'weep|lotus|text|rodata'
  [10] .text    PROGBITS  0000000000010a00  000a00 00119f  00  AX  0   0 16
  [11] .rodata  PROGBITS  0000000000011ba0  001ba0 000348  00   A  0   0  8
  [14] .weep    PROGBITS  0000000000011f60  001f60 000cd4  00   A  0   0 32
  [20] .lotus   PROGBITS  0000000000012f20  002f20 000100  00  WA  0   0 32
```

`.weep` is 0xcd4 = 3284 bytes, exactly 821 dwords. `.lotus` is 256 bytes and writable. Those are the VM's code and memory.

##### 2. Finding main

`kuna functions` reports 34 functions, but 25 are PLT thunks and none of the rest is `main`. The entry point is the giveaway:

```c
void sub_10a00(unsigned long a0, unsigned long a1, unsigned long a2)
{
  (*dat_12e18)(0x11a9b, v2, &Stack0000000000000008, 0, 0, a2, v1);
  do { } while (true);
}
```

That indirect call is `__libc_start_main`, and its first argument is `main`. So **main is at `0x11a9b`** — inside `.text`, but never reached by recursive descent because the only reference to it is that GOT-indirect call. Worth noting that turning on aggressive function discovery (`--option listing on --option aif on --option funcstart_patterns on`) did *not* grow the list; this was never a discovery-heuristics problem, and reading `_start` was the whole fix.

##### 3. main is an interpreter loop

```c
v1 = 0;
while (true) {
    dat_13040 = v1;                                   // PC
    if (!*(int *)((long)v1 * 4 + 0x11f60)) break;     // fetch from .weep, 0 = halt
    if (sub_11a28()) return 1;                        // dispatch one instruction
    v1 = dat_13040 + 1;                               // PC may have been rewritten
}
```

Reading `dat_13040` back after the dispatch is how jumps work: the handler writes the PC global and the loop picks it up. That gives the memory map:

| address | role |
|---------|------|
| `0x11f60` | `.weep` — code, one 32-bit word per instruction |
| `0x12f20` | `.lotus` — 256 bytes of byte-addressable VM memory |
| `0x13080` | 16 x 32-bit registers |
| `0x13040` | PC |
| `0x13060` | FLAGS |

##### 4. Decoding the weep ISA

`sub_11a28` is the dispatcher, and its first act is to decrypt its own operand:

```c
a0 = (a0 >> 0x10 & 0xff) * 0x1010101 ^ a0;
v5 = a0 >> 8 & 0xff;          // operand A  (dst)
v15 = a0 & 0xff;              // operand B  (src)
v3 = a0 >> 0x19 & 3;          // src mode
v10 = a0 >> 0x1b & 1;         // dst mode
switch (a0 >> 0x1c) { ... }   // opcode
```

Every instruction is XORed with its own byte 2 broadcast to all four lanes, so no two identical instructions look alike in a hexdump. After `w = raw ^ ((raw >> 16) & 0xff) * 0x01010101`:

| bits | meaning |
|-------|---------|
| 31-28 | opcode |
| 27 | dst mode: 0 = `r[A]`, 1 = `M[A]` |
| 26-25 | src mode: 0 = `r[B]`, 1 = `M[B]`, 2 = immediate `B` |
| 15-8 | operand A (dst) |
| 7-0 | operand B (src) |

Opcodes: `0 MOV`, `1 LDI/STI` (indirect through memory), `2 ADD`, `3 SUB`, `4 MUL`, `5 MOD`, `6 PUT`, `7 READ`, `9 CMP`, `10 JMP`, `11 AND`, `12 OR`, `13 XOR`, `14 SHL`, `15 SHR`. Opcode 8 is invalid and aborts.

Two details are easy to get wrong and both silently corrupt state:

- `MOV`/`ADD`/`AND`/`OR`/`XOR`/`SHL`/`SHR` targeting memory are **32-bit** accesses (`*(unsigned int *)((long)A + 0x12f20)`), while `CMP`/`LDI`/`PUT` are **byte** accesses.
- `CMP` sets `FLAGS = base | {1 equal, 2 greater, 4 less}` where `base` is `0x40`, or `0x60` if the sticky "input too long" bit `0x20` is set. `JMP` takes its *target from a register* and its condition as a mask, so `JMP r14, #64` — testing the always-set `0x40` — is an unconditional jump.

That register-sourced jump target is what makes the "janky functions" in the description: the bytecode fakes a calling convention with `r14` = callee and `r15` = return address, so `JMP r14, #64` is a call and `JMP r15, #64` is the matching return.

`PUT` and `READ` bypass libc entirely, going through raw `syscall(1, 1, buf, 1)` and `syscall(0, 0, buf, 1)` one byte at a time.

##### 5. An emulator, to check the reading is right

The ISA is small enough to just implement ([dis.py](dis.py), [vm.py](vm.py)). The payoff is immediate — the emulator reproduces the program's banner byte for byte, which is strong evidence the decode is correct before any of the hard analysis starts:

```
$ python3 vm.py WeeperVM--Level_1 AAAABBBBCCCC
 /\\\______________/\\\__/\\\\\\\\\\\\\\\__...
                                              (Ben_Lolo)
Long time no see, friend.
Let us speak the sacred phrase:
Have you forgotten it :(

[HALT steps=786 pc=820]
```

The disassembly is 821 instructions, and the interesting part starts at the only `READ`:

```
 358: 0a0e0a2e -> 04000420  MOV   r4      , #32
 359: 0d743470 -> 79004004  READ  M[64]   , r4
```

32 bytes of input land at `.lotus[64..95]`.

##### 6. The charset gate

```
 368: r6 = 64 ; 369: r6 += r12 ; 370: LDI r5, r6      # r5 = input[i]
 371: CMP   r5, M[62]      374: CMP r5, M[63]     375: CMP r5, M[254]
 377: MOV   r2, M[51] ; SUB r2, r5 ; CMP r2, #26 ; JMP accept if less
 381: MOV   r2, M[25] ; SUB r2, r5 ; CMP r2, #26 ; JMP accept if less
 385: MOV   r2, M[61] ; SUB r2, r5 ; CMP r2, #10 ; JMP accept if less
 389: JMP   r15, #64                                  # fall through = fail
```

The bounds are not immediates — they are read out of a table at `.lotus[0..63]`:

```
00000000: 4142 4344 4546 4748 494a 4b4c 4d4e 4f50  ABCDEFGHIJKLMNOP
00000010: 5152 5354 5556 5758 595a 6162 6364 6566  QRSTUVWXYZabcdef
00000020: 6768 696a 6b6c 6d6e 6f70 7172 7374 7576  ghijklmnopqrstuv
00000030: 7778 797a 3031 3233 3435 3637 3839 2829  wxyz0123456789()
```

A base64 alphabet with `()` where `+/` would be. So `M[25]` = `Z`, `M[51]` = `z`, `M[61]` = `9`, `M[62]` = `(`, `M[63]` = `)`, and `M[254]` = `_`. The three subtract-and-compare pairs are unsigned range checks for `a-z`, `A-Z` and `0-9`, giving a charset of `[A-Za-z0-9()_]`.

The loop covers all 32 positions, and the uninitialised tail of `.lotus` is not valid charset, so the input must be **exactly** 32 characters.

##### 7. The round key and the cipher

A short loop at 398-412 builds a 16-byte key by XORing two blocks of `.lotus` together — no input involved, so the key is a constant:

```
K0[i] = .lotus[160+i] ^ .lotus[176+i]   ->  46fc63eda6418771dc8d409cda61da1a
```

The main body (413-677) then processes the input as **two 16-byte blocks**, each split into `L` = bytes 0-7 and `R` = bytes 8-15. Per round, for each byte index `b` of `R`:

1. split `R[b]` into nibbles `hi`, `lo`
2. a key bit selects which halves of the S-box table are used —
   `SB = .lotus[128..143]` = `c7 f2 7e a9 e3 db b0 04 2c 6d 31 1a 96 4f 58 85`:

   ```c
   if (K[r1] & (1 << b))  P = ((SB[hi] & 0x0f) << 4) | ((SB[lo] & 0xf0) >> 4);
   else                   P = (SB[hi] & 0xf0) | (SB[lo] & 0x0f);
   ```
3. `P ^= K[r0]`
4. an 8-bit permutation, spelled out as eight mask/shift/or groups against the bit table at `.lotus[144..151]`: `7->4, 6->2, 5->7, 4->3, 3->5, 2->6, 1->0, 0->1`
5. a DES-style spread — for each bit `n`, `L[(b + KOFF[n]) % 8] ^= P & (0x80 >> n)` with `KOFF = [7,6,2,1,5,0,3,4]`

`r1` is the key index latched at the top of each round (`r1 = 7t mod 16` for round `t`) and stays fixed for the S-box selection; `r0` walks `r1..r1+7` across the eight bytes and feeds the XOR. Then `L` and `R` are swapped, 16 rounds total. Between the two blocks the key is rotated: `K'[(i+9)%16] = K[i]`.

The bit-spread in step 5 is where the "janky function" convention shows up — it is eight calls to a shared routine at `weep[570]`, each with a different `KOFF` constant and a different bit mask, using `r14`/`r15` as callee/return.

##### 8. The comparison, and the trap after it

The result is checked byte by byte against constants baked into the instruction stream:

```
 682: da46069a -> 9c0040dc  CMP   M[64]   , #220
 683: 57f2fcf0 -> a5000e02  JMP   r14     , #2      # greater -> fail
 684: 17b3bdb7 -> a4000e04  JMP   r14     , #4      # less    -> fail
 685: 20bcfdd3 -> 9c00416f  CMP   M[65]   , #111
 ...
 778: 8d282608 -> a5000e20  JMP   r14     , #32     # "input too long" -> fail
```

Scraping all 32 immediates gives the target:

```
dc6f56c2d34e507769b24de98ff52d122a9581e535db8a1014ffa704d0c1e574
```

Note `weep[778]`: even with all 32 bytes matching, the sticky `0x20` flag set by `READ` when the line ran long still sends you to the failure path.

##### 9. Invert it

Nothing here needs brute force or a solver. The construction is a textbook Feistel, so it inverts by running the rounds backwards with the key schedule reversed:

```
forward:  (L, R) -> (R, L ^ F(R))
inverse:  (L', R') -> (R' ^ F(L'), L')
```

The one thing that has to be right is the swap accounting. A **second swap loop at `weep[623..641]`** runs after all 16 rounds and undoes the final swap, exactly like DES — miss it and every 16-byte block comes out with its halves transposed. That is what happened on the first attempt here, and it was only caught by encrypting a known input with the hand-written model and diffing it against the emulator:

```
emulator : 6c46d06221b913211638ee227f2c343c a367909147822691c6bc58d864b150c2
model    : 1638ee227f2c343c6c46d06221b91321 c6bc58d864b150c2a367909147822691
```

With the trailing swap added the model matches the emulator exactly, the inverse round-trips on random input, and decrypting the target constants gives the phrase directly ([solve.py](solve.py)):

```
$ python3 solve.py WeeperVM--Level_1
round key K0 : 46fc63eda6418771dc8d409cda61da1a
target       : dc6f56c2d34e507769b24de98ff52d122a9581e535db8a1014ffa704d0c1e574
sacred phrase: ()v3Ng34nce_I5_4n_1D10T5_g4m3_()
```

##### 10. Verify on the untouched binary

No patching was needed at any point, so the check is just a plain run:

```bash
$ md5sum WeeperVM--Level_1
ce87814e8fb15c83fd646c6cac968891  WeeperVM--Level_1

$ printf '()v3Ng34nce_I5_4n_1D10T5_g4m3_()\n' | ./WeeperVM--Level_1
...
Let us speak the sacred phrase:
Welcome home :)
```

##### 11. The protections, for the record

All four were mapped during analysis and none had to be defeated, because a static solve never triggers them:

- **Encrypted strings** — `sub_10e27(ciphertext, len, key, keylen)` is a repeating-XOR: `out[i] = ct[i] ^ key[i % keylen]`. The keys sit in `.rodata` next to the ciphertext. Decrypting all six call sites yields `Sumin' ain't right...`, `How 'bout no???`, `Were my bytes not good enough for you >:(`, `How dare you... I worked hard on those threads >:(`, plus `rb` and `/proc/self/exe`.
- **Anti-patch** — `sub_10fe7` opens `/proc/self/exe`, hashes bytes `[0 : size-8]` with `h = h * 0x11 + b` seeded at `0x102a`, and compares against the trailing 8 bytes of the file stored little-endian. Any patch to the binary has to be followed by fixing that trailer.
- **Anti-debug / anti-thread-suspension** — `sub_11266` and `sub_10d2e` each spawn a thread that keeps a `time(0)` heartbeat; `sub_110ff` checks both are still ticking and is called at the top of *every* VM instruction, so stopping the process anywhere for long enough is fatal.

**Flag:** `()v3Ng34nce_I5_4n_1D10T5_g4m3_()`

### Takeaways

When a binary ships its own bytecode, writing the emulator early pays for itself. It is maybe an hour of work for an ISA this size, and it converts every later question from "did I read this disassembly correctly?" into an experiment. Reproducing the program's banner byte-for-byte validated the entire instruction decoder before any of the cipher analysis started, and the same emulator later caught a real bug in the hand-written cipher model.

A stripped, non-PIE binary whose function list looks implausibly short is worth one look at `_start` before reaching for heavier discovery options. Here `main` was reachable only through the GOT-indirect `__libc_start_main` call, and no amount of prologue scanning or address-taken analysis would have found it — but the first argument of that one call names it outright.

Recognising the *shape* of a cipher matters more than recovering every constant. The S-box, the bit permutation and the round key schedule all had to be read correctly, but the moment the structure was identifiable as a Feistel network the problem stopped being a search and became a decryption — no z3, no brute force, no dynamic instrumentation. Feistel networks invert with the same round function, which is exactly why they are attractive to implement in a toy VM.

Validate a reimplementation against ground truth *in the forward direction* before trusting its inverse. The missing final swap produced output that was the right length, the right byte distribution, and entirely wrong — the class of bug that yields a plausible-looking answer with no other symptom. Encrypting a known plaintext and diffing against the emulator caught it in one step; going straight to the inverse would have quietly produced garbage.
