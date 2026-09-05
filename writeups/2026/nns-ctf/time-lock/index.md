# Time Lock

- Category: rev
- Difficulty: Beginner
- Author: hoover

"The provided x86-64 ELF is a sealed archive. It asks the C standard library what day it is, refuses to open unless the answer is 1 January 9999, and prints sealed every other day of the year."

The brief warns that patching the date check won't be enough — "the key is derived from the answer the program gets back, not merely compared against it." In the shipped binary that turns out not to hold, because the compiler folded the derivation into a constant. The intended `LD_PRELOAD` solution is still the more interesting one, so both are below.

### Solution:

##### 1. The check

There is no `main`; everything lives in `_start`:

```asm
40104e:  call   401030 <time@plt>
401053:  movabs rdx,0x1845c8a0ce512957
40105d:  mov    rcx,rax
401060:  imul   rdx
401063:  sar    rcx,0x3f
401067:  sar    rdx,0xd
40106b:  sub    rdx,rcx
40106e:  cmp    edx,0x2cbf34
401074:  jne    4010f7                  ; -> "sealed"
```

The `movabs` / `imul` / `sar` sequence is the standard compiler idiom for signed division by a constant, recoverable as `2**(64 + shift) / magic`. With `shift = 13` that comes out to `86400` — so the program is computing `time(NULL) / 86400`, the day index since the epoch, and requires `0x2cbf34` = `2932532`:

```
2932532 * 86400 = 253370764800   ->   9999-01-01 00:00:00 UTC
```

##### 2. Preload a fake clock

`time` is an ordinary PLT import, so the loader will resolve it out of a preloaded object before it reaches libc:

```c
#include <time.h>
time_t time(time_t *t) {
    time_t v = 253370764800LL;   /* 9999-01-01 00:00:00 UTC */
    if (t) *t = v;
    return v;
}
```

```
$ gcc -shared -fPIC -o faketime.so faketime.c
$ LD_PRELOAD=./faketime.so ./time-lock
NNS{y0u_c4n_l13_70_4_pr0gr4m_w17h_ld_pr3l04d}
```

Shim: [faketime.c](faketime.c)

##### 3. The key isn't actually derived from the clock

The decryption seed is loaded immediately after the branch, and it is a literal:

```asm
40107a:  mov    DWORD PTR [rsp+0xc],0x4db55fbe    ; seed -- a constant
4010c0:  imul   edx,DWORD PTR [rsp+0xc],0x15a4e35
4010c8:  add    edx,0x1
4010d3:  shr    edx,0x10
4010d6:  xor    BYTE PTR [rax],dl
4010dc:  cmp    rcx,rax                           ; 0x2e bytes at <flag>
```

Nothing in that loop reads `rax` from the `time` call. The source presumably did seed the LCG from the day number, but because the guarding branch pins the day to `2932532`, constant propagation evaluated the whole expression at compile time and left `0x4db55fbe` behind.

Two consequences. First, NOP-ing the six-byte `jne` at `0x401074` (file offset `0x1074`) is sufficient on its own — no preload, no clock games, on any date:

```
$ ./time-lock-jnepatch          # 0f 85 7d 00 00 00  ->  90 90 90 90 90 90
NNS{y0u_c4n_l13_70_4_pr0gr4m_w17h_ld_pr3l04d}
```

Second, the flag falls out without executing anything, by replaying the LCG over the 46-byte blob at `0x404020`:

```python
s = 0x4db55fbe
out = bytearray()
for b in blob:
    s = (s * 0x15a4e35 + 1) & 0xffffffff
    out.append(b ^ ((s >> 16) & 0xff))
```

All three routes produce the same string.

**Flag:** `NNS{y0u_c4n_l13_70_4_pr0gr4m_w17h_ld_pr3l04d}`

### Takeaways

- `movabs` + `imul` + `sar N` is signed division by a constant. Recovering the divisor as `2**(64+N) / magic` turns an opaque magic number into something readable — here, "the day index of 1 Jan 9999".
- A "derived, not compared" anti-patch defence only holds if the compiler cannot see the value. Pinning the input inside the guarding branch is precisely the condition that lets constant propagation fold the derivation into a literal, which hands the key to the patcher instead of protecting it. To make this defence real, the key has to depend on a value the compiler cannot prove — the raw `time()` return, not the already-compared quotient.
