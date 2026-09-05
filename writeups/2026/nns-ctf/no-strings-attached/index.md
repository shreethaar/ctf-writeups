# No Strings Attached

- Category: rev
- Difficulty: Beginner
- Author: hoover

"The passphrase is the flag, but it is not written down anywhere in the file."

`strings` yields `guess:`, `correct` and `rejected` and nothing else. The passphrase is assembled in `.data` at runtime and handed straight to `strcmp`, so the whole challenge is about watching the arguments to a single libc call.

### Solution:

##### 1. Confirm the flag is never on disk

Three imports, one of which is the entire attack surface:

```
$ readelf -sW no-strings-attached | grep UND | awk '{print $8}'
write@GLIBC_2.2.5
read@GLIBC_2.2.5
strcmp@GLIBC_2.2.5
```

`main` reads 127 bytes into `input`, strips a trailing newline, then runs a decode loop over a 56-byte blob at `secret` (`0x404040`) before comparing:

```asm
40115e:  mov    DWORD PTR [rbp-0x10],0x6      ; LCG seed
4011e2:  imul   eax,eax,0x41c64e6d            ; state = state*1103515245 + 12345
4011eb:  add    eax,0x3039
4011f6:  shr    eax,0x10                      ; keystream byte = state >> 16
4011fe:  lea    rdx,[rip+0x2e3b]              ; <secret>
40120b:  xor    eax,edx
401220:  cmp    DWORD PTR [rbp-0xc],0x37      ; 56 bytes
40123a:  call   401050 <strcmp@plt>
```

The multiplier/addend pair `0x41c64e6d`/`0x3039` is glibc's `rand()` LCG. The plaintext exists only in the window between that loop finishing and `strcmp` returning.

##### 2. Read it out of `strcmp`

That window is exactly what a library-call tracer prints, and the decoded passphrase is `strcmp`'s second argument:

```
$ echo AAAA | ltrace -s 200 ./no-strings-attached
write(1, "guess: ", 7)                        = 7
read(0, "AAAA\n", 127)                        = 5
strcmp("AAAA", "NNS{n0_str1ngs_1n_7h3_b1n4ry_bu7_ltr4c3_s4w_7h3_c0mp4r3}") = -13
write(1, "rejected\n", 9)                     = 9
```

`-s 200` is load-bearing — `ltrace` truncates strings at 32 characters by default, which would cut a 56-byte flag off at `NNS{n0_str1ngs_1n_7h3_b1n4ry_bu`.

##### 3. Static cross-check

Replaying the same LCG over the blob offline gives an identical string, confirming nothing in the runtime environment fed into it:

```python
s = 6
out = bytearray()
for b in blob:                     # 56 bytes at vaddr 0x404040
    s = (s * 0x41c64e6d + 0x3039) & 0xffffffff
    out.append(b ^ ((s >> 16) & 0xff))
```

**Flag:** `NNS{n0_str1ngs_1n_7h3_b1n4ry_bu7_ltr4c3_s4w_7h3_c0mp4r3}`

### Takeaways

- Decode-then-`strcmp` is the weakest way to hide a secret: the PLT boundary is a free breakpoint that no amount of encoding gets past.
- Always raise `ltrace -s` when the expected secret is longer than 32 bytes, otherwise the flag arrives silently truncated and looks like a dead end.
