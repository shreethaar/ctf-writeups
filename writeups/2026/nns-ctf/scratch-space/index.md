# Scratch Space

- Category: rev
- Difficulty: Beginner
- Author: hoover

"The program maps a scratch page, builds the real passphrase there, compares it against your guess with a loop of its own, then zeroes the page and unmaps it before printing anything. strings, ltrace and strace all come back empty."

Third in the series, and it closes each of the previous doors on purpose: nothing on disk for `strings`, no libc compare for `ltrace`, no file for `strace`. What it doesn't hide is the generator.

### Solution:

##### 1. Why the tracers come back empty

`main` maps one anonymous RW page and builds the passphrase into it:

```asm
4011f6:  mov    r8d,0xffffffff       ; fd = -1
4011fc:  mov    ecx,0x22             ; MAP_PRIVATE|MAP_ANONYMOUS
401201:  mov    edx,0x3              ; PROT_READ|PROT_WRITE
401206:  mov    esi,0x1000
401210:  call   401040 <mmap@plt>
```

The comparison is a hand-written byte loop rather than `strcmp`, so no library call ever carries the plaintext:

```asm
401290:  movzx  edx,BYTE PTR [rax+rdx*1]     ; input[i]
4012a8:  movzx  eax,BYTE PTR [rax]           ; page[i]
4012ab:  cmp    dl,al
4012af:  mov    DWORD PTR [rbp-0x14],0x0     ; mismatch -> result = 0
```

and the page is wiped, then unmapped, *before* either verdict is printed:

```asm
4012c9:  mov    BYTE PTR [rax],0x0           ; zero 0x2a+1 bytes
4012ec:  call   401060 <munmap@plt>
4012f1:  cmp    DWORD PTR [rbp-0x14],0x0     ; only now decide what to print
```

##### 2. The generator is a static LCG

The page contents are not random. Seed and ciphertext are both fixed, and the blob sits at `0x404040`:

```asm
40116e:  mov    DWORD PTR [rbp-0x1c],0x311023df   ; seed
401225:  imul   eax,eax,0x343fd                   ; state = state*0x343fd + 0x269ec3
40122b:  add    eax,0x269ec3
401244:  shr    eax,0x10                          ; keystream byte = state >> 16
401253:  xor    ecx,esi
40125d:  cmp    DWORD PTR [rbp-0x18],0x29         ; 42 bytes
```

Nothing in that loop depends on the input, the clock or the environment, so the page can be rebuilt offline rather than raced in a debugger:

```
$ ./solve.py ./scratch-space
NNS{s34rch3d_7h3_mm4p_b3f0r3_17_w4s_w1p3d}
```

Full script: [solve.py](solve.py)

##### 3. Confirm against the binary

Worth feeding back, since it proves the reconstruction matches the page the program actually built rather than just decoding to something flag-shaped:

```
$ echo 'NNS{s34rch3d_7h3_mm4p_b3f0r3_17_w4s_w1p3d}' | ./scratch-space
guess: checking...
correct
```

##### 4. The intended dynamic route

Reading it out of memory also works, but the breakpoint has to be chosen with the wipe in mind. The order is build → print `checking...` → compare → **wipe** → `munmap` → verdict, so breaking on `munmap@plt` is already too late: the page is intact but zeroed. The last useful stop is the head of the wipe loop at `0x4012c0`, with the page pointer in `[rbp-0x8]`:

```
$ echo AAAA | gdb -q -batch -ex 'break *0x4012c0' -ex run \
      -ex 'x/s *(char**)($rbp-8)' ./scratch-space
Breakpoint 1, 0x00000000004012c0 in main ()
0x7ffff7f84000:	"NNS{s34rch3d_7h3_mm4p_b3f0r3_17_w4s_w1p3d}"
```

Under pwndbg, `telescope $rbp-8` at the same address shows the pointer and the string behind it in one step.

**Flag:** `NNS{s34rch3d_7h3_mm4p_b3f0r3_17_w4s_w1p3d}`

### Takeaways

- "Wipes the buffer before exiting" only defeats a breakpoint placed *after* the wipe. Locate the wipe loop first and break at its head — that is the latest point where the secret is still fully materialised.
- Anti-tracing that hides the plaintext (private page, no libc compare, scrubbed on exit) does nothing about the *generator*. If the seed and ciphertext are static, the runtime defences are irrelevant and the whole thing reduces to replaying a keystream offline.
