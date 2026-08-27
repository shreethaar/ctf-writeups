---
title: "Obfuscation1"
layout: default
---

# Obfuscation1

A crackme written in C, which have been obfuscated with llvm-ir passes. Obfuscation and anti-debugging. Have fun!

- Category: rev
- Difficulty: 4.0
- Challenge author: s4r
- Challenge link: [crackmes.one](https://crackmes.one/crackme/5bd1d1bb33c5d4110a29b31e)

There is no flag format here — the description only promises that the accepted `argv[1]` is printable ASCII. The obfuscation is LLVM's Mixed Boolean Arithmetic (MBA) substitution pass, which blows a single byte-to-byte transform up into ~175 KB of straight-line arithmetic. The actual puzzle is realising that none of that bulk ever needs to be read.

### Solution:

##### 1. Survey the binary

```bash
$ file Obfuscation1
Obfuscation1: ELF 32-bit LSB executable, Intel i386, version 1 (SYSV), dynamically linked,
interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, stripped
```

The section sizes are the first real clue:

```bash
$ readelf -SW Obfuscation1 | grep -E '\.text|\.rodata'
  [13] .text    PROGBITS  08048320 000320 072082 00  AX  0   0 16
  [15] .rodata  PROGBITS  080ba3b8 0723b8 00003a 00   A  0   0  4
```

466 KB of `.text` against 58 bytes of `.rodata`. That ratio is the OLLVM signature — code inflated by instruction substitution, with almost no data to show for it. It is *not* packed: the program headers show a normal `R E` / `RW` `PT_LOAD` pair with `p_memsz == p_filesz` and the section table fully intact.

The whole of `.rodata` fits in one dump, and it hands over the comparison target:

```
$ readelf -x .rodata Obfuscation1
  0x080ba3b8 03000000 01000200 dff0f3ff dfd3c1b6 ................
  0x080ba3c8 c7c06e6f 70002573 0a007765 6c6c2064 ..nop.%s..well d
  0x080ba3d8 6f6e650a 00706173 73776f72 6420696e one..password in
  0x080ba3e8 20617267 765b315d 0a00               argv[1]..
```

A 10-byte blob at `0x080ba3c0` — `df f0 f3 ff df d3 c1 b6 c7 c0` — sitting right before the strings `nop`, `well done` and `password in argv[1]`. So `well done` is the success path and that blob is what the input has to become.

##### 2. main is eleven lines

`main` is not at the start of `.text`; the entry stub pushes `0x80ba2b0` into `__libc_start_main`. Decompiling that address:

```c
unsigned int sub_80ba2b0(int a0, int a1)
{
  if (0x1000 <= (unsigned int)((int)rdtsc() - (int)rdtsc()))
    return (*NULL)();                       // anti-debug
  if (a0 != 2) {
    printf("password in argv[1]\n");
    return 0;
  }
  sub_8048440(*(unsigned int *)(a1 + 4));   // argv[1]
  return 0;
}
```

The anti-debugging is a `rdtsc` delta check: if two back-to-back reads differ by more than `0xfff`, control jumps through a zeroed register and the process dies. There are 44 of these traps scattered through the binary, so single-stepping is off the table — but a plain breakpoint-and-continue never sits *between* a paired `rdtsc`, so ordinary gdb use is fine.

Everything else lives in `sub_8048440`, which runs from `0x8048440` all the way to `0x80ba2b0`.

##### 3. Find where the input is actually touched

The checker opens by copying the blob onto the stack and taking the length:

```asm
8048471:  mov    ecx,DWORD PTR ds:0x80ba3c0   ; blob -> [ebp-0x16]
804847a:  mov    ecx,DWORD PTR ds:0x80ba3c4
8048483:  mov    dx,WORD PTR ds:0x80ba3c8
804848e:  mov    ecx,DWORD PTR ds:0x80ba3ca   ; "nop"
80484a1:  call   80482f0 <strlen@plt>
80484b0:  imul   eax,eax,0x7
```

and then dissolves into endless ladders of the form

```asm
mov    ecx,0xffffffff
xor    edx,0xffffffff
and    edx,0xffffffff
sub    edx,esi
add    edx,0xffffffff
...
```

which is MBA busywork computing constants the long way round. Reading it linearly is hopeless. Instead, ask where the input bytes are *physically* read. The entire binary contains only seven `BYTE PTR` references, and just two of them matter:

```bash
$ objdump -d -M intel Obfuscation1 | grep -n 'movzx\|movsx'
 806d545:  0f be 04 08    movsx  eax,BYTE PTR [eax+ecx*1]      ; input[i]
 809828d:  0f b6 54 15 ea movzx  edx,BYTE PTR [ebp+edx*1-0x16] ; blob[i]
```

One load site each means this is a genuine loop, not 466 KB of unrolled code. The compare sits right after the second load:

```asm
8098277:  mov    BYTE PTR [ebp-0x29],al     ; transform(input[i]) truncated to a byte
8098287:  movzx  ecx,al
809828a:  mov    edx,DWORD PTR [ebp-0x28]   ; loop index i
809828d:  movzx  edx,BYTE PTR [ebp+edx*1-0x16]
8098292:  cmp    ecx,edx
8098294:  jne    80a31c8                    ; mismatch -> bail out
```

That is the whole check: `transform(input[i]) == blob[i]`, one character at a time, aborting on the first mismatch. The final verdict at the end of the function is just `cmp eax,0x0` guarding the `well done` print.

##### 4. Neutralise the early exit and read the transform

The per-character structure means each position is an independent constraint — but the `jne` bails out before later characters are ever processed, so a single run only reveals one position. Patching that one instruction to `nop` (**in a scratch copy**, never the original) lets the loop run all ten iterations regardless of correctness:

```python
off = 0x8098294 - 0x8048000       # LOAD maps vaddr 0x8048000 at file offset 0
d = bytearray(open('patched','rb').read())
assert d[off:off+6] == bytes.fromhex('0f852eaf0000')   # jne 0x80a31c8
d[off:off+6] = b'\x90' * 6
```

Then break on the compare and read both operands each iteration:

```
break *0x8098292
commands
silent
printf "IDX %d ECX %d EDX %d\n", *(int*)($ebp-0x28), $ecx, $edx
continue
end
run ABCDEFGHIJ
```

```
IDX 0 ECX 243 EDX 223
IDX 1 ECX 240 EDX 240
IDX 2 ECX 241 EDX 243
...
IDX 9 ECX 232 EDX 192
```

The `EDX` column reads back as exactly `df f0 f3 ff df d3 c1 b6 c7 c0`, confirming the blob. Two more runs pin down the shape of the problem:

- `AAAAAAAAAA` yields `ECX 243` at *every* index — the transform does not depend on position, so it is a plain byte-to-byte function `f(c)`.
- 4-character and 14-character inputs never reach the loop body at all, so the length is checked first and must be exactly 10 (that is what the earlier `imul eax,eax,0x7` feeds).

If gdb is running under pwndbg, `commands` + `continue` deadlocks and it says so; `gdb -nx` skips the init file and behaves.

##### 5. Build the table and invert it

Because `f` is position-independent and the loop always runs ten times, each run yields ten table entries. Ten runs over batches of the 95 printable characters recover `f` completely, and inverting it gives the answer directly ([solve.py](solve.py)):

```
$ python3 solve.py
table size: 95
collisions: {}
pos 0: blob=0xdf -> ['M']
pos 1: blob=0xf0 -> ['B']
pos 2: blob=0xf3 -> ['A']
pos 3: blob=0xff -> ['-']
pos 4: blob=0xdf -> ['M']
pos 5: blob=0xd3 -> ['a']
pos 6: blob=0xc1 -> ['s']
pos 7: blob=0xb6 -> ['t']
pos 8: blob=0xc7 -> ['e']
pos 9: blob=0xc0 -> ['r']

FLAG: MBA-Master
```

`f` turns out to be injective over printable ASCII — zero collisions — so `MBA-Master` is the *unique* printable solution rather than merely one that happens to work. The name is also a fair hint at what the 466 KB was hiding: Mixed Boolean Arithmetic.

##### 6. Verify against the untouched binary

The patched copy was only ever an instrument. The answer has to hold on the original, with no debugger attached:

```bash
$ md5sum Obfuscation1
860b2bc131c2c533994d6ccbc13026c1  Obfuscation1

$ ./Obfuscation1 'MBA-Master'
well done

$ ./Obfuscation1 'MBA-Mastes'; ./Obfuscation1 'mBA-Master'; ./Obfuscation1 'MBA-Master1'
nop
nop
nop
```

**Flag:** `MBA-Master`

### Takeaways

MBA obfuscation inflates the *implementation* of a function but not its *interface*. This one expands a byte-to-byte mapping into 175 KB of arithmetic, yet the thing still only consumes one byte and produces one byte — so it is far cheaper to treat it as a black-box oracle and tabulate it than to simplify the algebra. Whenever the input domain is small (95 printable characters here), tabulating wins outright.

Grepping for the instructions that actually dereference the input — `BYTE PTR` / `movzx` / `movsx` — is a fast way into a huge obfuscated function. Seven hits across the entire binary went straight to the comparison; the loop structure and the per-character independence both fell out of the fact that there was only *one* load site for each operand.

An early-exit `jne` in a per-character check is worth a patch even when you are not trying to bypass anything. Removing it converted a serial one-position-per-run oracle into a ten-entries-per-run table dump. Patch a scratch copy, and always close the loop by re-verifying on the pristine original — the patched binary proves nothing on its own.
