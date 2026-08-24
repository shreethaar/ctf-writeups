# Guessing Game

- Category: pwn
- Difficulty: Hard
- Author: Vincent
- Status: Not solved live — analysis pushed independently, then reconciled against the confirmed solution path shared in post-CTF Discord discussion

"My company is hosting a contest to win a new laptop. I just beat the game but they won't pay out... I'm pretty sure their program is vulnerable." `guessing_game` is a non-stripped, PIE, no-canary x86-64 binary served one-shot per connection via `socat`, glibc 2.41-12+deb13u3.

### Solution:

##### 1. Bug A — unbounded index becomes a popcount oracle

The game holds ten `rand()` values in `var_98[0..9]` and lets you guess one at a time. The index is read straight off the wire and used unmasked:

```asm
1458: mov rax,[rbp-0x20]        ; rax = Index, full 64-bit, no bound
145c: mov rdx,[rbp+rax*8-0x90]  ; rdx = MEM[rbp + Index*8 - 0x90]
1464: cmp rdx, Value
14a6: call __popcountdi2(Value ^ rdx)   ; on mismatch, prints the Hamming distance
```

`Index` is a raw `strtoull` result, so `Index*8 - 0x90` reaches any 8-byte-aligned offset from `rbp`, positive or negative, mod 2⁶⁴. The popcount reply turns this into a bit oracle: guess `0` for a baseline, then flip one bit of `Value` at a time — a rising or falling Hamming distance reveals that bit of the target qword. 64 queries recover any qword exactly, anywhere reachable as `rbp + k·8` — effectively the whole stack.

##### 2. Bug B — an 8-byte write into the frame pointer

Choosing "0: Submit" calls `submit()`, which has no local buffer of its own:

```asm
1253: push rbp          ; pushes challenge()'s saved rbp
1254: mov  rbp, rsp
126d: fgets(rbp, 8, stdin)   ; writes straight over that saved-rbp slot
1281: pop  rbp           ; rbp = attacker's 8 bytes
1282: ret                ; back into challenge(), rbp now forged
```

`fgets` with size 8 always NUL-terminates by byte 7, forcing the top byte of the forged `rbp` to `0x00` — harmless, since real user-space addresses already have a zero top byte. `challenge()`'s epilogue then runs `leave; ret` on the forged frame pointer: `rsp` becomes the attacker's value, `pop rbp` reads whatever sits there, and the final `ret` jumps to whatever sits one slot above it. Net primitive: a single indirect jump to the contents of an address of your choosing.

##### 3. Map the frame and the leaks

Static analysis plus GDB (breaking right before the call into `submit()`) pinned the frame down precisely:

| oracle index | address | holds |
|---|---|---|
| 18 | `rbp+0x00` | saved rbp → `main()`'s frame |
| 19 | `rbp+0x08` | return address into `main` (PIE leak) |
| 21 | `rbp+0x18` | return address inside libc (libc leak) |

idx19's low 12 bits matched the known file offset of the instruction after `call challenge`, giving `PIE_base = leak − 0x153c`. idx18 gives `main`'s saved rbp directly, and since `challenge()`'s own prologue is just `push rbp; mov rbp,rsp` one frame deeper, `challenge_rbp = main_rbp − 0x10` always — a fixed, ASLR-invariant delta. Single-stepping past `submit()`'s return also showed `rdi == 0` at the pivot point (the last real call was `fgets()`, which clobbers it) — relevant for gadget selection next.

`one_gadget` against the bundled libc surfaced `0xddf83 execve("/bin/sh", rbp-0x40, r13)`, constraints `rbp-0x38` writable and `rdi == NULL || valid argv` — the second is free since `rdi` is already 0.

##### 4. Where independent analysis stopped

The remaining problem: only two genuinely free 8-byte slots exist on the stack (the attempted/correct-answer bitmasks), and the two mandatory leak queries (indices 18, 21) unavoidably force bits 18 and 21 of any address built from them — so a one-gadget landing built this way only works if the real ASLR-picked `libc_base` happens to already have those two bits set (~25% of runs). Verification was still in progress when the competitors' own solutions surfaced in Discord.

One pitfall worth flagging regardless: `ldd guessing_game` resolves `libc.so.6` from the system path unless forced otherwise. On a non-Debian host, debugging without explicitly loading the bundled loader (`./ld-linux-x86-64.so.2 --library-path . ./guessing_game`) silently runs against the *host's* libc — a completely different version with different offsets, invisibly poisoning every derived constant.

##### 5. The confirmed solution

Both community solves exploit that choosing "0" doesn't have to end the game — the first pivot can jump back into `main`'s own return-into-`main` value, restarting `challenge()` on a shifted stack for another shot at the same primitives.

**Path A — one_gadget (Wardor).** Pack a ROP-free chain into the two free qwords (`correct_mask` as the forged `rbp`, crafted to land in libc's writable segment; `attempted_mask` as the jump target) landing directly on the `0xddf83` one_gadget. Because bits 18 and 21 of `libc_base` get forced on, this lands roughly 1 in 4 connections — the fix is a reconnect-and-retry loop, reported at ~50 attempts / 2–3 minutes end to end.

**Path B — ret2libc via a `gets()` trampoline (Vincent).** Use the first pivot to land on a gadget that sets `rdi` to a known-writable stack address and falls into libc's `gets()`, which, being unbounded, writes a full ROP chain (`pop rdi; ret` → `"/bin/sh"` → `system`) into memory in one shot. This sidesteps the two-free-qword ceiling entirely and needs no ASLR-bit luck, at the cost of one extra careful pivot.

Constants re-derived independently against the provided `libc.so.6` (not copied from the shared writeups) matched exactly: libc leak → `libc_base = leak − 0x29ca8` (return site in `__libc_start_call_main`), one_gadget at `base + 0xddf83`, `pop rdi; ret` at `base + 0x2a145`, `system()` at `base + 0x53110`, `"/bin/sh"` at `base + 0x1a5ea4`, PIE leak → `PIE_base = leak − 0x153c`.

### Takeaways

- A raw, unmasked attacker index used as `rbp + Index*8` is a full-stack read oracle the moment any comparison result (even just a popcount) is echoed back — the leak doesn't need to be the compared value itself.
- Two genuinely free attacker-controlled qwords plus a single indirect-jump primitive is enough for ret2libc *if* the exploit can afford non-determinism (ASLR-bit-dependent one-gadget landings) or can spend one pivot buying an unbounded write (`gets()` trampoline) to remove that dependency entirely.
- Always force the bundled loader/libc explicitly when debugging on a host whose system libc differs from the target's (`./ld-linux... --library-path . ./binary`) — a silent version mismatch produces confidently wrong offsets, not an obvious crash.
