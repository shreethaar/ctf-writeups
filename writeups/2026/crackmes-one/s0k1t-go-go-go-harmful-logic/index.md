---
title: "GO GO GO - Harmful Logic"
layout: default
---

# GO GO GO - Harmful Logic

My first crackme. Author's note: "I don't really know what I'm doing."

- Category: rev
- Difficulty: 2.0
- Challenge author: s0k1t
- Challenge link: [crackmes.one](https://crackmes.one/crackme/6044083333c5d42c3d016d3d)
- Platform: Linux x86-64 (ELF, statically linked, stripped), Go 1.16

There's no flag format — the goal is just the password the binary accepts. The interesting part isn't an algorithm to invert: the binary reads a guess and appears to hex-decode and compare it, but the actual comparison target is never derived from the input at all — it's a fixed hex-encoded string sitting in `.rodata`. The whole "crackme" reduces to reading a constant back out of the file.

### Solution:

##### 1. Confirm it's Go, and check whether the symbol table survived

```
$ file main
main: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked,
BuildID[unknown]=3768317334696e377433485034353577337244, stripped
```

Statically linked and stripped, 1.4 MB — the profile of a Go binary rather than a genuinely stripped C one. `strings` confirms it: `go1.16` shows up directly, and Go 1.16 predates the 1.17 register-based calling convention, so this binary passes function arguments and returns entirely on the stack. That matters later — it's why the decompiled C reads as stack-slot writes instead of clean parameter lists.

`kuna functions ./main --json` returns 1,554 functions, and every one of them is named (no `sub_<addr>` entries). The `pclntab` — Go's own function-name table — is intact, so there's no garble-style obfuscation to work around here; `gopclntab` recovery just worked.

##### 2. Filtering runtime noise leaves exactly one function

1,554 named functions is still almost entirely `runtime.*`, `reflect.*`, `fmt.*`, and compiler-generated `type..eq.*` equality thunks — none of that is code the author wrote. Filtering to names outside the standard library/runtime package set:

```python
STD = {"internal","runtime","reflect","syscall","type:","sync","os","errors",
       "strconv","sort","time","unicode","math","io","fmt","bufio","strings",
       "bytes","encoding","crypto","hash","context","path","go:", ...}
user = [f for f in funcs if f["name"].split(".")[0].split("/")[0] not in STD]
```

leaves a single hit: `main.main` at `0x4a5800`. There is no separate "check" function to hunt for — the entire crackme is inlined into `main`.

##### 3. Decompile `main.main`

```bash
kuna decompile ./main main.main
```

```c
void main.main(void)
{
  int8 v1;
  uint8 v2; // rax
  char *v3;
  char *v4;
  char *v5;
  int8 v6; // fs_offset

  v3 = &Stack0000000000000000;
  do {
    v4 = v3;
    if (*(char **)(*(int8 *)(v6 + -8) + 0x10) < &v3[-0x58]) {
      v4 = &v3[-0xd8];
      *(char **)&v3[-8] = v5;
      v5 = &v3[-8];
      *(unsigned long *)&v3[-0xd8] = 0x4b0da0;
      *(unsigned long *)&v3[-0xe0] = 0x4a583f;
      runtime.newobject();
      *(unsigned long *)&v3[-0x20] = *(unsigned long *)&v3[-0xd0];
      *(unsigned long *)&v3[-0xd8] = 0x4eae98;
      *(unsigned long *)&v3[-0xd0] = dat_564970;
      *(unsigned long *)&v3[-200] = 0x4cb7e3;
      *(unsigned long *)&v3[-0xc0] = 0x10;
      *(unsigned long *)&v3[-0xb8] = 0;
      *(unsigned long *)&v3[-0xb0] = 0;
      *(unsigned long *)&v3[-0xa8] = 0;
      *(unsigned long *)&v3[-0xe0] = 0x4a588f;
      fmt.Fprintf();
      *(unsigned long *)&v3[-0x18] = 0;
      *(unsigned long *)&v3[-0x10] = 0;
      *(unsigned long *)&v3[-0x18] = 0x4ae9c0;
      *(unsigned long *)&v3[-0x10] = *(unsigned long *)&v3[-0x20];
      *(unsigned long *)&v3[-0xd8] = 0x4eae78;
      *(unsigned long *)&v3[-0xd0] = dat_564968;
      *(char **)&v3[-200] = &v3[-0x18];
      *(unsigned long *)&v3[-0xc0] = 1;
      *(unsigned long *)&v3[-0xb8] = 1;
      *(unsigned long *)&v3[-0xe0] = 0x4a58f4;
      fmt.Fscan();
      *(char **)&v3[-0xd8] = &v3[-0x50];
      *(unsigned long *)&v3[-0xd0] = 0x4cd928;
      *(unsigned long *)&v3[-200] = 0x1a;
      *(unsigned long *)&v3[-0xe0] = 0x4a591a;
      runtime.stringtoslicebyte();
      *(uint8 *)&v3[-0x88] = *(uint8 *)&v3[-0xb8];
      *(unsigned long *)&v3[-0x30] = *(unsigned long *)&v3[-0xc0];
      *(unsigned long *)&v3[-0x80] = *(unsigned long *)&v3[-0xb0];
      *(unsigned long *)&v3[-0xd8] = 0x4b0ee0;
      v2 = *(uint8 *)&v3[-0xb8] >> 1;
      *(uint8 *)&v3[-0x78] = v2;
      *(uint8 *)&v3[-0xd0] = v2;
      *(uint8 *)&v3[-200] = v2;
      *(unsigned long *)&v3[-0xe0] = 0x4a595d;
      runtime.makeslice();
      *(unsigned long *)&v3[-0x28] = *(unsigned long *)&v3[-0xc0];
      *(unsigned long *)&v3[-0xd8] = *(unsigned long *)&v3[-0xc0];
      *(unsigned long *)&v3[-0xd0] = *(unsigned long *)&v3[-0x78];
      *(unsigned long *)&v3[-200] = *(unsigned long *)&v3[-0x78];
      *(unsigned long *)&v3[-0xc0] = *(unsigned long *)&v3[-0x30];
      *(unsigned long *)&v3[-0xb8] = *(unsigned long *)&v3[-0x88];
      *(unsigned long *)&v3[-0xb0] = *(unsigned long *)&v3[-0x80];
      *(unsigned long *)&v3[-0xe0] = 0x4a59a5;
      encoding/hex.Decode();
      if (*(int8 *)&v3[-0xa0])
        return;
      if (*(uint8 *)&v3[-0xa8] <= *(uint8 *)&v3[-0x78]) {
        *(char **)&v3[-0xd8] = &v3[-0x70];
        *(unsigned long *)&v3[-0xd0] = *(unsigned long *)&v3[-0x28];
        *(uint8 *)&v3[-200] = *(uint8 *)&v3[-0xa8];
        *(unsigned long *)&v3[-0xe0] = 0x4a59e9;
        runtime.slicebytetostring();
        v1 = (*(unsigned long **)&v3[-0x20])[1];
        if (*(int8 *)&v3[-0xb8] == v1) {
          *(unsigned long *)&v3[-0xd8] = **(unsigned long **)&v3[-0x20];
          *(unsigned long *)&v3[-0xd0] = *(unsigned long *)&v3[-0xc0];
          *(int8 *)&v3[-200] = v1;
          *(unsigned long *)&v3[-0xe0] = 0x4a5a6d;
          runtime.memequal();
          if (v3[-0xc0]) {
            *(unsigned long *)&v3[-0xd8] = 0x4eae98;
            *(unsigned long *)&v3[-0xd0] = dat_564970;
            *(unsigned long *)&v3[-200] = 0x4ca452;
            *(unsigned long *)&v3[-0xc0] = 8;
            *(unsigned long *)&v3[-0xb8] = 0;
            *(unsigned long *)&v3[-0xb0] = 0;
            *(unsigned long *)&v3[-0xa8] = 0;
            *(unsigned long *)&v3[-0xe0] = 0x4a5ab6;
            fmt.Fprintf();
            return;
          }
        }
        *(unsigned long *)&v3[-0xd8] = 0x4eae98;
        *(unsigned long *)&v3[-0xd0] = dat_564970;
        *(unsigned long *)&v3[-200] = 0x4cba43;
        *(unsigned long *)&v3[-0xc0] = 0x10;
        *(unsigned long *)&v3[-0xb8] = 0;
        *(unsigned long *)&v3[-0xb0] = 0;
        *(unsigned long *)&v3[-0xa8] = 0;
        *(unsigned long *)&v3[-0xe0] = 0x4a5a4a;
        fmt.Fprintf();
        return;
      }
      *(unsigned long *)&v3[-0xe0] = 0x4a5acd;
      runtime.panicSliceAcap();
    }
    *(unsigned long *)&v4[-8] = 0x4a5ad3;
    runtime.morestack_noctxt();
    v3 = v4;
  } while( true );
}
```

The stack-slot writes right before each call (`v3[-0xe0] = 0x4a583f`, etc.) are Go's stack-based argument setup — each block stages a call's arguments (and the return PC) into the caller's frame, then the runtime helper reads them back off the stack rather than out of registers. Read past that boilerplate and the sequence of calls tells the whole story: `newobject` → `Fprintf` (prompt) → `Fscan` (read guess) → `stringtoslicebyte` → `makeslice` → `hex.Decode` → `slicebytetostring` → `memequal` → `Fprintf` (verdict).

##### 4. The hex string being decoded isn't the user's input

The one line worth stopping on is the `stringtoslicebyte` setup:

```c
*(char **)&v3[-0xd8] = &v3[-0x50];
*(unsigned long *)&v3[-0xd0] = 0x4cd928;
*(unsigned long *)&v3[-200] = 0x1a;
runtime.stringtoslicebyte();
```

`runtime.stringtoslicebyte(buf, s.ptr, s.len)` is being called with `s.ptr = 0x4cd928` and `s.len = 0x1a` (26) as **immediate constants**, not with the pointer that `fmt.Fscan` had just written the guess into (that pointer is still sitting in the `v3[-0x20]` slot from `newobject`, untouched here). Cross-checking against the disassembly confirms it's a fixed address, not a runtime value:

```asm
4a58f4: lea rax,[rsp+0x88]
4a58fc: mov [rsp], rax
4a5900: lea rax,[rip+0x28021]      # 0x4cd928
4a5907: mov [rsp+8], rax
4a590c: mov qword [rsp+0x10], 0x1a
4a5915: call 0x44c740              ; runtime.stringtoslicebyte
```

So the program hex-decodes a **26-character string baked into the binary**, not anything the player typed. That decoded value — 13 raw bytes, since `hex.Decode`'s destination is always half the source length (`v2 = len >> 1` right after) — becomes the left-hand side of the later `memequal` against the actual user input. In other words: the "obfuscation" here is that the real password sits in `.rodata` as hex text instead of plain ASCII, and the input read via `Fscan` is just what gets compared against it.

##### 5. Pull the constant strings straight from `.rodata`

`readelf -SW main` gives `.rodata` mapped at VA `0x4a6000`, file offset `0xa6000` — a flat `-0x400000` delta, so any `.rodata` VA converts to a file offset by subtracting `0x400000`:

```python
data = open("main", "rb").read()
def get(va, ln):
    return data[va - 0x400000 : va - 0x400000 + ln]

get(0x4cb7e3, 16)   # prompt string   -> b'Password Plox: \n'
get(0x4cba43, 16)   # failure string  -> b'try again loser\n'
get(0x4ca452, 8)    # success string  -> b'Welcome\n'
get(0x4cd928, 26)   # the hex blob    -> b'736f6c617277696e6473313233'
```

Hex-decoding that last one:

```python
>>> bytes.fromhex("736f6c617277696e6473313233")
b'solarwinds123'
```

##### 6. Verify

```
$ echo "solarwinds123" | ./main
Password Plox:
Welcome
```

The failure path (`try again loser`) confirms anything else is rejected, and the success path matches the decoded constant exactly — no algorithm, no per-character transform, just a hex-encoded literal compared against the guess.

**Password:** `solarwinds123`

### Takeaways

Hex-encoding a secret in `.rodata` doesn't hide it from a decompiler the way it hides it from `strings` — it just moves the "obvious plaintext" tell from the bytes themselves to a `hex.Decode` call with a suspiciously constant source pointer. When a comparison's operand is being *decoded* rather than *computed*, check whether the decode's input is actually reachable from user input at all before assuming there's an algorithm to reverse; here it wasn't, and the whole "crackme" was reading a literal back out of the binary.

On a Go 1.16 binary (pre-1.17 register ABI), arguments and return values are staged entirely on the stack, so kuna's decompiled C for `runtime.*` calls looks like a wall of `v3[-0xNN] = ...` writes right before each call. That's not decompiler noise to fight through — each block is exactly the argument list for the call that follows it, and reading it that way (plus a quick disassembly cross-check when a value's origin isn't obvious, as with the `0x4cd928` constant here) is enough to trace the whole function by hand even with zero named locals.
