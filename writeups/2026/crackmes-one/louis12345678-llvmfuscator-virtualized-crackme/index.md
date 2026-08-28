---
title: "LLVMfuscator Virtualized CrackMe!"
layout: default
---

# LLVMfuscator Virtualized CrackMe!

The binary is heavily virtualized. Find the correct input values to get the "valid key" message!

- Category: rev
- Difficulty: 5.0
- Challenge author: Louis12345678
- Platform: Windows x86-64 (PE32+ console), solved from Linux

Two things make this one awkward, and neither is the virtualization. The first is host: it is a Windows PE, and on this machine neither `winedbg` nor `gdb` can debug a 64-bit guest, so the usual breakpoint-and-look move is unavailable. The second is that the checker is **completely branch-free** — the native basic-block trace is byte-identical for every input, so instruction counts, path divergence and timing all leak exactly nothing. What defeats it is that the VM still has to *build* its expected key somewhere, and it builds it on the stack right next to the two verdict strings. Once you can watch memory at all, the answer is sitting in plain sight.

### Solution:

##### 1. A PE with nothing to read

```bash
$ file crackme_windows.bin
crackme_windows.bin: PE32+ executable for MS Windows 6.00 (console), x86-64, 7 sections

$ diec crackme_windows.bin
PE64
    Compiler: Microsoft Visual C/C++(16.00)
```

Not packed: normal MSVC section names, sane raw/virtual sizes, entry in `.text`.

```bash
$ objdump -h crackme_windows.bin
  0 .text   00040626  0000000140001000  ...  CONTENTS, ALLOC, LOAD, READONLY, CODE
  1 .rdata  0000a50c  0000000140042000  ...
  2 .data   0000ae00  000000014004d000  ...
```

The import table is 73 functions and all of them are `KERNEL32` — a statically linked CRT, so `printf`/`scanf` are inside the binary rather than imported. `IsDebuggerPresent` and `QueryPerformanceCounter` are both there, which is worth remembering later.

The strings are the real signal, in that there aren't any:

```bash
$ strings -a crackme_windows.bin | grep -iE 'key|valid|correct|flag'
invalid argument
invalid seek
...
```

Every hit is CRT boilerplate. A `strings -el` pass for UTF-16 finds only locale tables. Nothing the program actually prints — no prompt, no "valid key" — exists in the file, so the strings are constructed at runtime.

##### 2. Following the CRT startup chain to main

Names are stripped apart from the imports, so `main` has to be found by walking out of the entry point. `kuna` gives 718 functions, and the entry at `0x140035520` is the usual two-call MSVC stub:

```c
void sub_140035520(void)
{
  sub_140035774();
  sub_1400353a4(); // tail-call
}
```

Inside `sub_1400353a4` — `__scrt_common_main_seh` — the call taking `argc`/`argv`/`envp` shape is `sub_140034440`, and that is `main`:

```c
void sub_140034440(unsigned long long a0, unsigned long long a1)
{
  unsigned long long v1, v2, v3, v4;   // four u64 locals
  v1 = 0; v2 = 0; v3 = 0; v4 = 0;
  sub_140034600(a0, a1, &v1, &v2, &v3, &v4);
}
```

Four `uint64` locals, addresses passed on. Combined with "find the correct input **values**" in the description, this reads like the program wants four numbers. It does not — see step 3. Those 32 contiguous bytes are one MSVC `std::string` (16-byte SSO buffer + size + capacity), handed over as four pointers.

`sub_140034600` builds a context struct, plants a magic constant, and hands off:

```asm
140034718:  movabs rcx,0x4db7852c9709485e
14003472d:  lea    r13,[rsp+0x90]        ; VM context
140034735:  lea    rbp,[rsp+0x70]
14003473a:  mov    r15d,0xa43abc25       ; dispatch key
140034740:  call   0x140033a80
```

`kuna` declines to decompile `0x140033a80` ("no code at this address"), and the raw bytes show why — it is not a function so much as a threaded-code trampoline:

```asm
140033a80:  mov  rax,rsp
140033a83:  mov  rsp,rbp          ; swap the real and VM stacks
140033a86:  mov  rbp,rax
140033a89:  jmp  0x140033940
...
140033ad0:  mov  eax,DWORD PTR [r15]        ; next opcode from the stream
140033ad6:  sub  eax,DWORD PTR [r13+0x348]  ; minus a rolling key
140033add:  add  r15,0x8                    ; advance bytecode pointer
140033ae3:  add  rcx,rax
140033ae9:  jmp  rcx                        ; chain to the next handler
```

Handlers chain through a computed `jmp` with a key-subtracted delta, and the VM swaps `rsp`/`rbp` so its working memory sits inside `main`'s frame. This is where reading decompiled C stops paying for itself.

##### 3. What it actually wants

Before reconstructing an ISA, just run it. `wine` executes the binary fine even though wine's *debuggers* will not:

```bash
$ wine crackme_windows.bin
invalid arg count
$ wine crackme_windows.bin 1
invalid key
$ wine crackme_windows.bin 1 2
invalid arg count
```

So it wants exactly **one** argument, not four values. Every string that isn't in the file is printed here, confirming they are built at runtime. Nothing about the format leaks — `1-2-3-4`, `AAAA-BBBB-CCCC-DDDD`, 32 hex chars and a bare number all return the same `invalid key`.

##### 4. No usable debugger, so emulate the PE

On this host every native-debugging route is closed:

- `winedbg --gdb <prog>` and plain `winedbg <prog>` both fail with `Couldn't start process` — this wine build reports `guest: i386` and will not launch an x86-64 guest.
- `gdb --args wine <prog>` loses the process across wine's exec chain; `follow-fork-mode child` + `detach-on-fork off` just hangs.
- `/proc/sys/kernel/yama/ptrace_scope` is `1`, so attaching to a wine process that isn't a gdb descendant is refused.

`angr` isn't installed either, but `unicorn` is — so the binary gets its own loader ([peemu.py](peemu.py)). Map the sections at `ImageBase`, point every IAT slot at a one-byte `0xC3` stub and implement KERNEL32 by name from a code hook on that page, fake a TEB through the GS base, and start at the **PE entry point** so the static CRT initialises itself. Returning a real command line from `GetCommandLineA/W` means the CRT builds `argv` for you, and the key is just a string in that command line.

Two details cost real time:

- **Stack arguments.** In the Win64 convention the 5th argument is at `[rsp+0x28]` — past the return address *and* 32 bytes of shadow space, not at `[rsp+8]`. Getting this wrong makes `MultiByteToWideChar` scribble on a garbage pointer.
- **The clock must advance.** A constant `QueryPerformanceCounter` sends the program into an endless `QueryPerformanceCounter`/`Sleep` loop — it is waiting on elapsed time. Advancing the counter on every query clears it instantly.

With those fixed the emulator reproduces the real thing:

```bash
$ CRACKME=./crackme_windows.bin python3 peemu.py "AAAA-BBBB-CCCC-DDDD"
=== OUTPUT ===
invalid key
```

##### 5. A snapshot harness, and the bad news it delivers

Snapshotting memory and registers at `main` and restoring them per trial ([harness.py](harness.py)) turns the emulator into a ~100 trial/sec oracle, with a `UC_HOOK_BLOCK` counter as a "how far did it get" signal. Sweeping the key length:

```
len= 1 blocks=[3639]   len=15 blocks=[3650]
len=16 blocks=[3941]   len=17 blocks=[3942]
len=32 blocks=[3943]   len=48 blocks=[3950]
```

The jump at 16 is tempting but it is only the MSVC `std::string` SSO-to-heap boundary; the slow drift after it is `memcpy` length. No length is special.

Worse, at any fixed length the block count is identical for every input, and so is the block *sequence*:

```
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA   out='invalid key' blocks=3943
BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB   out='invalid key' blocks=3943
01234567890123456789012345678901   out='invalid key' blocks=3943
all sequences identical: True
```

The check is fully oblivious: no branch anywhere depends on the input. Path-divergence, instruction counting and timing are all dead ends, and the verdict has to be selected by *data*.

##### 6. Follow the message backwards

If the verdict is data, follow the data. Hooking writes to the buffer that reaches `WriteFile` lands in the CRT's `\n`-to-`\r\n` translation in `_write`:

```asm
14003bf85:  mov  al,BYTE PTR [rsi]
14003bf8a:  cmp  al,0xa
14003bf91:  mov  BYTE PTR [rdi],0xd
14003bf97:  mov  BYTE PTR [rdi],al
```

That is just stdio, but `rsi` points at the assembled message, which is on the stack. Dumping that stack window at the moment the verdict is emitted gives the whole game away:

```
0x3003fd780: 54 48 49 53 49 53 54 48 45 4b 45 59 31 32 33 34  |THISISTHEKEY1234|
0x3003fd790: 35 20 61 6e 64 20 73 6f 6d 65 20 75 73 65 6c 65  |5 and some usele|
0x3003fd7a0: 73 73 20 6a 75 6e 6b 00 6f 3f ff 07 f8 ff ff ff  |ss junk.o?......|
0x3003fd7b0: 69 6e 76 61 6c 69 64 20 6b 65 79 00 f8 ff ff ff  |invalid key.....|
0x3003fd7c0: 76 61 6c 69 64 20 6b 65 79 20 3a 29 00 00 00 00  |valid key :)....|
```

Two 16-byte verdict buffers — `invalid key` and `valid key :)` — and directly above them, the expected key the VM reconstructed for the comparison. The oblivious check picks between the two buffers with arithmetic, which is exactly why no branch ever moved.

##### 7. The junk is the key

The obvious read is that `THISISTHEKEY12345` is the answer and `and some useless junk` is the decoy telling you so. It is the other way round:

```bash
$ wine crackme_windows.bin "THISISTHEKEY12345"
invalid key
$ wine crackme_windows.bin "THISISTHEKEY12345 and some useless junk"
valid key :)
```

The whole 39-character string is the key, self-deprecating tail included. It contains spaces, so it has to be quoted into a single `argv[1]` — which also explains the `invalid arg count` from step 3 for anyone who pastes it unquoted.

[solve.py](solve.py) does the recovery end to end, without knowing the answer in advance: run any dummy input, scrape the stack at verdict time, then re-run to confirm.

```bash
$ CRACKME=./crackme_windows.bin python3 solve.py
dummy input 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' -> invalid key
success string found at 0x3003fd7c0
recovered key (39 chars): 'THISISTHEKEY12345 and some useless junk'
verify                    -> valid key :)
truncated by one          -> invalid key
```

##### 8. Verify on the untouched binary

Instrumentation only ever touched scratch copies (an `int3` at `main` and a spin-loop, both abandoned once wine's debuggers proved unusable). The answer has to hold on the original, with nothing attached:

```bash
$ sha256sum crackme_windows.bin
5da79d1e60b21dff2ef2288fa6d83a68cf6b5f0bb5ca284f2159d525337a53e1  crackme_windows.bin

$ wine crackme_windows.bin "THISISTHEKEY12345 and some useless junk"
valid key :)

$ wine crackme_windows.bin "THISISTHEKEY12345 and some useless junk "   # trailing space
invalid key
$ wine crackme_windows.bin "thisisthekey12345 and some useless junk"    # case
invalid key
$ wine crackme_windows.bin "THISISTHEKEY12345 and some useless jun"     # truncated
invalid key
```

Exact, case-sensitive, whole-string match.

**Flag:** `THISISTHEKEY12345 and some useless junk`

### Takeaways

A constant-time checker is a statement about the *oracle*, not about the difficulty. Identical block traces across wildly different inputs killed every dynamic oracle at once — but the same property means the verdict must be selected from data held in memory, which narrows where to look rather than widening it. "No branch depends on the input" is a lead, not a wall.

A VM that compares against a key still has to materialise that key. Reconstructing the bytecode ISA would have worked and would have taken an order of magnitude longer; the expected value had to exist in memory at comparison time regardless of how elaborately it got there. Dumping the stack window around the verdict strings is worth trying before writing a disassembler for someone else's instruction set.

When the platform's debuggers are unavailable, writing a loader is a reasonable substitute and not as large a job as it sounds. Roughly forty KERNEL32 stubs — most of them returning 0 or 1 — were enough to boot a statically linked MSVC CRT to `main`, and letting `GetCommandLineW` feed the CRT means argument parsing comes for free instead of being re-implemented. Budget the time for two specific traps: Win64 stack arguments start at `[rsp+0x28]`, and any emulated clock has to move or anti-timing loops never exit.

Finally, a decoy that calls itself junk is still worth typing in full. The string literally reads `and some useless junk`, which is a good bluff — the substring that looks like the key is the part that fails.
