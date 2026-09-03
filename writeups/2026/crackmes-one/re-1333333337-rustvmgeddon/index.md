---
title: "RustVMgeddon"
layout: default
---

# RustVMgeddon

- Category: rev
- Challenge author: Re_1333333337
- Platform: Linux x86-64 (ELF PIE, dynamically linked, not stripped, Rust)

The download ships a bare binary with no description and no stated flag format, so the goal has to be inferred: it prompts `Enter input: ` and answers either `Access Granted.` or `Access Denied.`. The name promises a VM and it delivers one — a small XOR-obfuscated stack machine — wrapped in anti-debug and anti-VM checks and a SHA-256 of the input.

The unusual part is what happens when you actually chase the data flow. The SHA-256 is never read, the bytecode never touches the input, and the shipped program is missing the opcodes that would make its own comparison satisfiable. `Access Granted.` is not reachable on the binary as distributed, by any input. The answer is still recoverable — it is sitting in the bytecode as data — but this writeup ends by *proving* the unreachability rather than by finding a password, because there isn't one.

### Solution:

##### 1. One function does everything

```bash
$ file rustvmgeddon
rustvmgeddon: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV),
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, ... not stripped
```

`kuna functions` reports 557, but almost all of them are Rust runtime. Filtering out `core::`/`std::`/`alloc::`/demangler internals leaves exactly one function belonging to the crate — `rustvmgeddon::main` at `0x84c0`, running to `0x9190`, about 3.2 KB. It is a release build with everything inlined, so the whole challenge is that single function.

Two names in the survey are worth flagging early: `sha2::sha256::compress256`, and `std::fs::File::read_to_string` — a crackme that reads *files* is doing something other than checking a password.

`strings` explains what files. Rust merges string literals into one blob, and this one decomposes cleanly:

```
/proc/self/status   /sys/class/dmi_id/product_name   /sys/class/dmi_id/sys_vendor
/proc/scsi/scsi     /sys/devices/virtual/dmi_id/board_vendor
virtualbox   vmware   qemu
"Access Denied."  "Access Granted."  "Invalid opcode: 0x"  "Enter input: "
"Execution blocked (Debugger or VM detected)."
```

`ptrace` is in the import table too. So: anti-debug, anti-VM, then a bytecode interpreter.

##### 2. A binary that blocks itself

Running it gives `Execution blocked (Debugger or VM detected).` — with no debugger attached, on bare metal, most of the time but not always. That flakiness is the interesting bug.

The check is the first thing `main` does:

```
84db:  call QWORD PTR [rip+0x5b84f]   # ptrace@GLIBC, called as ptrace(0,0,0,0)
84e1:  cmp  rax,0xffffffffffffffff
84e5:  je   8952                      # -1 -> "Execution blocked"
```

`ptrace(PTRACE_TRACEME, ...)` returns `-1` only if the process is already traced. Undebugged it *succeeds* — and that is the problem, because succeeding makes the process traced **by its own parent**, which sets its own `TracerPid`. The binary then reads that value back:

```
84ff:  call read_to_string("/proc/self/status", 17)
       ... locate the line beginning "TracerPi" "d:" ...
8c3c:  call core::str::trim_end_matches
8c41:  test rdx,rdx
8c44:  je   8faa                      # empty -> blocked
8c4a:  cmp  BYTE PTR [rax+rdx*1-0x1],0x30    # last char == '0' ?
8c4f:  sete bl
8c6b:  je   8952                      # not '0' -> blocked
```

There is no length comparison before that byte test, so this is `ends_with('0')`, not `== "0"`. After a successful `TRACEME` the field holds the parent's PID, and the binary passes only when **the parent's PID ends in the digit 0**.

That is testable. Launching it 40 times through a wrapper that prints its own PID, the only runs that got through were these:

```
PASS parent_pid=807662    PASS parent_pid=807732    PASS parent_pid=807792
PASS parent_pid=807802    PASS parent_pid=807892    PASS parent_pid=807962
=== pass=6 fail=34 ===
```

Every passing PID ends in `2`, and the wrapper is forked two PIDs after the subshell that parents the binary — so in each case the actual parent's PID ended in `0`. Six of forty is the ~1-in-10 the theory predicts. No patching is needed to get through this reliably, just a launcher that forks until it is itself a suitable parent ([run.py](run.py)):

```python
if os.getpid() % 10 == 0:            # our PID ends in 0 -> good parent
    res = subprocess.run([binary], input=data, capture_output=True)
```

The anti-VM layer at `0x86d8` is more conventional and, here, inert: four `read_to_string` calls over the DMI and SCSI paths above, each lowercased and tested with `str::is_contained_in` against `virtualbox`, `vmware` and `qemu` (`0x87eb`, `0x883a`, `0x8889`). A read that fails is skipped rather than treated as suspicious, and the DMI files are not world-readable on this host, so only `/proc/scsi/scsi` is actually examined.

##### 3. A SHA-256 that goes nowhere

Past the prompt, the input is trimmed at `0x8a5d` and hashed. The IV load at `0x8a89`, the bulk `compress256` at `0x8ac4`, the `0x80` padding byte and `bswap`-ed length at `0x8ba0`-`0x8b9d`, and the final `compress256` at `0x8c34` are a stock SHA-256, leaving the digest at `[rsp+0x80]`.

Then nothing reads it. Every reference to that buffer after `0x8c34` is either a `lea` taking its address to reuse the slot as `print!` arguments, or a store into it:

```bash
$ # all post-hash references to [rsp+0x80..0x9f], reads only
$ awk '/^ *8c3a:/,0' main.asm | grep -E 'rsp\+0x(8[0-9a-f]|9[0-9a-f])\]' \
    | grep -v 'mov .* PTR \[rsp\+0x[89]' | grep -v 'movaps XMMWORD PTR \[rsp'
    8c7e:  lea rdi,[rsp+0x80]        # print! args
    8ce7:  lea r12,[rsp+0x80]        # print! args
    ...
```

The hash is a decoy: it consumes the input and is discarded. That is the first sign that the input may not matter at all.

##### 4. The VM

At `0x8c9e` a 20-byte program is loaded to `[rsp+0x110]` — 16 bytes from `.rodata:0x4e000` in one `movaps`, plus a trailing `mov DWORD PTR [rsp+0x120],0x55321076`. The dispatcher follows:

```
8d25:  movzx eax,BYTE PTR [rsp+r15*1+0x110]   # fetch prog[pc]
8d2e:  xor   eax,0xaa                         # deobfuscate
8d37:  lea   ecx,[rax-0xab]
8d3d:  cmp   ecx,0x9
8d40:  ja    8ef3                             # out of range -> HALT/invalid
8d46:  movsxd rax,DWORD PTR [rbp+rcx*4+0x0]   # jump table at 0x4e580
8d4e:  jmp   rax
```

Every opcode and operand byte is XOR-`0xAA`. The stack is a `Vec<u8>`; `[rsp+0x10]` is its capacity, `[rsp+0x18]` its pointer and `[rsp+0x20]` its length. Decoding the ten-entry table gives the ISA:

| raw | decoded | op | effect | size |
|-----|---------|-------|--------|------|
| `01` | `0xAB` | PUSH | `push(imm ^ 0xAA)` | 2 |
| `07` | `0xAD` | ADD | `top += imm ^ 0xAA` | 2 |
| `04` | `0xAE` | XOR | `top ^= imm ^ 0xAA` | 2 |
| `05` | `0xAF` | CHECK | compare, then fall through | 1 |
| `1e` | `0xB4` | ROL | `top = rol(top, (imm ^ 2) & 7)` | 2 |
| `55` | `0xFF` | HALT | stop | 1 |

Two details are easy to misread. `ROL` obfuscates its shift count with key `0x02`, not `0xAA` (`8ea0: xor cl,0x2`) — the only operand in the ISA that does. And the five remaining table slots (`0xAC`, `0xB0`-`0xB3`) all point at the same `Invalid opcode` stub at `0x8efa`, so the decompiler collapsing them into one arm is accurate, not a lost branch:

```
op 0xab -> 0x8d50    op 0xac -> 0x8efa    op 0xad -> 0x8d86    op 0xae -> 0x8dc5
op 0xaf -> 0x8e0f    op 0xb0 -> 0x8efa    op 0xb1 -> 0x8efa    op 0xb2 -> 0x8efa
op 0xb3 -> 0x8efa    op 0xb4 -> 0x8e6e
```

`CHECK` is the whole game:

```
8cdd:  movabs rbx,0x98badcfeefbeadde        # hoisted out of the loop
...
8e0f:  mov  rax,[rsp+0x20]                  # len
8e14:  cmp  rax,0x8
8e18:  jb   8eb1                            # fewer than 8 -> Access Denied
8e1e:  mov  rcx,[rsp+0x18]                  # ptr
8e23:  cmp  QWORD PTR [rcx+rax*1-0x8],rbx   # top 8 bytes as LE u64
8e28:  jne  8eb1
8e2e:  ... "Access Granted." ...            # then continues the loop
```

Read little-endian, `0x98badcfeefbeadde` is the byte string `de ad be ef fe dc ba 98`. So the VM must build `deadbeeffedcba98` on its stack.

##### 5. The bytecode, and the author's bug

Pulling all 20 bytes and XOR-ing them ([vm.py](vm.py)):

```
raw    : 01 ab 04 af 07 a9 04 ae 1e ab 05 74 07 14 45 54 76 10 32 55
decoded: ab 01 ae 05 ad 03 ae 04 b4 01 af de ad be ef fe dc ba 98 ff
```

Stepping it:

```
  pc=0  PUSH  0x01   stack=01
  pc=2  XOR   0x05   stack=04
  pc=4  ADD   0x03   stack=07
  pc=6  XOR   0x04   stack=03
  pc=8  ROL   0x01   stack=06
  pc=10 CHECK  len=1 -> Access Denied.
```

`CHECK` needs eight bytes and finds one. And the reason is visible in the raw bytes: the tail `74 07 14 45 54 76 10 32` is exactly `de ad be ef fe dc ba 98` under the same XOR-`0xAA`. The eight target bytes were laid down as raw data with **no `0x01` PUSH opcode in front of each one**, so the interpreter never pushes them — it reads `05` (CHECK) at `pc=10` and stops. The answer is present in the program, as an operand stream that nothing executes.

![Curated control-flow graph of rustvmgeddon::main: entry through the ptrace and TracerPid anti-debug checks and the DMI anti-VM reads to a shared "Execution blocked" sink, the input prompt feeding a SHA-256 whose digest is discarded, then the bytecode dispatch loop with its PUSH/ADD/XOR/ROL/CHECK handlers, CHECK falling to "Access Denied." with the "Access Granted." path marked unreachable](callgraph.png)

The graph is a control-flow graph rather than a call graph: with the whole challenge inlined into one function there are no interesting call edges, and the branching *inside* `main` is the thing worth drawing. It was written by hand from the verified addresses above and rendered with `dot -Tpng -Gdpi=140`, because the labels needed to say what each block does rather than repeat its address.

##### 6. Proof, on a scratch copy

The claim "no input can pass" deserves better than a hand trace, so: repair the bytecode in a **copy** and see what changes. The repair is mechanical — interleave the missing PUSH opcodes:

```python
prog = b"".join(bytes([0x01, b ^ KEY]) for b in TARGET)   # 0x01 = PUSH encoded
return prog + bytes([0x05, 0x55, 0x55, 0x55])             # CHECK, HALT, pad
```

which is 18 bytes and fits the 20-byte budget. It goes back in the two places the program is built from — 16 bytes at `.rodata:0x4e000`, and the `0x55321076` immediate at `.text:0x8cb4`:

```
$ python3 vm.py rustvmgeddon --patch scratch_patched
  pc=14 PUSH  0x98   stack=deadbeeffedcba98
  pc=16 CHECK  len=8 -> Access Granted.
  pc=17 HALT
wrote scratch_patched: .rodata:0x4e000 and .text:0x8cb4 patched
```

Running both, through the launcher from step 2 and with no debugger attached:

```
$ python3 run.py ./scratch_patched deadbeef whatever ""
'deadbeef'   -> 'Enter input: Access Granted.'
'whatever'   -> 'Enter input: Access Granted.'
''           -> 'Enter input: Access Granted.'

$ python3 run.py ./rustvmgeddon deadbeef whatever ""
'deadbeef'   -> 'Enter input: Access Denied.'
'whatever'   -> 'Enter input: Access Denied.'
''           -> 'Enter input: Access Denied.'

$ sha256sum rustvmgeddon
aecc68a1059106ffb693fa8bf38b870e8ed4bb0ac863c00b75460f47834cfb91  rustvmgeddon
```

The patched build grants on *every* input including the empty one, which confirms two things at once: the reading of the ISA is exact, and the input genuinely has no bearing on the verdict. The untouched original denies everything.

##### 7. Compared with the published solution

There is an accepted solution for this crackme by **Berardinis**, and it lands on the same bottom line — no input passes, so the binary has to be patched — but by a different route and from a different reading of the VM. Its patches work: the archive it ships prints `Access Granted.` for every input, which I confirmed by running it.

Where it diverges is the origin of the bytecode:

> The input string is then hashed using **SHA-256**. The first 20 bytes of the resulting hash are interpreted as bytecode for a custom stack-based virtual machine.

and, following from that, its explanation of why the challenge cannot be solved by input — that doing so would require a partial preimage on SHA-256, which is infeasible.

The bytecode is not hash-derived. It is the 20-byte constant from `.rodata:0x4e000` plus the `0x55321076` immediate, and the digest at `[rsp+0x80]` is never read at all. Two cheap experiments separate the two models. Changing a single byte of `.rodata:0x4e000` from `01` to `00`, leaving the entire SHA-256 path untouched, changes what the VM does — and changes it identically for every input:

```bash
$ python3 -c "d=bytearray(open('rustvmgeddon','rb').read()); d[0x4e000]=0x00; \
              open('one_byte_test','wb').write(d)"          # 0x00 ^ 0xAA = 0xAA, not an opcode
$ chmod +x one_byte_test && python3 run.py ./one_byte_test deadbeef hello
'deadbeef'   -> 'Enter input: Invalid opcode: 0xAA'
'hello'      -> 'Enter input: Invalid opcode: 0xAA'
```

And the shipped binary is stable across inputs where the hash model predicts noise. Of the 256 possible values for the first decoded byte, only five are executable opcodes and one is `HALT`; the other 250 print `Invalid opcode: 0x..`. So a hash-derived program should print that in roughly 97.7% of runs. It never does:

```
$ # 30 random inputs, pristine binary
   30x  'Access Denied.'
```

The misreading is an easy one to fall into, and it is worth recording precisely because the binary sets the trap. `[rsp+0x110]` really is part of the SHA-256 computation — it holds the final padding block written at `0x8bf3`-`0x8c17` — and the VM really does fetch its instructions from `[rsp+0x110]`. The only thing separating those two facts is the `movaps` at `0x8ca5` that overwrites the buffer with the `.rodata` constant in between. Miss that single instruction and "the VM runs on the hash" is the natural conclusion; the SHA-256 is positioned to be mistaken for the mechanism rather than merely ignored.

The anti-debug description differs too. The published solution reads the check as testing whether `TracerPid` is non-zero, and attributes the spurious blocking it observed on clean bare-metal Debian to the anti-VM check. As step 2 shows, the test is `ends_with('0')` against a field that `PTRACE_TRACEME` has just populated with the parent's PID, which is why it fires on honest machines about nine times in ten — and why it does not need patching at all.

One last difference worth noting for anyone diffing the two: the published archive carries four patches, not the three its writeup documents.

```
0x84e5  0f 84 67 04 00 00  ->  e9 ba 04 00 00 90    jmp 0x89a4     documented
0x8d1f  0f 83 42 02 00 00  ->  e9 0a 01 00 00 90    jmp 0x8e2e     documented
0x8e28  0f 85 83 00 00 00  ->  90 90 90 90 90 90    NOP the cmp    undocumented
0x8e69  e9 a6 fe ff ff     ->  e9 f9 00 00 00       jmp 0x8f67     documented
```

The undocumented one is inert. Patching `0x8d1f` turns it into an *unconditional* `jmp 0x8e2e`, and every opcode handler returns through `0x8d17` into `0x8d1f`, so control reaches the success printer after the VM's very first instruction. `CHECK` at `0x8e0f` is never executed, and NOPping its mismatch branch cannot matter. That is the real structural difference between the two approaches: forcing the outcome exits the interpreter after one instruction and so never has to be right about the ISA, whereas repairing the bytecode makes the VM compute the target itself and lets `CHECK` succeed on its own terms.

So there is no accepting password. The value the challenge was built around — embedded in its own bytecode as the operands of the PUSHes that were never emitted, and hoisted into `rbx` as the comparison target — is:

**Flag:** `deadbeeffedcba98`

### Takeaways

An anti-debug check can be the vulnerability. `ptrace(PTRACE_TRACEME)` is normally paired with a `TracerPid` read as belt-and-braces, but the two interact: `TRACEME` *succeeding* is what populates `TracerPid` with the parent's PID, so the second check is reading a value the first one just created. Testing it with `ends_with('0')` instead of `== "0"` turned a deterministic guard into a ~1-in-10 dice roll that mostly blocks legitimate runs. When a protection behaves non-deterministically with no debugger present, the flakiness itself is the lead worth pulling.

Verify that a decoy is a decoy before spending time on it. SHA-256 is expensive-looking and draws attention, and here it was reachable, correct, and completely dead — one `awk`/`grep` pass over the disassembly for reads of the digest buffer settled it in a minute and redirected the whole analysis. "Which instructions consume this value?" is usually a faster question than "what does this algorithm compute?". The published solution treats the digest as the VM's bytecode and concludes the challenge needs a SHA-256 partial preimage — a much harder-sounding wrong answer that a single check for readers of that buffer rules out.

Patch to *disprove*, not just to bypass. The interesting result here was negative, and a hand trace saying "`CHECK` sees one byte" is not very convincing on its own. Repairing the bytecode in a scratch copy and watching it grant access on every input — including the empty string — is positive evidence for both the ISA decode and the claim that the input is unused, and it costs one file copy. Keeping the original pristine and diffing behaviour against it is what makes the comparison mean anything.
