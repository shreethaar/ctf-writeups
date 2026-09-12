# srev

- Category: rev

"I wrote this program for a competitive programming contest the other day. Unfortunately, before I could get it to work I tripped and spilled my operating systems notes all over it. Also I kept getting this annoying 'Time Limit Exceeded' verdict. Maybe you can make it work?"

The operating systems notes are `sigreturn`. `srev` is a virtual machine whose instruction dispatch is not a jump table or an indirect call — it is a signal frame handed back to the kernel, so each "instruction" is a `sigcontext` and the VM registers are saved general-purpose registers.

### Solution:

##### 1. The program is data, not code

It hangs, which is the promised TLE. The section table says why there is nothing to read:

```
  [12] .text    PROGBITS  0000000000401100  001100  000bae
  [14] .rodata  PROGBITS  0000000000402000  002000  0133bc
```

2990 bytes of code against 78 KB of read-only data. `.rodata` opens with a magic and two counts, and the interesting strings are all VM diagnostics:

```
$ xxd -s 0x20e0 -l 16 srev
000020e0: 5352 4556 0001 0000 1900 0000 2301 0000  SREV........#...

$ strings srev | grep -E 'halt|K17|signal'
halt: empty stack
K17{
halt: depth=%zu
signal setup
```

`0x19` = 25 and `0x123` = 291. `main` turns those into a table base and a code base:

```asm
401150:  lea    rax,[rip+0xfa1]            ; 0x4020f8   table base
401162:  mov    QWORD PTR [rip+0x15f63],0x19    ; 25 table entries
401179:  add    rax,0x189c                 ; 25 * 0xfc = 0x189c
40117f:  mov    QWORD PTR [rip+0x15f3a],rax     ; 0x403994   code base
401195:  mov    QWORD PTR [rip+0x15f28],0x123   ; 291 instructions
4011a0:  mov    QWORD PTR [rip+0x15f2d],0xfc    ; 252-byte table stride
```

##### 2. Dispatch is `rt_sigreturn`

`main` does nothing but install a `SIGUSR1` handler and raise it:

```asm
4011e2:  call   4010a0 <sigemptyset@plt>
4011ec:  mov    edi,0xa                    ; SIGUSR1
4011f1:  call   401070 <sigaction@plt>
4011fe:  mov    edi,0xa
401203:  call   401030 <raise@plt>
401210:  call   401480                     ; enter the VM
```

The handler's entire body is a copy of the kernel-supplied `ucontext` into a buffer:

```asm
4013b0:  mov    rsi,rdx                    ; rdx = ucontext (SA_SIGINFO)
4013b7:  lea    rdi,[rip+0x2d942]          ; 0x42ed00
4013be:  mov    edx,0x3c8
4013c3:  call   4010b0 <memcpy@plt>
```

That is the whole trick. With a real signal frame captured, `0x401480` restores it, splices a 248-byte record from `.rodata` over the top of it, and returns into it:

```asm
401480:  mov    rbx,QWORD PTR [rip+0x15c59]  ; pc
40149c:  imul   rbx,rbx,0xf8                 ; 248-byte instructions
4014c7:  mov    r12,QWORD PTR [rbx+0x90]     ; instr[0x90] -> RAX slot = operand
4014ce:  mov    rbp,QWORD PTR [rbx+0xa8]     ; instr[0xa8] -> RIP slot = opcode
4014d5:  call   4010b0 <memcpy@plt>          ; restore saved ucontext
4014da:  movdqu xmm0,XMMWORD PTR [rbx]       ; ... then overwrite 0xf8 bytes of it
4015b3:  cmp    ebp,0x9                      ; 10 opcodes
4015cc:  jmp    rax

4015e0:  mov    QWORD PTR [rip+0x2d3c1],rax  ; [0x42e9a8] RIP   := handler addr
4015ee:  mov    QWORD PTR [rip+0x2d3ab],rax  ; [0x42e9a0] RSP   := scratch
4015f5:  mov    QWORD PTR [rip+0x2d394],r12  ; [0x42e990] RAX   := operand
4015fc:  mov    QWORD PTR [rip+0x2d3d9],0x0  ; [0x42e9e0] fpstate := NULL
401607:  mov    rsp,rcx
40160a:  mov    rax,0xf                      ; __NR_rt_sigreturn
401611:  syscall
```

So an instruction *is* a `sigcontext`. Read against the x86-64 `uc_mcontext` layout, `+0xa8` is the `RIP` slot and `+0x90` is `RAX` — the opcode is smuggled in as a return address and the operand as a register value.

The same layout gives the register file. A VM frame is 248 bytes, and the 16 register indices map onto `greg` offsets:

```
idx  0    1     2     3     4     5     6     7     8     9    10    11    12    13    14    15
off  0  0x28  0x30  0x38  0x40  0x48  0x50  0x58  0x60  0x68  0x70  0x78  0x80  0x88  0x98  0xa8
          R8    R9   R10   R11   R12   R13   R14   R15   RDI   RSI   RBP   RBX   RDX   RCX   RIP
```

Register 15 lands on the `RIP` slot, and `0x401660` gives it a second job — a non-zero r15 pops the current frame and jumps to `r15 - 1`, which is how a `LOAD` of a table entry becomes a conditional branch.

##### 3. The call graph has a hole in it, on purpose

![Call graph of srev showing main installing a SIGUSR1 handler, the handler saving the kernel ucontext, and the exec/sigreturn/next cycle feeding six opcode handlers that are entered by sigreturn rather than by call, with HALT branching to a flag-printing sink and two failure sinks](callgraph.png)

Worth generating this one from the decompiler rather than `r2 -A`, because `r2` cannot see half of it:

```
$ r2 -A -q -c afl ./srev | wc -l
21
$ kuna functions ./srev --json | jq '.functions | length'
53
```

The gap is not noise. `r2` discovers functions by following cross-references, and *nothing calls the opcode handlers* — `0x401750` (FOLD), `0x4017f0` (LOAD), `0x401970` (DUP), `0x401ac0` (POP), `0x4016b0` (ALU), `0x401b30` (HALT) and the signal handler `0x4013b0` are all entered by the kernel restoring a `RIP` value. There is no `call` instruction to follow, so they are simply absent from `agC` output.

##### 4. The instruction set

Ten opcodes, decoded from the jump table at `0x402038`:

| op | handler | meaning |
|---|---|---|
| 1 | `0x401750` | FOLD — add a register into the parent frame for each bit of a mask, then pop |
| 2 | `0x4017f0` | LOAD — push `table[idx]` if a predicate holds |
| 3 | `0x401970` | DUP — clone the frame `n` below the top |
| 4 | `0x401ac0` | POP `n` frames |
| 5-8 | `0x4016b0` | ADD / SUB / XOR / ROR |
| 9 | `0x401b30` | HALT |

ALU operands pack as `dest = bits 0-3`, `bit 4 = immediate flag`, `bits 8+ = immediate or source register`; the conditional ops (`0x4013d0`) pack as `idx = bits 0-23`, `compare code = bits 24-27`, `register = bits 28-31`, `immediate = bits 32-63`, with six compare forms (`==`, `!=`, `<u`, `>=u`, `<s`, `>=s`).

Dumping all 291 instructions gives a program in four parts:

```
  0- 1   LOAD table[0] ; DUP           -- candidate frame, plus a working copy
  2-237  XOR/ADD/SUB over r1..r12      -- the mix
238-249  if r1..r12 != 0 -> goto 252
250-251  POP 1 ; HALT
252-290  a 12-digit odometer over 0x20..0x7e, wrapping into r13
```

Table entry 0 is the initial candidate — `r1..r12 = 0x20`, twelve spaces — and entries 1..24 exist only to carry an `r15` jump target.

##### 5. Where the TLE comes from, and why it does not matter

Instructions 252-290 increment `r12`, branch back to 1 while it is under `0x7f`, subtract `0x5f` to wrap it and carry into `r11`, and so on down to `r1`. That is a brute force over 95^12 printable strings — about 5.4e23 — checking each one for `r1..r12 == 0` after the mix. HALT only prints when all twelve registers are printable ASCII *and* r13 (the overflow counter) is still zero:

```asm
401b87:  sub    rdx,0x20
401b8b:  cmp    rdx,0x5e                  ; 0x20 <= reg <= 0x7e, for r1..r12
401ba4:  cmp    QWORD PTR [rsi+0x88],0x0  ; r13 == 0, i.e. odometer never wrapped
401c3a:  fwrite("K17{", 1, 4, stdout)     ; then putc each of r1..r12, then "}"
```

But the mix in 2-237 is only ever `XOR` with an immediate or register, `ADD`/`SUB` with an immediate, `ADD` of one register into another, and XOR-swap triples. Every one of those is invertible, so the search is pointless — run the block backwards from the all-zero target and the unique preimage falls out:

```python
def run(regs, forward):
    r = regs[:]
    for op, a in (body if forward else reversed(body)):
        dst, (kind, v) = decode(a)
        val = v if kind == "i" else r[v]
        if   op == 5: r[dst] = (r[dst] + val) & M if forward else (r[dst] - val) & M
        elif op == 6: r[dst] = (r[dst] - val) & M if forward else (r[dst] + val) & M
        elif op == 7: r[dst] ^= val            # self-inverse
    return r

pre = run([0] * 16, forward=False)
```

```
$ ./solve.py
FLAG: K17{00p$_nO_s1g$}
```

Full script: [solve.py](solve.py)

##### 6. Confirm it against the VM

Cheapest possible check, and it exercises the real interpreter rather than a Python model of it: patch the recovered bytes into table entry 0 so the odometer starts on the answer instead of on twelve spaces.

```python
base = 0x4020f8 - 0x400000 + 4          # table[0] frame
for i, c in enumerate(b'00p$_nO_s1g$', 1):
    d[base + REGOFF[i] : base + REGOFF[i] + 8] = bytes([c]) + b'\0' * 7
```

```
$ ./srev_patched
K17{00p$_nO_s1g$}
$ echo $?
0
```

**Flag:** `K17{00p$_nO_s1g$}`

### Takeaways

- A fetch-decode-execute loop does not have to look like one. Here the dispatch is a `syscall`, the opcode lives in the `RIP` slot of a signal frame and the operand in the `RAX` slot — so the usual tells (a big `switch`, a handler table, an indirect `jmp`) are all absent from the decompiled `main`.
- When dispatch is not a `call`, cross-reference-based function discovery silently under-reports. `r2 -A` found 21 functions where `kuna` found 53, and the missing 32 were the entire instruction set. Always diff two tools' function lists on a stripped binary before trusting a call graph.
- "Time Limit Exceeded" in the prompt is a hint about the *algorithm*, not the harness. A brute force over a transform built only from `ADD`/`SUB`/`XOR`/swap is a bijection with a known output — the search space is a decoy and the answer is one pass backwards.
