# small guy

- Category: rev
- Difficulty: none
- Author: 0xle

"A small guy once told me something special. Life hasn't been the same ever since."

`.text` is 931 bytes and computes nothing at all — the 32 dispatch handlers are byte-identical. The actual program lives in the DWARF unwind tables, and the "small guy" doing the work is `_Unwind`.

### Solution:

##### 1. main is trivial, and `.vmin` is the giveaway

```asm
400468:  cmp    DWORD PTR [rbx],0x7b534e4e      ; "NNS{"
400470:  cmp    BYTE PTR [rbx+rax*1-0x1],0x7d   ; '}'
40047b:  cmp    rax,0x20                        ; payload must be 32 chars
4004aa:  movdqu xmm0,XMMWORD PTR [rbx]          ; payload -> .vmin (0x4d0000)
4004ba:  movzx  eax,WORD PTR [rip+0xcfb3f]      ; key = payload's first 2 bytes
4004cf:  call   0x400600                        ; run the "VM"
4004e3:  call   memcmp                          ; 0x404080 vs 0x401dd0, 32 bytes
```

A custom 40-byte RW section, `.vmin`, holds the 32-byte payload plus an 8-byte key word taken from its first two characters. `NNS{th15_is_n0t_th3_fl4g}` also sits in `.data`, for anyone who stops at `strings`.

##### 2. The dispatcher recurses, then throws

```asm
400618:  cmp    eax,0x100                       ; depth 256 -> throw
40062a:  movzx  r8d,BYTE PTR [rax+0x4014d0]     ; tbl_a[i]
400638:  mov    r10,QWORD PTR [rip+0xcf9e1]     ; key
40063f:  shr    r10,cl                          ; key >> (i & 7)
400645:  and    r8d,0x1f                        ; -> handler index
400649:  mov    r9,QWORD PTR [rax*8+0x4015d0]   ; tbl_b[i]
400658:  movabs r11,0x9e3779b97f4a7c15
400666:  xor    r9,r10                          ; round constant
400669:  push   r9
40066b:  push   r9
400671:  jmp    QWORD PTR [r8*8+0x401df0]
```

Every one of the 32 jump targets is the same two instructions — `call step ; jmp end` — so the dispatch index changes nothing about control flow, and the pushed constants are never read by any instruction. At depth 256 it throws an `int`, and the catch handler at `0x4003f0` stores `rbx/r12/r13/r14` into `0x404080`, which is exactly the buffer `memcmp` checks.

Four callee-saved registers hold the answer, and nothing in `.text` ever writes them. A 1816-byte `.eh_frame` attached to functions this trivial is the only place left.

##### 3. The unwind tables are the cipher

`readelf --debug-dump=frames` decodes the entire program, no custom parser needed. At the throw site the CFI seeds the state straight out of `.vmin`:

```
DW_CFA_val_expression: r3  (rbx) (DW_OP_addr: 4d0000; DW_OP_deref)
DW_CFA_val_expression: r12 (r12) (DW_OP_addr: 4d0008; DW_OP_deref)
DW_CFA_val_expression: r13 (r13) (DW_OP_addr: 4d0010; DW_OP_deref)
DW_CFA_val_expression: r14 (r14) (DW_OP_addr: 4d0018; DW_OP_deref)
```

and each handler stub carries one round operation, with `rcx` restored from the stack slot holding that frame's pushed constant:

```
DW_CFA_offset_extended: r2 (rcx) at cfa-24
DW_CFA_val_expression:  r14 (r14) (DW_OP_breg14: 0; DW_OP_breg12: 0; DW_OP_dup;
                         DW_OP_constu: 53; DW_OP_shl; DW_OP_swap;
                         DW_OP_constu: 11; DW_OP_shr; DW_OP_or; DW_OP_xor)
```

which is `r14 ^= rotl(r12, 53)`. Across the 32 stubs it is a tidy ARX instruction set: 8 add-constant, 4 multiply-constant, 8 xor-rotate, 4 xor-key, 4 add-key×constant, 2 register swaps, and 2 iterated LCGs whose repeat count comes from `rcx & 3`. The jump table at `0x401df0` maps each handler index to its rule, keyed on the range `[handler, handler+5)` — the unwinder looks up `return address - 1`, which lands inside the `call`, not the `jmp` after it.

![Diagram of small guy: main copies the payload into .vmin, step recurses 256 deep through 32 identical handler stubs pushing round constants, throws, and the unwinder then applies one ARX round per frame before the catch handler stores four registers for memcmp](callgraph.png)

##### 4. Invert it

Two details had to match the real unwinder before the simulator agreed with the binary:

- rounds apply in **unwinding** order, `i = 255 … 0`;
- the `rcx` a round sees is the constant pushed by the frame *inside* it, not its own — DWARF expressions read the register context of the frame being unwound *from*.

With those right, a simulator reproduced the binary's output exactly for a known input. Every round op is invertible (all multipliers are odd), and the round schedule depends only on the 16-bit key, so 65536 trial keys cover the entire space: invert from the target for each candidate and keep the one whose first two bytes reproduce the key it assumed.

```
$ ./solve.py ./small-guy
NNS{unw1nd_m3_1f_y0u_c4n_sm4ll_guy!!}

$ ./small-guy 'NNS{unw1nd_m3_1f_y0u_c4n_sm4ll_guy!!}'
Correct!
```

Full script: [solve.py](solve.py)

**Flag:** `NNS{unw1nd_m3_1f_y0u_c4n_sm4ll_guy!!}`

### Takeaways

- Identical dispatch handlers are the tell. If a jump table's targets are all the same bytes, the table is not selecting behaviour in the code — it is selecting behaviour somewhere else, and the operand it indexes with is the real opcode.
- `.eh_frame` is executable in every sense that matters. `DW_CFA_val_expression` runs a small stack language during unwinding, so exception handling can carry arbitrary computation that no disassembler view of `.text` will ever show. A `.eh_frame` disproportionate to the code it describes is the signal.
- `readelf --debug-dump=frames` decodes the whole thing for free — this is one of the rare obfuscation schemes where standard binutils is a complete decompiler for the hidden program.
- When a keyed permutation's schedule depends only on a small part of the input, that part is a brute-force key and the rest falls out by inversion. Check the size of what the schedule actually reads before assuming a 256-bit state means a 256-bit search.
