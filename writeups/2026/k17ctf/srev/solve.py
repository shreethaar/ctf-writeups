#!/usr/bin/env python3
"""srev (K17CTF rev) -> K17{00p$_nO_s1g$}

srev is a *sigreturn-oriented* VM ("I spilled my operating systems notes all
over it"). It installs a SIGUSR1 handler that memcpy()s the kernel-supplied
ucontext into a buffer, then each "instruction" is a 248-byte sigcontext blob
that gets sigreturn()'d into:

  instr[0xa8] (RIP slot) = opcode        instr[0x90] (RAX slot) = operand

Opcodes: 1 FOLD, 2 LOAD(cond), 3 DUP(cond), 4 POP, 5 ADD, 6 SUB, 7 XOR,
         8 ROR, 9 HALT.  15 VM registers live at the sigcontext greg offsets
         [0x28,0x30,...,0xa8]; register 15 (RIP slot) doubles as "jump to
         r15-1 and pop a frame", which is how LOAD-from-table implements a
         conditional branch.

Program layout (291 instructions @ 0x403994):
   0- 1  load candidate frame, DUP it
   2-237 an invertible mix over r1..r12 (ADD/SUB/XOR imm, ADD/XOR reg,
         XOR-swap triples) -- no information is lost
 238-249 if any of r1..r12 != 0 -> goto 252
 250-251 POP, HALT  (HALT prints K17{r1..r12} when all are printable ASCII
                     and r13 == 0)
 252-290 a 12-digit odometer over 0x20..0x7e, i.e. brute force 95**12
         -> "Time Limit Exceeded"

Since 2..237 is a bijection, just run it backwards from the all-zero target.
"""
import struct
import sys

BIN = sys.argv[1] if len(sys.argv) > 1 else "srev"
CODE_VA, NINSTR, ISZ = 0x403994, 291, 0xF8
M = (1 << 64) - 1

d = open(BIN, "rb").read()
rd = lambda va, n: d[va - 0x400000: va - 0x400000 + n]

prog = []
for i in range(NINSTR):
    ins = rd(CODE_VA + i * ISZ, ISZ)
    prog.append((struct.unpack_from("<Q", ins, 0xA8)[0],    # opcode
                 struct.unpack_from("<Q", ins, 0x90)[0]))   # operand

def decode(a):
    """dest = bits 0-3, bit 4 = immediate flag, bits 8+ = imm or src reg."""
    dest = a & 0xF
    return (dest, ("i", a >> 8) if (a >> 4) & 1 else ("r", (a >> 8) & 0xF))

body = prog[2:238]

def run(regs, forward):
    r = regs[:]
    for op, a in (body if forward else reversed(body)):
        dst, (kind, v) = decode(a)
        val = v if kind == "i" else r[v]
        if op == 5:
            r[dst] = (r[dst] + val) & M if forward else (r[dst] - val) & M
        elif op == 6:
            r[dst] = (r[dst] - val) & M if forward else (r[dst] + val) & M
        elif op == 7:
            r[dst] ^= val                      # self-inverse
        else:
            raise SystemExit(f"unexpected opcode {op}")
    return r

pre = run([0] * 16, forward=False)
assert all(0x20 <= x <= 0x7E for x in pre[1:13]), pre[1:13]
assert run(pre, forward=True)[1:13] == [0] * 12   # round-trip check

print("FLAG: K17{" + "".join(chr(x) for x in pre[1:13]) + "}")
