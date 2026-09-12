#!/usr/bin/env python3
"""Solver for cat-ctf 'Silent Stranger'.

Three arguments, three gates, each one's code encrypted under the previous
argument, so they have to fall in order:

  arg1 (31)  level 1 -- plaintext in .rdata, 248 per-bit checks
  arg2 (24)  level 2 -- decrypted with arg1, 24 arithmetic constraints (z3)
  arg3 (33)  level 3 -- decrypted with arg2, SEH-dispatched per-byte checks

The flag is the final .rdata blob decrypted under SHA256(arg1|arg2|arg3).

Needs: unicorn, capstone, z3-solver, and launcher.exe in the cwd.
"""
import hashlib
import struct

from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from unicorn import UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_EAX
from z3 import BitVec, BitVecVal, If, LShR, Or, Solver, sat, unsat

import emu
import seh

EXE = 'launcher.exe'
RDATA_VA, RDATA_OFF = 0x41b000, 0x19a00

# .rdata layout, read straight out of sub_401470
L1_VA, L1_LEN = 0x41b1b0, 0x534f
L2_VA, L2_LEN = 0x420508, 0x59d
L3_VA, L3_LEN = 0x420aa8, 0x1a38
FL_VA, FL_LEN = 0x4224e8, 0x4f


def blob(va, n):
    with open(EXE, 'rb') as f:
        d = f.read()
    off = RDATA_OFF + (va - RDATA_VA)
    return d[off:off + n]


def keystream_xor(src, key):
    """sub_401220: dst[i] = src[i] ^ SHA256(key || u32le(ctr))[i % 32]."""
    out, ctr, dig = bytearray(), 0, b''
    for i, b in enumerate(src):
        if i % 32 == 0:
            dig = hashlib.sha256(key + struct.pack('<I', ctr)).digest()
            ctr += 1
        out.append(b ^ dig[i % 32])
    return bytes(out)


# ---------------------------------------------------------------- level 1
def solve_lvl1():
    """Each of the 248 blocks is

        call  <opaque>          ; the expected bit, obfuscated
        xor   eax, ebp          ; ebp = PEB->BeingDebugged
        and   eax, 1
        movzx edx, byte [edi+k] ; input byte k
        shr   edx, j            ; absent when j == 0
        and   edx, 1
        xor   eax, edx
        xor   eax, 1
        add   ebx, eax          ; +1 per matching bit, and ebx must reach 0xF8

    so EAX at the `movzx` *is* the expected bit.  One emulation reads all 248.
    """
    code = blob(L1_VA, L1_LEN)
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    insns = {i.address: i for i in md.disasm(code, 0)}

    sites = {}
    for addr, ins in insns.items():
        if ins.mnemonic != 'movzx' or not ins.op_str.startswith('edx, byte ptr [edi'):
            continue
        k = int(ins.op_str.split('+')[1].rstrip(']'), 16) if '+' in ins.op_str else 0
        nxt = insns.get(addr + ins.size)
        j = int(nxt.op_str.split(',')[1], 16) if nxt and nxt.mnemonic == 'shr' \
            and nxt.op_str.startswith('edx,') else 0
        sites[emu.CODE + addr] = (k, j)
    assert len(sites) == 248, len(sites)

    bits = {}
    uc = emu.build(blob=code)
    uc.mem_write(emu.INPUT, b'\x00' * 31)
    emu.call(uc, emu.CODE, [emu.INPUT, 31],
             hook=lambda u, a, s, d: bits.__setitem__(
                 sites[a], u.reg_read(UC_X86_REG_EAX) & 1) if a in sites else None)

    out = bytearray(31)
    for (k, j), b in bits.items():
        out[k] |= b << j
    arg1 = bytes(out)

    uc = emu.build(blob=code)
    uc.mem_write(emu.INPUT, arg1)
    assert emu.call(uc, emu.CODE, [emu.INPUT, 31]) == 1, 'level 1 rejected arg1'
    return arg1


# ---------------------------------------------------------------- level 2
_BIN = {'add': lambda x, y: x + y, 'sub': lambda x, y: x - y,
        'xor': lambda x, y: x ^ y, 'and': lambda x, y: x & y,
        'or': lambda x, y: x | y, 'shl': lambda x, y: x << y,
        'shr': lambda x, y: LShR(x, y), 'imul': lambda x, y: x * y}


def solve_lvl2(arg1):
    """Straight-line constraints, each ending in

        cmp eax, IMM / setne dl / movzx edx, dl / or edi, edx

    with the function returning (edi == 0).  The poison register ebx is fed
    only by heap-debug detection and by two callback probes whose answers are
    known, so it is 0 on a clean run: fix it and hand the compares to z3.
    """
    code = keystream_xor(blob(L2_VA, L2_LEN), arg1)
    md = Cs(CS_ARCH_X86, CS_MODE_32)

    inp = [BitVec(f'b{i}', 32) for i in range(24)]
    zero = BitVecVal(0, 32)
    regs = {'eax': zero, 'ecx': zero, 'edx': zero}
    cmp_pair, cons = None, []
    low = {'al': 'eax', 'cl': 'ecx', 'dl': 'edx', 'bl': 'ebx'}
    rd = lambda n: zero if n == 'ebx' else regs.get(n, zero)

    for ins in md.disasm(code, 0):
        m, ops = ins.mnemonic, ins.op_str
        if m in ('jmp', 'je', 'jne', 'jg', 'jl', 'jge', 'jle', 'ja', 'jb',
                 'jecxz', 'loop', 'nop', 'ud2', 'ret', 'push', 'pop', 'leave',
                 'lea', 'call', 'int1', 'int3'):
            continue                       # junk, convergent jcc triples, stack
        dst = ops.split(',')[0].strip()
        if dst == 'ebx':
            continue                       # the poison register
        if m == 'movzx':
            if 'byte ptr [esi' in ops:
                k = int(ops.split('+')[1].rstrip(']'), 16) if '+' in ops else 0
                regs[dst] = inp[k]
            else:
                regs[dst] = rd(low[ops.split(',')[1].strip()])
        elif m == 'mov':
            if dst in regs:
                src = ops.split(',')[1].strip()
                regs[dst] = rd(src) if src in ('eax', 'ecx', 'edx', 'ebx') else zero
        elif m in _BIN:
            if m == 'or' and dst == 'edi':
                cons.append(rd(ops.split(',')[1].strip()) == 0)
                continue
            if dst not in regs:
                continue
            p = [x.strip() for x in ops.split(',')]
            if m == 'imul' and len(p) == 3:
                a, b = rd(p[1]), BitVecVal(int(p[2], 16), 32)
            else:
                a = rd(dst)
                b = rd(p[1]) if p[1] in ('eax', 'ecx', 'edx', 'ebx') \
                    else BitVecVal(int(p[1], 16) & 0xffffffff, 32)
            regs[dst] = _BIN[m](a, b)
        elif m in ('cmp', 'test'):
            p = [x.strip() for x in ops.split(',')]
            a = rd(p[0]) if p[0] in ('eax', 'ecx', 'edx', 'edi', 'ebx') else zero
            b = rd(p[1]) if p[1] in ('eax', 'ecx', 'edx', 'edi', 'ebx') \
                else BitVecVal(int(p[1], 16) & 0xffffffff, 32)
            cmp_pair = (a, b) if m == 'cmp' else (a & b, zero)
        elif m in ('setne', 'sete'):
            r = low[ops.strip()]
            if r == 'ebx':
                continue
            a, b = cmp_pair
            regs[r] = If(a != b, BitVecVal(1, 32), zero) if m == 'setne' \
                else If(a == b, BitVecVal(1, 32), zero)
        else:
            raise AssertionError(f'unhandled: {m} {ops}')

    s = Solver()
    s.add(*cons, *[(b >= 0x20) for b in inp], *[(b <= 0x7e) for b in inp])
    assert s.check() == sat
    mdl = s.model()
    arg2 = bytes(mdl[b].as_long() for b in inp)
    s.add(Or([b != mdl[b].as_long() for b in inp]))
    assert s.check() == unsat, 'arg2 is not unique in printable ASCII'

    # re-check against the untouched blob, with a faithful host callback
    cb = bytes.fromhex('8b44240883f81f0f94c00fb6c08b4c240c85c97402890131c0c3')
    uc = emu.build(blob=code)
    uc.mem_write(emu.CB, cb)
    uc.mem_write(emu.INPUT, arg2)
    assert emu.call(uc, emu.CODE, [emu.INPUT, 24, emu.CB]) == 1, 'level 2 rejected arg2'
    return arg2, code


# ---------------------------------------------------------------- level 3
ACC = 0x42c6a9          # or dword ptr [state+0xc], eax  -- one hit per byte


def solve_lvl3(arg2):
    """Level 3 faults on purpose and lets its SEH handlers pick the next Eip,
    so it needs a dispatcher (seh.py) on top of Unicorn.  Hooking the single
    accumulator instruction turns the one boolean it returns into 33 per-byte
    bits -- and since the checks are position-independent, feeding it a uniform
    string tells us every position that equals that character at once.
    """
    code = keystream_xor(blob(L3_VA, L3_LEN), arg2)

    def flags(arg):
        uc = emu.build(lvl3=code)
        uc.mem_write(emu.INPUT, arg + b'\0')
        emu.push_args(uc, [emu.INPUT, len(arg)])
        out = []
        uc.hook_add(UC_HOOK_CODE,
                    lambda u, a, s, d: out.append(u.reg_read(UC_X86_REG_EAX) & 1),
                    begin=ACC, end=ACC)
        r = seh.SehRunner(uc, emu.RET_MAGIC, emu.SCRATCH, emu.TEB)
        return r.run(0x42c000), out

    sol = [None] * 33
    for c in range(0x20, 0x7f):
        for i, bit in enumerate(flags(bytes([c]) * 33)[1]):
            if bit == 0:
                sol[i] = c
        if all(x is not None for x in sol):
            break
    assert all(x is not None for x in sol), 'level 3: unresolved positions'

    arg3 = bytes(sol)
    assert flags(arg3)[0] == 1, 'level 3 rejected arg3'
    return arg3


if __name__ == '__main__':
    arg1 = solve_lvl1()
    print(f'arg1 ({len(arg1)}) = {arg1.decode()}')
    arg2, _ = solve_lvl2(arg1)
    print(f'arg2 ({len(arg2)}) = {arg2.decode()}')
    arg3 = solve_lvl3(arg2)
    print(f'arg3 ({len(arg3)}) = {arg3.decode()}')

    digest = hashlib.sha256(arg1 + b'|' + arg2 + b'|' + arg3).digest()
    print(f'\nsha256 = {digest.hex()}')
    print(keystream_xor(blob(FL_VA, FL_LEN), digest).decode())
