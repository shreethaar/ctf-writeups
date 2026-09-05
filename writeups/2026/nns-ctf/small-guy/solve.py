#!/usr/bin/env python3
"""small guy (NNS CTF 2026) -- invert the cipher hidden in .eh_frame.

The 32 dispatch handlers in .text are byte-identical (`call step; jmp end`), so
the machine code computes nothing. The real program is the DWARF unwind info:
step() recurses 256 deep pushing a round constant per level, then throws, and as
the C++ unwinder walks back out each frame's DW_CFA_val_expression rewrites
rbx/r12/r13/r14. The catch handler memcmp's those four registers against 32
bytes of .rodata.

Every round op is invertible and the schedule depends only on the payload's
first two bytes, so 65536 trial keys cover the whole space: invert from the
target for each and keep the one whose first two bytes reproduce the key.
"""
import re
import struct
import subprocess
import sys

M = (1 << 64) - 1
GOLD = 0x9E3779B97F4A7C15
TBL_A, TBL_B, TARGET, JUMPTAB = 0x4014D0, 0x4015D0, 0x401DD0, 0x401DF0
REG = {'r2': 'rcx', 'r3': 'rbx', 'r12': 'r12', 'r13': 'r13', 'r14': 'r14'}


def load(path):
    """Map the ELF's PT_LOAD segments so virtual addresses can be read."""
    d = open(path, 'rb').read()
    phoff, = struct.unpack_from('<Q', d, 0x20)
    phentsize, phnum = struct.unpack_from('<HH', d, 0x36)
    segs = []
    for i in range(phnum):
        p = phoff + i * phentsize
        if struct.unpack_from('<I', d, p)[0] != 1:      # PT_LOAD
            continue
        off, vaddr = struct.unpack_from('<QQ', d, p + 8)
        filesz, = struct.unpack_from('<Q', d, p + 32)
        segs.append((vaddr, off, filesz))

    def read(va, n):
        for vaddr, off, filesz in segs:
            if vaddr <= va < vaddr + filesz:
                o = off + (va - vaddr)
                return d[o:o + n]
        raise SystemExit(f'{va:#x} not mapped')
    return read


def parse_cfi(path):
    """PC -> [(dest register, DWARF expression)] from the .eh_frame rules."""
    out = subprocess.run(['readelf', '--debug-dump=frames', path],
                         capture_output=True, text=True).stdout
    rules, pc = {}, None
    for line in out.splitlines():
        line = line.strip()
        m = re.match(r'DW_CFA_advance_loc\d?: \d+ to ([0-9a-f]+)', line)
        if m:
            pc = int(m.group(1), 16)
            continue
        m = re.match(r'DW_CFA_val_expression: (r\d+) \(\w+\) \((.*)\)$', line)
        if m and pc is not None:
            rules.setdefault(pc, []).append((REG[m.group(1)], m.group(2)))
    return rules


def compile_op(dst, expr):
    """One DWARF expression -> a small opcode tuple."""
    ops = [o.strip() for o in expr.split(';')]
    if len(ops) == 1:                                   # half of a register swap
        src = re.fullmatch(r'DW_OP_breg(\d+) \(\w+\): 0', ops[0]).group(1)
        return ('copy', dst, REG['r' + src])
    body = '; '.join(ops[1:])

    m = re.fullmatch(r'DW_OP_constu: (\d+); DW_OP_(plus|mul)', body)
    if m:
        return ('addc' if m.group(2) == 'plus' else 'mulc', dst, int(m.group(1)))
    if body == 'DW_OP_breg2 (rcx): 0; DW_OP_xor':
        return ('xorkey', dst)
    m = re.fullmatch(r'DW_OP_breg2 \(rcx\): 0; DW_OP_constu: (\d+); DW_OP_mul; DW_OP_plus', body)
    if m:
        return ('addmul', dst, int(m.group(1)))
    m = re.fullmatch(r'DW_OP_breg(\d+) \(\w+\): 0; DW_OP_dup; DW_OP_constu: (\d+); DW_OP_shl; '
                     r'DW_OP_swap; DW_OP_constu: \d+; DW_OP_shr; DW_OP_or; DW_OP_xor', body)
    if m:
        return ('xorrot', dst, REG['r' + m.group(1)], int(m.group(2)))
    m = re.fullmatch(r'DW_OP_breg2 \(rcx\): 0; DW_OP_lit3; DW_OP_and; DW_OP_lit1; DW_OP_plus; '
                     r'DW_OP_swap; DW_OP_constu: (\d+); DW_OP_mul; DW_OP_constu: (\d+); '
                     r'DW_OP_plus; DW_OP_swap; DW_OP_lit1; DW_OP_minus; DW_OP_dup; '
                     r'DW_OP_bra: -\d+; DW_OP_drop', body)
    if m:
        return ('lcg', dst, int(m.group(1)), int(m.group(2)))
    raise ValueError('unparsed expression: ' + expr)


def rotl(v, s):
    return ((v << s) | (v >> (64 - s))) & M


def apply_ops(ops, st, inverse):
    if len(ops) == 2 and ops[0][0] == 'copy':           # swap is its own inverse
        (_, d1, s1), (_, d2, s2) = ops
        st[d1], st[d2] = st[s1], st[s2]
        return
    for op in (reversed(ops) if inverse else ops):
        kind, dst = op[0], op[1]
        if kind == 'addc':
            st[dst] = (st[dst] + (-op[2] if inverse else op[2])) & M
        elif kind == 'mulc':
            k = pow(op[2], -1, 1 << 64) if inverse else op[2]
            st[dst] = (st[dst] * k) & M
        elif kind == 'xorkey':
            st[dst] ^= st['rcx']
        elif kind == 'addmul':
            step = st['rcx'] * op[2]
            st[dst] = (st[dst] + (-step if inverse else step)) & M
        elif kind == 'xorrot':
            st[dst] ^= rotl(st[op[2]], op[3])
        elif kind == 'lcg':
            x, mul, add = st[dst], op[2], op[3]
            inv = pow(mul, -1, 1 << 64)
            for _ in range((st['rcx'] & 3) + 1):
                x = ((x - add) * inv) & M if inverse else (x * mul + add) & M
            st[dst] = x


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else './small-guy'
    read = load(path)
    rules = parse_cfi(path)

    tbl_a = read(TBL_A, 256)
    tbl_b = list(struct.unpack('<256Q', read(TBL_B, 256 * 8)))
    target = read(TARGET, 32)
    handlers = struct.unpack('<32Q', read(JUMPTAB, 32 * 8))
    ops = [[compile_op(d, e) for d, e in rules[a]] for a in handlers]

    def schedule(key):
        """(handler index, rcx) per round, in unwinding order i = 255..0."""
        mix = (key * GOLD) & M
        out, prev = [], 0
        for i in range(255, -1, -1):
            out.append(((tbl_a[i] + (key >> (i & 7))) & 0x1F, prev))
            prev = tbl_b[i] ^ mix
        return out

    for key in range(1 << 16):
        q = struct.unpack('<4Q', target)
        st = {'rbx': q[0], 'r12': q[1], 'r13': q[2], 'r14': q[3], 'rcx': 0}
        for k, rcx in reversed(schedule(key)):
            st['rcx'] = rcx
            apply_ops(ops[k], st, inverse=True)
        cand = struct.pack('<4Q', st['rbx'], st['r12'], st['r13'], st['r14'])
        if struct.unpack('<H', cand[:2])[0] == key and all(32 <= c < 127 for c in cand):
            print(f"NNS{{{cand.decode()}}}")
            return
    print('no solution found', file=sys.stderr)


if __name__ == '__main__':
    main()
