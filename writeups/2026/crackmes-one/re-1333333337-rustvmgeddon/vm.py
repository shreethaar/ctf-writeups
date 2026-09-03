#!/usr/bin/env python3
"""rustvmgeddon -- VM emulator, bytecode trace, and bytecode repair.

The interpreter is inlined into rustvmgeddon::main (0x84c0). Its 20-byte
program lives in two places: 16 bytes at .rodata:0x4e000 (loaded with a
single movaps) and the trailing 4 bytes as the immediate 0x55321076 of the
`mov DWORD PTR [rsp+0x120], imm32` at .text:0x8cb4.

Every opcode and every operand is XOR-0xAA obfuscated -- except the ROL
shift count, which uses key 0x02.

    ./vm.py rustvmgeddon             # trace the shipped bytecode
    ./vm.py rustvmgeddon --patch out # write a copy with the bytecode repaired
"""
import re
import subprocess
import sys

KEY = 0xAA
TARGET = bytes.fromhex("deadbeeffedcba98")   # LE u64 0x98badcfeefbeadde
RODATA_VA, IMM_VA, PROG_LEN = 0x4E000, 0x8CB4, 0x14
NAMES = {0xAB: "PUSH", 0xAD: "ADD", 0xAE: "XOR", 0xAF: "CHECK", 0xB4: "ROL", 0xFF: "HALT"}


def loads(path):
    """Map virtual addresses to file offsets using the PT_LOAD headers."""
    out = subprocess.check_output(["readelf", "-l", "-W", path]).decode()
    segs = []
    for line in out.splitlines():
        m = re.match(r"\s*LOAD\s+0x(\w+)\s+0x(\w+)\s+0x\w+\s+0x(\w+)", line)
        if m:
            segs.append((int(m[1], 16), int(m[2], 16), int(m[3], 16)))
    def v2o(va):
        for off, base, fsz in segs:
            if base <= va < base + fsz:
                return off + (va - base)
        raise ValueError(f"unmapped va {va:#x}")
    return v2o


def read_bytecode(path):
    v2o = loads(path)
    d = open(path, "rb").read()
    o1, o2 = v2o(RODATA_VA), v2o(IMM_VA)
    return d[o1:o1 + 16] + d[o2:o2 + 4]


def run(prog, verbose=True):
    stack, pc = [], 0
    while pc < PROG_LEN:
        op = prog[pc] ^ KEY
        name = NAMES.get(op, f"BAD({op:#04x})")
        if op == 0xAB:                                   # PUSH imm^0xAA
            arg = prog[pc + 1] ^ KEY
            stack.append(arg)
        elif op == 0xAD:                                 # ADD imm^0xAA
            arg = prog[pc + 1] ^ KEY
            if stack:
                stack[-1] = (stack[-1] + arg) & 0xFF
        elif op == 0xAE:                                 # XOR imm^0xAA
            arg = prog[pc + 1] ^ KEY
            if stack:
                stack[-1] ^= arg
        elif op == 0xB4:                                 # ROL by (raw imm ^ 2) & 7
            arg = (prog[pc + 1] ^ 0x02) & 7
            if stack:
                stack[-1] = ((stack[-1] << arg) | (stack[-1] >> (8 - arg))) & 0xFF
        elif op == 0xAF:                                 # CHECK top-8 against TARGET
            ok = len(stack) >= 8 and bytes(stack[-8:]) == TARGET
            if verbose:
                print(f"  pc={pc:<3}CHECK  len={len(stack)} -> "
                      f"{'Access Granted.' if ok else 'Access Denied.'}")
            if not ok:
                return "DENIED"
            pc += 1
            continue
        elif op == 0xFF:
            if verbose:
                print(f"  pc={pc:<3}HALT")
            return "HALT"
        else:
            if verbose:
                print(f"  pc={pc:<3}{name} -> Invalid opcode")
            return "INVALID"
        if verbose:
            print(f"  pc={pc:<3}{name:<6}{arg:#04x}   stack={bytes(stack).hex()}")
        pc += 2
    return "END"


def repaired():
    """The program the author meant to write: PUSH each target byte, then CHECK."""
    prog = b"".join(bytes([0x01, b ^ KEY]) for b in TARGET)   # 0x01 = PUSH encoded
    return prog + bytes([0x05, 0x55, 0x55, 0x55])             # CHECK, HALT, pad


def patch(src, dst):
    v2o = loads(src)
    d = bytearray(open(src, "rb").read())
    fixed, o1, o2 = repaired(), v2o(RODATA_VA), v2o(IMM_VA)
    assert bytes(d[o2:o2 + 4]) == bytes.fromhex("76103255"), "immediate mismatch"
    d[o1:o1 + 16], d[o2:o2 + 4] = fixed[:16], fixed[16:20]
    open(dst, "wb").write(d)
    print(f"wrote {dst}: .rodata:{RODATA_VA:#x} and .text:{IMM_VA:#x} patched")


if __name__ == "__main__":
    binary = sys.argv[1]
    prog = read_bytecode(binary)
    print("shipped bytecode")
    print("  raw    :", prog.hex(" "))
    print("  decoded:", bytes(b ^ KEY for b in prog).hex(" "))
    print("trace"); print(" ", run(prog))
    print("\nrepaired bytecode")
    print("  raw    :", repaired().hex(" "))
    print("trace"); print(" ", run(repaired()))
    if "--patch" in sys.argv:
        patch(binary, sys.argv[sys.argv.index("--patch") + 1])
