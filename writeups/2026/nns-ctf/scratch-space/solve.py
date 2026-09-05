#!/usr/bin/env python3
"""scratch-space (NNS CTF 2026) -- recover the passphrase without running it.

main() mmaps an anonymous page, fills it with plaintext from a static LCG
keystream, compares it against stdin with a hand-rolled byte loop, then zeroes
and unmaps the page before printing a verdict. Nothing in the generator depends
on input, clock or environment, so the page can be rebuilt offline instead of
raced in a debugger.
"""
import struct
import sys

SEED = 0x311023DF
MUL = 0x343FD
ADD = 0x269EC3
BLOB_VADDR = 0x404040  # <blob>
BLOB_LEN = 42


def vaddr_to_off(data, vaddr):
    """Map a virtual address to a file offset via the PT_LOAD segments."""
    phoff = struct.unpack_from("<Q", data, 0x20)[0]
    phentsize, phnum = struct.unpack_from("<HH", data, 0x36)
    for i in range(phnum):
        p = phoff + i * phentsize
        if struct.unpack_from("<I", data, p)[0] != 1:  # PT_LOAD
            continue
        p_offset, p_vaddr = struct.unpack_from("<QQ", data, p + 8)
        p_filesz = struct.unpack_from("<Q", data, p + 32)[0]
        if p_vaddr <= vaddr < p_vaddr + p_filesz:
            return p_offset + (vaddr - p_vaddr)
    raise SystemExit("vaddr %#x is not in any PT_LOAD segment" % vaddr)


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "./scratch-space"
    data = open(path, "rb").read()

    off = vaddr_to_off(data, BLOB_VADDR)
    blob = data[off:off + BLOB_LEN]

    state = SEED
    out = bytearray()
    for b in blob:
        state = (state * MUL + ADD) & 0xFFFFFFFF
        out.append(b ^ ((state >> 16) & 0xFF))

    print(out.decode())


if __name__ == "__main__":
    main()
