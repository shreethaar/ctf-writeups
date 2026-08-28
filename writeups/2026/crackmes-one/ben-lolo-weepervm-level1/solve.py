#!/usr/bin/env python3
"""
Ben_Lolo -- WeeperVM Level 1  :  solver

The binary embeds a register VM ("weep" ISA) whose bytecode lives in the .weep
section and whose data/memory lives in .lotus.  The sacred phrase is checked by
running the 32-byte input through a 16-round Feistel network (2 x 16-byte
blocks) and comparing against 32 constants embedded as CMP immediates.

The Feistel is invertible, so we simply decrypt the target constants.
Everything below is derived from the binary itself.
"""
import struct, sys

ELF = sys.argv[1] if len(sys.argv) > 1 else "WeeperVM--Level_1"
raw = open(ELF, "rb").read()

# --- pull .lotus (VM memory) and .weep (VM code) straight out of the ELF -----
def sections(buf):
    e_shoff, = struct.unpack_from("<Q", buf, 0x28)
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", buf, 0x3a)
    sh = lambda i: struct.unpack_from("<IIQQQQIIQQ", buf, e_shoff + i*e_shentsize)
    stroff = sh(e_shstrndx)[4]
    out = {}
    for i in range(e_shnum):
        n, _, _, _, off, size = sh(i)[:6]
        name = buf[stroff+n : buf.index(b"\0", stroff+n)].decode()
        out[name] = buf[off:off+size]
    return out

S     = sections(raw)
LOTUS = S[".lotus"]
WEEP  = list(struct.unpack("<%dI" % (len(S[".weep"])//4), S[".weep"]))

# --- VM constants -----------------------------------------------------------
SB   = list(LOTUS[128:144])                                   # packed nibble S-boxes
KOFF = [7, 6, 2, 1, 5, 0, 3, 4]                               # bit n -> L[(i+KOFF[n])%8]
K0   = bytes(LOTUS[160+i] ^ LOTUS[176+i] for i in range(16))   # round key built at weep[398..412]
PERM = [(0x80, 0x10), (0x40, 0x04), (0x20, 0x80), (0x10, 0x08),
        (0x08, 0x20), (0x04, 0x40), (0x02, 0x01), (0x01, 0x02)]

def perm(v):
    r = 0
    for src, dst in PERM:
        if v & src: r |= dst
    return r

def F(R, K, r1):
    """One round's 8-byte output, XORed into the left half."""
    acc = [0]*8
    r0 = r1
    for b in range(8):
        v  = R[b]
        hi, lo = (v & 0xf0) >> 4, v & 0x0f
        if K[r1] & (1 << b):                       # key bit picks the S-box halves
            P = ((SB[hi] & 0x0f) << 4) | ((SB[lo] & 0xf0) >> 4)
        else:
            P = (SB[hi] & 0xf0) | (SB[lo] & 0x0f)
        P = perm((P ^ K[r0]) & 0xff)
        for n in range(8):
            acc[(b + KOFF[n]) % 8] ^= P & (0x80 >> n)
        if b < 7:
            r0 = (r0 + 1) % 16
    return acc

RKEYS = [(7*t) % 16 for t in range(16)]            # r1 at the top of each round

def dec_block(blk, K):
    blk = bytes(blk[8:] + blk[:8])                 # undo trailing swap (weep[623..641])
    L, R = list(blk[:8]), list(blk[8:])
    for r1 in reversed(RKEYS):                     # (L',R') -> (R' ^ F(L'), L')
        f = F(L, K, r1)
        L, R = [R[i] ^ f[i] for i in range(8)], L
    return bytes(L + R)

def enc_block(blk, K):
    L, R = list(blk[:8]), list(blk[8:])
    for r1 in RKEYS:                               # (L,R) -> (R, L ^ F(R))
        f = F(R, K, r1)
        L, R = R, [L[i] ^ f[i] for i in range(8)]
    return bytes(R + L)

def rotkey(K):                                     # weep[642..672]: K'[(i+9)%16] = K[i]
    o = bytearray(16)
    for i in range(16): o[(i+9) % 16] = K[i]
    return bytes(o)

def crypt(data, fn):
    K, out = K0, b""
    for b in range(2):
        out += fn(data[b*16:(b+1)*16], K)
        K = rotkey(K)
    return out

# --- recover the 32 target bytes from the CMP immediates in .weep ------------
def decode(w):
    w ^= ((w >> 16) & 0xff) * 0x01010101           # per-instruction self-decrypt
    return w & 0xffffffff

target = {}
for word in WEEP:
    if not word: continue
    w  = decode(word)
    op, dm, sm = w >> 28, (w >> 27) & 1, (w >> 25) & 3
    A,  B      = (w >> 8) & 0xff, w & 0xff
    if op == 9 and dm == 1 and sm == 2 and 64 <= A <= 95:   # CMP M[64+i], #imm
        target[A] = B
assert len(target) == 32, f"expected 32 CMP constants, got {len(target)}"
target = bytes(target[64+i] for i in range(32))

flag = crypt(target, dec_block)
assert crypt(flag, enc_block) == target, "verification failed"

print("round key K0 :", K0.hex())
print("target       :", target.hex())
print("sacred phrase:", flag.decode())
