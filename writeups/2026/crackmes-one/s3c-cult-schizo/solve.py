#!/usr/bin/env python3
"""
Schizo (crackmes.one, S3c_Cult) -- full static solve.

  1. derive the AES key from the binary's own .sforce2 section
  2. decrypt lib.so  -> lib_dec.so   (needs pycryptodome; skipped if absent)
  3. decode the two obfuscated tables in .rodata
  4. invert ___1 to recover the five flag fragments

Run from the challenge directory (needs ./schizo, optionally ./lib.so).
"""
import hashlib, sys
from pathlib import Path

SFORCE2_OFF, SFORCE2_LEN = 0xb7d10, 0x3c6
T1_ADDR, T2_ADDR = 0xc02a0, 0xc02c1          # .rodata, 5 NUL-terminated strings each
M32 = 0xFFFFFFFF


# ---------------------------------------------------------------- basE91-style codec
# Radix 91 (digit = c - 0x21), two digits packed into 13 bits, MSB-first (sub_afebb).
def b91_decode(s):
    if isinstance(s, str):
        s = s.encode('latin-1')
    out, hi, nbits, acc = bytearray(), None, 0, 0
    for ch in s:
        if hi is None:
            hi = ch - 0x21
            continue
        nbits += 13
        acc = (acc | ((hi * 91 + (ch - 0x21)) << ((32 - nbits) & 31))) & M32
        while True:
            out.append((acc >> 24) & 0xFF)
            acc = (acc << 8) & M32
            nbits -= 8
            if nbits < 8:
                break
        hi = None
    if hi is not None:                        # trailing odd character
        out.append((((acc >> 24) & 0xFF) | (((hi << ((32 - (nbits + 6)) & 31)) & M32) >> 24)) & 0xFF)
    return bytes(out)


def dec_str(s):
    """___4: undo the ___3 string obfuscation."""
    b = b91_decode(s)
    return bytes(ror8((~(x - 9 * i)) & 0xFF, 3) for i, x in enumerate(b))


# ---------------------------------------------------------------- ___1 primitives
def rol8(v, n):
    n &= 7
    return v if n == 0 else ((v << n) | (v >> (8 - n))) & 0xFF


def ror8(v, n):
    n &= 7
    return v if n == 0 else ((v >> n) | (v << (8 - n))) & 0xFF


class RNG:
    """xorshift32; prng_byte() returns bits 8..15."""
    def __init__(self, s):
        self.s = s & M32

    def byte(self):
        s = self.s
        s ^= (s << 13) & M32
        s ^= s >> 17
        s ^= (s << 5) & M32
        self.s = s & M32
        return (self.s >> 8) & 0xFF


def build_sboxes(seed):
    r = RNG(seed if seed else 0xdeadbeef)
    sb = list(range(256))
    for i in range(255, 0, -1):
        j = r.byte() % (i + 1)
        sb[i], sb[j] = sb[j], sb[i]
    inv = [0] * 256
    for i, v in enumerate(sb):
        inv[v] = i
    return sb, inv


def build_perms(seed, rounds, n):
    r = RNG(seed ^ 0x5a5a5a5a)
    base = list(range(n))
    for i in range(n - 1, 0, -1):
        j = r.byte() % (i + 1)
        base[i], base[j] = base[j], base[i]
    out = []
    for _ in range(rounds):
        out.append(base[:])
        if n >= 2:
            a, b = r.byte() % n, r.byte() % n
            base[a], base[b] = base[b], base[a]
    return out


def round_keys(seed, rounds, n):
    r = RNG(seed ^ 0xc3c3c3c3)
    k1 = [[0] * n for _ in range(rounds)]
    k2 = [[0] * n for _ in range(rounds)]
    for rr in range(rounds):
        for i in range(n):
            k1[rr][i] = r.byte()
            k2[rr][i] = r.byte()
    return k1, k2


def seed_of(pt):
    s = ((sum(pt) * 0x85EBCA6B) ^ (len(pt) * 0x9E3779B1) ^ 0xA3C59AC3) & M32
    return s or 0xcafebabe


def enc1(pt):
    pt = list(pt)
    n = len(pt)
    seed = seed_of(pt)
    rounds = (seed & 7) + 6
    sb, _ = build_sboxes(seed ^ 0xa5a5a5a5)
    perms = build_perms(seed ^ 0x3c3c3c3c, rounds, n)
    k1, k2 = round_keys(seed, rounds, n)
    st = pt[:]
    for r in range(rounds):
        st = [st[i] ^ k1[r][i] for i in range(n)]
        st = [sb[b] for b in st]
        st = [st[perms[r][i]] for i in range(n)]
        st = [rol8(st[i], (r + i) & 7) for i in range(n)]
        st = [(st[i] + k2[r][i]) & 0xFF for i in range(n)]
    return seed.to_bytes(4, 'big') + bytes([rounds]) + bytes(st)


def dec1(ct):
    """___1 stores its own seed and round count in the output -- no search needed."""
    seed = int.from_bytes(ct[:4], 'big')
    rounds = ct[4]
    st = list(ct[5:])
    n = len(st)
    _, inv = build_sboxes(seed ^ 0xa5a5a5a5)
    perms = build_perms(seed ^ 0x3c3c3c3c, rounds, n)
    k1, k2 = round_keys(seed, rounds, n)
    for r in reversed(range(rounds)):
        st = [(st[i] - k2[r][i]) & 0xFF for i in range(n)]
        st = [ror8(st[i], (r + i) & 7) for i in range(n)]
        new = [0] * n
        for i in range(n):
            new[perms[r][i]] = st[i]
        st = [inv[b] for b in new]
        st = [st[i] ^ k1[r][i] for i in range(n)]
    return bytes(st)


# ---------------------------------------------------------------- sub_9cc9
def split_indexed(s):
    """Shortest prefix whose base91 decode is all digits -> (index, remainder)."""
    for L in range(1, len(s) + 1):
        d = b91_decode(s[:L])
        if d and all(0x30 <= b <= 0x39 for b in d):
            return int(d), s.replace(s[:L], '', 1)
    raise ValueError('no index prefix in %r' % s)


# ---------------------------------------------------------------- driver
def read_table(exe, addr, count=5):
    out = []
    for _ in range(count):
        end = exe.index(b'\0', addr)
        out.append(exe[addr:end].decode('latin-1'))
        addr = end + 1
    return out


def main():
    here = Path(sys.argv[1] if len(sys.argv) > 1 else '.')
    exe = (here / 'schizo').read_bytes()

    # 1/2 -- key is SHA256 of the hex dump of the binary's own .sforce2 section
    sec = exe[SFORCE2_OFF:SFORCE2_OFF + SFORCE2_LEN]
    key = hashlib.sha256(''.join('%02x' % b for b in sec).encode()).digest()
    print('[*] AES-256 key : %s' % key.hex())
    print('[*] IV          : %s' % bytes(range(16)).hex())
    blob = here / 'lib.so'
    if blob.exists():
        try:
            from Crypto.Cipher import AES
            pt = AES.new(key, AES.MODE_CBC, bytes(range(16))).decrypt(blob.read_bytes())
            pt = pt[:-pt[-1]]
            (here / 'lib_dec.so').write_bytes(pt)
            print('[+] lib_dec.so  : %d bytes, magic %s' % (len(pt), pt[:4]))
        except ImportError:
            print('[-] pycryptodome missing; skipping lib.so decryption')

    # 3 -- the two indexed tables
    keys = dict(split_indexed(s) for s in read_table(exe, T1_ADDR))
    expect = dict(split_indexed(s) for s in read_table(exe, T2_ADDR))

    # 4 -- invert ___1 on each expected value
    print('\nidx  X-Fragment-Key  seed      rnds  fragment')
    frags = []
    for i in sorted(expect):
        ct = b91_decode(expect[i])
        pt = dec1(ct)
        assert seed_of(pt) == int.from_bytes(ct[:4], 'big'), 'seed self-check failed'
        assert enc1(pt) == ct, 'round-trip failed'
        print('%3d  %-14r %08x  %-4d  %r' % (i, keys[i], int.from_bytes(ct[:4], 'big'), ct[4], pt))
        frags.append(pt)

    print('\nFLAG: %s' % b''.join(frags).decode())


if __name__ == '__main__':
    main()
