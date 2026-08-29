#!/usr/bin/env python3
"""
NinthCircle (WhistleDev) - keygen.
Derives a valid serial for any operator ID by reimplementing the custom VM's
key-derivation program directly. No VM emulation needed.
"""
import re, sys

M = 0xFFFFFFFF
rol = lambda v, n: ((v << (n & 31)) | ((v & M) >> (32 - (n & 31)))) & M if n & 31 else v & M
ror = lambda v, n: (((v & M) >> (n & 31)) | (v << (32 - (n & 31)))) & M if n & 31 else v & M

# Finalisation rounds: (xor r0, add r1, xor r2, add r3)
ROUNDS = [
    (0xA341316C, 0xC8013EA4, 0xAD90777D, 0x7E95761E),
    (0x9E3779B9, 0x3C6EF372, 0xDAA66D2B, 0x78DDE6E4),
    (0xBB67AE85, 0x6A09E667, 0x510E527F, 0x1F83D9AB),
    (0xC2B2AE35, 0x27D4EB2F, 0x165667B1, 0x85EBCA77),
    (0xD2511F53, 0xCD9E8D57, 0x9E3779B1, 0x94D049BB),
    (0xDEADBEEF, 0xA5A5A5A5, 0xC001D00D, 0xFEEDFACE),
]

def derive(operator_id: str):
    data = operator_id.encode()
    n = len(data)
    r0, r1, r2, r3 = 0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344
    for i, b in enumerate(data):                      # absorb
        t  = (b + 0x9E3779B9 + i) & M
        r0 = rol(r0 ^ t, 5); r0 = (r0 + r1) & M
        t  = (r0 + 0x7F4A7C15) & M
        r1 = rol(r1 ^ t, 9); r1 = (r1 * 0x85EBCA6B) & M
        t  = ((b * 0x045D9F3B) & M) ^ r1
        r2 = ror((r2 + t) & M, 7)
        t  = (((i * 0x27D4EB2D) & M) + r2 + r0) & M
        r3 = rol(r3 ^ t, 13)
    for c0, c1, c2, c3 in ROUNDS:                     # finalise
        r0 = rol((r0 + r3) & M, 7) ^ c0
        r1 = (ror(r1 ^ r0, 11) + c1) & M
        r2 = rol((r2 + r1) & M, 17) ^ c2
        r3 = (ror(r3 ^ r2, 3) + c3) & M
    r0 ^= (n * 0xA5B35705) & M                        # length mixing
    r1  = (r1 + (n * 0xC2B2AE3D)) & M
    r2 ^= (n * 0x27D4EB2F) & M
    r3  = (r3 + (n * 0x165667B1)) & M
    return "-".join("%08X" % x for x in (r0, r1, r2, r3))

VALID = re.compile(r'^[A-Z0-9_-]{4,24}$')

if __name__ == "__main__":
    ids = sys.argv[1:] or ["OPERATOR"]
    for oid in ids:
        if not VALID.match(oid):
            print(f"{oid}: invalid (need 4-24 chars of A-Z 0-9 _ -)"); continue
        print(f"{oid:26s} {derive(oid)}")
