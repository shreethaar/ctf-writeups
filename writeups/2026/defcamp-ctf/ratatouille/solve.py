#!/usr/bin/env python3
"""RATatouille (DefCamp CTF 2026) — recover the .recipe plaintext.

The 70-byte .recipe section is XORed with a xorshift64* keystream whose seed is
an FNV-1a-64 over seven fields of the implant's expected "activation profile".
Every field value is read out of the compare immediates in the gate at 0x125f0.
"""

M     = (1 << 64) - 1
PRIME = 0x100000001B3
BASIS = 0xCBF29CE484222325
MUL   = 0x2545F4914F6CDD1D          # xorshift64* multiplier, 0x1d75e

BIN    = "ratatouille"
RECIPE = (0x47B1B6, 0x46)           # .recipe vaddr == file offset, 70 bytes

# The seven FNV inputs, in the order sub_1d6c0 marshals them into sub_12840.
# Values are byte-exact from the gate's cmp immediates (sub_125f0):
#   bit 0  len 5   "linux"            bit 1  len 6   "x86_64"
#   bit 3  len 4   "remy"             bit 4  len 7   "gusteau"
#   bit 5  len 9   "/bin/bash"        bit 6  len 15  "auguste-gusteau"
#   bit 7  len 14  "confit-byaldi\n"  -> trailing \n stripped by sub_1d6c0
FIELDS = [
    b"linux",
    b"x86_64",
    b"remy",
    b"gusteau",
    b"/bin/bash",
    b"auguste-gusteau",
    b"confit-byaldi",
]


def seed_from_profile(fields):
    """FNV-1a-64 with a ^0xff,*prime separator after *every* field (sub_12840),
    then the tail mix at 0x12dab."""
    h = BASIS
    for f in fields:
        for b in f:
            h = ((h ^ b) * PRIME) & M
        h = ((h ^ 0xFF) * PRIME) & M
    return h ^ 0x72617461746F7569      # "ratatoui"


def keystream(seed, n):
    """xorshift64*, top byte of the product — the loop at 0x1d770."""
    x = seed
    for _ in range(n):
        x ^= x >> 12
        x ^= (x << 25) & M
        x ^= x >> 27
        yield ((x * MUL) & M) >> 56


def validate(pt):
    """sub_127e0: len 70, 'DCTF' '{' ... '}', 64 hex digits between."""
    return (len(pt) == 0x46 and pt[:5] == b"DCTF{" and pt[0x45:] == b"}"
            and all(c in b"0123456789abcdefABCDEF" for c in pt[5:0x45]))


def main():
    off, n = RECIPE
    blob = open(BIN, "rb").read()[off:off + n]

    seed = seed_from_profile(FIELDS)
    pt   = bytes(c ^ k for c, k in zip(blob, keystream(seed, n)))

    print("seed  =", hex(seed))
    print("flag  =", pt.decode())
    print("valid =", validate(pt))       # the binary's own check, sub_127e0


if __name__ == "__main__":
    main()
