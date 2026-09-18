#!/usr/bin/env python3
"""HollowDex (DefCamp CTF 2026) — invert the recovered verifyFlag.

After patch_dex.py, Verifier.verifyFlag is a 3-round Feistel over the two
big-endian u64 halves of the 16 key bytes:

    round(prev, cur, K) = prev ^ rotl64(cur + K, 17) ^ K

    j4 = round(L,  R,  K1)
    j6 = round(R,  j4, K2)   == T4   (checked)
    j8 = round(j4, j6, K3)   == T5   (checked)

Each round is a bijection in `prev`, so (T4, T5) pins j4, then R, then L.
"""

import hashlib

M = (1 << 64) - 1

K1 = 2611923443488327891 & M
K2 = 1376283091369227076 & M
K3 = (-6626703657320631856) & M      # `j6 - 6626703657320631856` == `j6 + K3` mod 2^64

T4 = 6146647970834606741 & M         # required j6
T5 = (-5423340355720311942) & M      # required j8


def rotl17(v):
    """Java's (v >>> 47) | (v << 17)."""
    v &= M
    return ((v >> 47) | (v << 17)) & M


def rnd(prev, cur, k):
    return (prev ^ rotl17((cur + k) & M) ^ k) & M


def recover_key():
    j4 = rnd(T5, T4, K3)
    r = rnd(T4, j4, K2)
    l = rnd(j4, r, K1)
    return l.to_bytes(8, "big") + r.to_bytes(8, "big")


# --- independent check: a literal transcription of the decompiled Java -------
def verify_flag(s):
    """Java semantics: signed 64-bit longs, >>> as a logical shift."""
    def sl(x):
        x &= M
        return x - (1 << 64) if x >> 63 else x

    def ushr(x, n):
        return (x & M) >> n

    def shl(x, n):
        return sl((x & M) << n)

    if s is None or len(s) != 32:
        return False
    b = []
    for i in range(16):
        try:
            hi, lo = int(s[2 * i], 16), int(s[2 * i + 1], 16)
        except ValueError:
            return False
        b.append(lo | (hi << 4))

    j = j2 = 0
    for i in range(8):
        j2 = sl(shl(j2, 8) | (255 & b[i]))
    for i in range(8):
        j = sl(shl(j, 8) | (b[i + 8] & 255))

    j3 = sl(j + 2611923443488327891)
    j4 = sl(2611923443488327891 ^ (j2 ^ (ushr(j3, 47) | shl(j3, 17))))
    j5 = sl(j4 + 1376283091369227076)
    j6 = sl((j ^ (ushr(j5, 47) | shl(j5, 17))) ^ 1376283091369227076)
    j7 = sl(j6 - 6626703657320631856)
    return (j6 == 6146647970834606741
            and sl((j4 ^ (ushr(j7, 47) | shl(j7, 17))) ^ (-6626703657320631856))
            == -5423340355720311942)


def main():
    key = recover_key()
    kh = key.hex()

    print("key (32 hex) :", kh)
    print("verifyFlag   :", verify_flag(kh))
    print("tampered     :", verify_flag(kh[:-1] + ("f" if kh[-1] != "f" else "0")))
    print()
    # Format is CTF{sha256}; nothing in the APK hashes anything, and the
    # scoreboard takes the digest of the raw 16 bytes, not of the hex text.
    print("flag         : CTF{" + hashlib.sha256(key).hexdigest() + "}")


if __name__ == "__main__":
    main()
