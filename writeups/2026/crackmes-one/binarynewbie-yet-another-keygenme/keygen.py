#!/usr/bin/env python3
"""
Keygen for BinaryNewbie's "Yet Another Keygenme/Crackme".

Usage:  ./keygen.py <username>            # 10 alnum chars
        ./keygen.py <username> --len10    # generate a 10-char key (branch 2)

Writes the key to stdout; run the target as:
        ./keygenme <username> <keyfile>
where <keyfile> contains the key followed by a trailing byte (e.g. '\n').
"""
import sys, string, random, itertools

M = (1 << 64) - 1
U32 = 0xffffffff
ALNUM = string.digits + string.ascii_uppercase + string.ascii_lowercase


def check_diff_len(user: bytes, pw: bytes):
    """sub_1bb0, len(user) != len(pw).  None => the binary would SIGFPE."""
    S, P = 0, 1
    for j in range(len(pw)):
        v16 = pw[j]
        for i in range(len(user)):
            v4 = (user[i] + (pw[j] ^ i)) & 0xf
            S = (S + 2 * v4) & M
            v11 = ((i ^ j) | v16) & U32
            v16 = (v16 + 1) & U32
            P = (P * ((v4 | v11) & U32)) & M
    r = (((P - S) & M) % ((P + S) & M)) & 0xf
    return None if r == 0 else (9 % r == 0)


def check_same_len(user: bytes, pw: bytes):
    """sub_1bb0, len(user) == len(pw) == 10.  Only pw[0:9] is used."""
    if user == pw:
        return False                      # rejected: "content is equal"
    S, P = 0, 1
    for i in range(len(user)):
        u = user[i]
        t = [((pw[k] ^ u ^ k) & 0xf) for k in range(9)]
        v16 = ((u + i) ^ i) & U32
        S += sum(t)
        for x in t:
            P = (P * ((x | v16) & U32)) & M
    return S != 0 and ((P % S) * 5) & 0xf == 0


def len10_possible(user: bytes) -> bool:
    """
    The equal-length branch is unsatisfiable when every username byte is odd.

    v16_i = (u_i + i) ^ i always has the same parity as u_i, so an all-odd
    username makes every factor (t | v16) odd => P odd.  And parity(S) equals
    parity(count of odd username bytes) = parity(10) = 0 => S even.  P odd with
    S even forces P % S odd, which can never be == 0 (mod 16).
    """
    return not all(c & 1 for c in user)


def keygen(user: bytes, len10=False):
    if len10:
        if not len10_possible(user):
            return None
        rng = random.Random(0xC0FFEE)
        for _ in range(500000):
            pw = bytes(rng.choice(ALNUM).encode()[0] for _ in range(10))
            if check_same_len(user, pw):
                return pw
        return None
    # shortest-first search over the length != 10 branch
    for L in (1, 2, 3):
        for cand in itertools.product(ALNUM.encode(), repeat=L):
            pw = bytes(cand)
            if check_diff_len(user, pw) is True:
                return pw
    return None


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    user = sys.argv[1].encode()
    if len(user) != 10 or not all(chr(c).isalnum() for c in user):
        sys.exit("error: username must be exactly 10 alphanumeric characters")
    want10 = "--len10" in sys.argv
    if want10 and not len10_possible(user):
        sys.exit("error: no 10-char key exists for this username (every byte is "
                 "odd => P odd, S even => P %% S is odd, never 0 mod 16). "
                 "Use the default short-key mode instead.")
    pw = keygen(user, len10=want10)
    if pw is None:
        sys.exit("error: no key found")
    print(pw.decode())


if __name__ == "__main__":
    main()
