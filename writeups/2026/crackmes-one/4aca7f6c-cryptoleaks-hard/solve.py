#!/usr/bin/env python3
"""cryptoleaks -- HARD (AES-256).

The leak alternates on a coin flip between the state entering round 14 and the
state entering round 13.

Round 14 is the same vote as EASY and yields rk14. Round 13 looks like it needs a
2**32 per-column search through MixColumns -- but InvMixColumns is linear, so

    InvMC(s14) = ShiftRows(SubBytes(s13)) ^ InvMC(rk13)

and the round key separates back out into the identical byte-independent vote.
Recover InvMC(rk13), MixColumns it back, and rk13 || rk14 inverts to the 32-byte key.
"""
import re
import socket
from collections import Counter

PORT = 32620

SBOX = bytes.fromhex(
    '637c777bf26b6fc53001672bfed7ab76'
    'ca82c97dfa5947f0add4a2af9ca472c0'
    'b7fd9326363ff7cc34a5e5f171d83115'
    '04c723c31896059a071280e2eb27b275'
    '09832c1a1b6e5aa0523bd6b329e32f84'
    '53d100ed20fcb15b6acbbe394a4c58cf'
    'd0efaafb434d338545f9027f503c9fa8'
    '51a3408f929d38f5bcb6da2110fff3d2'
    'cd0c13ec5f974417c4a77e3d645d1973'
    '60814fdc222a908846eeb814de5e0bdb'
    'e0323a0a4906245cc2d3ac629195e479'
    'e7c8376d8dd54ea96c56f4ea657aae08'
    'ba78252e1ca6b4c6e8dd741f4bbd8b8a'
    '703eb5664803f60e613557b986c11d9e'
    'e1f8981169d98e949b1e87e9ce5528df'
    '8ca1890dbfe6426841992d0fb054bb16'
)
INV_SBOX = bytes(SBOX.index(i) for i in range(256))
SHUF = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11]          # ShiftRows: out[i] = state[SHUF[i]]
RCON = [1, 2, 4, 8, 16, 32, 64, 128, 27, 54]


def key_expand(key):
    """AES key schedule -> list of 16-byte round keys."""
    nk = len(key) // 4
    nr = {4: 10, 8: 14}[nk]
    w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    for i in range(nk, 4 * (nr + 1)):
        t = list(w[i - 1])
        if i % nk == 0:
            t = [SBOX[b] for b in t[1:] + t[:1]]
            t[0] ^= RCON[i // nk - 1]
        elif nk > 6 and i % nk == 4:
            t = [SBOX[b] for b in t]
        w.append([w[i - nk][j] ^ t[j] for j in range(4)])
    return [bytes(b for word in w[4 * r:4 * r + 4] for b in word) for r in range(nr + 1)]


def invert_schedule(last_rks, nk):
    """Run the key schedule backwards from the final nk words to the key."""
    nr = {4: 10, 8: 14}[nk]
    total = 4 * (nr + 1)
    w = {total - nk + j: list(last_rks[4 * j:4 * j + 4]) for j in range(nk)}
    for i in range(total - 1, nk - 1, -1):
        t = list(w[i - 1])
        if i % nk == 0:
            t = [SBOX[b] for b in t[1:] + t[:1]]
            t[0] ^= RCON[i // nk - 1]
        elif nk > 6 and i % nk == 4:
            t = [SBOX[b] for b in t]
        w[i - nk] = [w[i][j] ^ t[j] for j in range(4)]
    return bytes(b for i in range(nk) for b in w[i])


def collect(port, want):
    """Read hint lines "<32 hex ct> 0x<&sbox + leaked byte>" from the server."""
    s = socket.create_connection(('127.0.0.1', port))
    s.settimeout(20)
    buf, hints = b'', []
    while len(hints) < want:
        try:
            chunk = s.recv(65536)
        except socket.timeout:
            break
        if not chunk:
            break
        buf += chunk
        *lines, buf = buf.split(b'\n')
        for ln in lines:
            ct, ptr = ln.split()
            hints.append((bytes.fromhex(ct.decode()), int(ptr, 16)))
    # &sbox = base + 0x3790 with base page-aligned; the leak is <= 255 so it never
    # crosses a page, and the low 12 bits pin &sbox down from a single pointer.
    sbox_addr = (hints[0][1] & ~0xfff) | 0x790
    out = [(ct, p - sbox_addr) for ct, p in hints]
    assert all(0 <= v < 256 for _, v in out), 'sbox base misidentified'
    print(f'  {len(out)} hints, &sbox = {sbox_addr:#x}')
    return s, out


def vote(samples):
    """samples: (known 16-byte vector, leaked byte). The unknown round key is the
    per-position majority of known[i] ^ SBOX[leak]: right 1 sample in 16, noise
    otherwise."""
    tally = [Counter() for _ in range(16)]
    for known, leak in samples:
        sb = SBOX[leak]
        for i in range(16):
            tally[i][known[i] ^ sb] += 1
    return bytes(t.most_common(1)[0][0] for t in tally)


def state_last_round(ct, rk_last):
    """ct[i] = SBOX[s[SHUF[i]]] ^ rk_last[i]  ->  recover s."""
    s = bytearray(16)
    for i in range(16):
        s[SHUF[i]] = INV_SBOX[ct[i] ^ rk_last[i]]
    return bytes(s)


def submit(sock, key):
    """Send the guess and return the verdict. The server only notices our data on
    its next poll, so drain to EOF and drop the hints still in flight."""
    sock.sendall(key.hex().encode())
    sock.settimeout(5)
    data = b''
    try:
        while True:
            c = sock.recv(4096)
            if not c:
                break
            data += c
    except socket.timeout:
        pass
    sock.close()
    return re.sub(rb'(?m)^[0-9a-f]{32} 0x[0-9a-f]+\n', b'', data)


def xtime(a):
    return ((a << 1) ^ 0x1b) & 0xff if a & 0x80 else a << 1


def gmul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a, b = xtime(a), b >> 1
    return r


def _mix(st, mat):
    out = bytearray(16)
    for c in range(4):
        col = st[4 * c:4 * c + 4]
        for r in range(4):
            out[4 * c + r] = (gmul(col[0], mat[r][0]) ^ gmul(col[1], mat[r][1])
                              ^ gmul(col[2], mat[r][2]) ^ gmul(col[3], mat[r][3]))
    return bytes(out)


mix_columns = lambda s: _mix(s, [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]])
inv_mix_columns = lambda s: _mix(s, [[14, 11, 13, 9], [9, 14, 11, 13],
                                     [13, 9, 14, 11], [11, 13, 9, 14]])


def explains(key, hints):
    """Self-check: every leak must be a byte of the round-14 or round-13 input."""
    rk = key_expand(key)
    for ct, leak in hints:
        s14 = state_last_round(ct, rk[14])
        if leak in s14:
            continue
        inner = inv_mix_columns(bytes(a ^ b for a, b in zip(s14, rk[13])))
        s13 = bytes(INV_SBOX[inner[SHUF.index(i)]] for i in range(16))
        if leak not in s13:
            return False
    return True


def main():
    print('[HARD] 127.0.0.1:%d' % PORT)
    sock, hints = collect(PORT, 800)

    # Stage 1: round-14 leaks. The round-13 half is noise, so vote, then keep only
    # the samples consistent with a round-14 leak and vote again on those.
    rk14 = vote(hints)
    r14 = [h for h in hints if h[1] in state_last_round(h[0], rk14)]
    rk14 = vote(r14)
    print('  rk14 =', rk14.hex(), '(%d round-14 samples)' % len(r14))

    # Stage 2: whatever is left cannot be a round-14 leak, so it is a round-13 one.
    r13 = [(inv_mix_columns(state_last_round(ct, rk14)), leak)
           for ct, leak in hints if leak not in state_last_round(ct, rk14)]
    rk13 = mix_columns(vote(r13))
    print('  rk13 =', rk13.hex(), '(%d round-13 samples)' % len(r13))

    key = invert_schedule(rk13 + rk14, 8)
    print('  key  =', key.hex())
    assert explains(key, hints), 'recovered key does not explain the leaks'

    print('  ->', submit(sock, key))


if __name__ == '__main__':
    main()
