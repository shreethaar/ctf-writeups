#!/usr/bin/env python3
"""cryptoleaks -- EASY (AES-128).

Every hint leaks one byte, at a random position, of the state entering the final
round. Since ct[i] = SBOX[s[SHUF[i]]] ^ rk10[i], each hint votes for the correct
rk10[i] at exactly one position i and for noise at the other 15. A majority vote
over a few hundred hints recovers rk10; inverting the key schedule gives the key.
"""
import re
import socket
from collections import Counter

PORT = 19146

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


def explains(key, hints):
    """Self-check: a correct key must account for every leaked byte."""
    rk = key_expand(key)
    return all(leak in state_last_round(ct, rk[-1]) for ct, leak in hints)


def main():
    print('[EASY] 127.0.0.1:%d' % PORT)
    sock, hints = collect(PORT, 400)

    rk10 = vote(hints)
    print('  rk10 =', rk10.hex())

    key = invert_schedule(rk10, 4)
    print('  key  =', key.hex())
    assert explains(key, hints), 'recovered key does not explain the leaks'

    print('  ->', submit(sock, key))


if __name__ == '__main__':
    main()
