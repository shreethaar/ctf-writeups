#!/usr/bin/env python3
"""purgatory (NNS CTF 2026) -- recover the passphrase from the two BEAM modules.

old.beam and new.beam have a byte-identical Code chunk and differ only in their
literal tables. Each encodes a 25-char passphrase as affine triples
{index, a, b, c} checked as (a*ch + b) band 255 =:= c, with the trailing 12
characters XOR-masked first.

The worker is spawned before the hot upgrade, so it keeps running old code for
every *local* call (first_half/1, mask/2) while the one fully-qualified call,
purgatory:second_half/2, dispatches to the new module. The mask is computed by
old and passed in as an argument -- so the answer mixes new triples with the
old mask, and every other combination is a decoy the author planted.
"""
import struct
import sys


def chunks(path):
    d = open(path, 'rb').read()
    assert d[:4] == b'FOR1' and d[8:12] == b'BEAM', 'not a BEAM file'
    out, off = {}, 12
    while off < len(d):
        name = d[off:off + 4].decode()
        size, = struct.unpack_from('>I', d, off + 4)
        out[name] = d[off + 8:off + 8 + size]
        off += 8 + ((size + 3) // 4) * 4
    return out


def etf(b, i=0):
    """Minimal Erlang external term format decoder (the tags LitT uses)."""
    t = b[i]; i += 1
    if t == 97:                                        # SMALL_INTEGER
        return b[i], i + 1
    if t == 98:                                        # INTEGER
        return struct.unpack_from('>i', b, i)[0], i + 4
    if t == 106:                                       # NIL
        return [], i
    if t == 107:                                       # STRING (byte list)
        n, = struct.unpack_from('>H', b, i); i += 2
        return list(b[i:i + n]), i + n
    if t == 108:                                       # LIST
        n, = struct.unpack_from('>I', b, i); i += 4
        out = []
        for _ in range(n):
            v, i = etf(b, i); out.append(v)
        _, i = etf(b, i)                               # tail
        return out, i
    if t == 104:                                       # SMALL_TUPLE
        n = b[i]; i += 1
        out = []
        for _ in range(n):
            v, i = etf(b, i); out.append(v)
        return tuple(out), i
    raise ValueError(f'unhandled ETF tag {t}')


def literals(path):
    b = chunks(path)['LitT']
    # OTP 28 stores this chunk uncompressed, flagged by a zero size prefix.
    assert struct.unpack_from('>I', b, 0)[0] == 0, 'compressed LitT not handled'
    count, = struct.unpack_from('>I', b, 4)
    out, off = [], 8
    for _ in range(count):
        size, = struct.unpack_from('>I', b, off); off += 4
        term = b[off:off + size]; off += size
        assert term[0] == 131, 'missing ETF version tag'
        v, _ = etf(term, 1)
        out.append(v)
    return out


def solve(triples, mask=None, first=0):
    """Invert (a*ch + b) band 255 =:= c, undoing the XOR mask if given."""
    out = bytearray()
    for i, a, b, c in sorted(triples):
        ch = ((c - b) * pow(a, -1, 256)) % 256
        if mask is not None:
            ch ^= mask[i - first]
        out.append(ch)
    return bytes(out)


def main():
    paths = sys.argv[1:3] or ['old.beam', 'new.beam']
    lit = {tag: literals(p) for tag, p in zip(('old', 'new'), paths)}

    first = {t: solve(lit[t][0]) for t in lit}
    second = {(t, m): solve(lit[t][1], lit[m][2], first=13) for t in lit for m in lit}

    print("first_half (local call -> old code):")
    for t in lit:
        print(f"   {t}: {first[t].decode()}")
    print("\nsecond_half (remote call -> new code) x mask (local -> old code):")
    for (t, m), v in second.items():
        printable = all(32 <= c < 127 for c in v)
        print(f"   triples={t}, mask={m}: {v.decode() if printable else v.hex()}")

    print("\npassphrase:", (first['old'] + second[('new', 'old')]).decode())


if __name__ == '__main__':
    main()
