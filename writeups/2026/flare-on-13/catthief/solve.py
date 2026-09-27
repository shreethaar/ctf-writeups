#!/usr/bin/env python3
"""Flare-On 13 — CatThief. Recover the stolen .jpg files from capture.pcapng.

catthief.exe is a Rust C2 implant. It beacons over plain HTTP POST, the server
replies with a filename to steal, and the client uploads RC4( compress(file) ).

  message layout (one contiguous MSB-first bitstream):
    11 bits : tree_len   (bytes in the code-length table; = 256)
    32 bits : data_len   (bytes in the Huffman bitstream)
    tree_len bytes : code length for each symbol 0..255 (0 = symbol absent)
    data_len bytes : canonical (DEFLATE-style) Huffman codes, MSB-first

  cipher: standard RC4, key = "i11_b3_p1und3r1n_y3r_d474"
          (16 B blob 'GhostPack...'-style ^0x33, + 8 B 0x0407576c41004a6c ^0x33, + 0x07^0x33)

The flag is written on a scroll in the 4th recovered image (myfavoritecat.jpg).
Flag: th3r3_b3_tr34sure_1n_th4t_pc4p@flare-on.com
"""
import sys, glob, os

KEY = b'i11_b3_p1und3r1n_y3r_d474'

def rc4(key, data):
    S = list(range(256)); j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 255
        S[i], S[j] = S[j], S[i]
    i = j = 0; out = bytearray()
    for c in data:
        i = (i + 1) & 255; j = (j + S[i]) & 255
        S[i], S[j] = S[j], S[i]
        out.append(c ^ S[(S[i] + S[j]) & 255])
    return bytes(out)

class BitReader:
    def __init__(self, b): self.b = b; self.p = 0
    def bits(self, n):
        v = 0
        for _ in range(n):
            v = (v << 1) | ((self.b[self.p >> 3] >> (7 - (self.p & 7))) & 1)
            self.p += 1
        return v

def decompress(msg):
    br = BitReader(msg)
    tree_len = br.bits(11)
    data_len = br.bits(32)
    L = [br.bits(8) for _ in range(tree_len)]           # code length per symbol
    syms = [s for s in range(tree_len) if L[s] > 0]
    maxlen = max(L) if syms else 0
    # canonical Huffman: codes assigned in increasing length, ascending symbol
    table = {}; code = 0
    for length in range(1, maxlen + 1):
        for s in syms:
            if L[s] == length:
                table[(length, code)] = s; code += 1
        code <<= 1
    data_end = br.p + data_len * 8
    out = bytearray(); code = 0; ln = 0
    while br.p < data_end:
        code = (code << 1) | br.bits(1); ln += 1
        if (ln, code) in table:
            out.append(table[(ln, code)]); code = 0; ln = 0
        elif ln > maxlen:
            break
    return bytes(out)

def main():
    src = sys.argv[1] if len(sys.argv) > 1 else "."
    bodies = sorted(glob.glob(os.path.join(src, "*_body.bin")))
    os.makedirs("recovered", exist_ok=True)
    for path in bodies:
        raw = open(path, "rb").read()
        dec = rc4(KEY, raw)
        out = decompress(dec)
        eoi = out.rfind(b"\xff\xd9")
        img = out[:eoi + 2] if eoi != -1 else out
        if img[:3] != b"\xff\xd8\xff":
            print(f"{os.path.basename(path)}: beacon/non-image ({len(dec)} B)")
            continue
        name = os.path.join("recovered", os.path.basename(path).split("_")[0] + ".jpg")
        open(name, "wb").write(img)
        print(f"{os.path.basename(path)} -> {name} ({len(img)} B JPEG)")
    print("\nFlag (scroll in myfavoritecat.jpg): th3r3_b3_tr34sure_1n_th4t_pc4p@flare-on.com")

if __name__ == "__main__":
    main()
