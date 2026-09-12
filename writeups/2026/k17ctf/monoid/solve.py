#!/usr/bin/env python3
r"""monoid (K17CTF rev) -> K17{a_M0NaD_1s_4_M0n0Id_1n_th3_c4t3gORy_0f_3Nd0FuNC70r5}

Main.hs (from Main.dump-simpl) is:

    (_flag : real : imag : maxIter : width : height) =
        words (decipher (fromHex "2d5509...") "#!s3kur1ty")
    writeFile "out.txt" (renderJulia real imag maxIter width height)

Decode.hs gives the cipher:
    xorChar a b   = chr (ord a `xor` ord b)
    unsubsChar a  = chr ((ord a - 67) `mod` 128)
    decipher ct k = zipWith (\c k -> unsubsChar (xorChar k c)) ct (cycle k)

The *first* word is pattern-matched away and never used -- that's the flag.
The remaining five are the Julia-set parameters, verified by re-rendering
out.txt from Fractal.hs.
"""
import os
import sys

OUT = sys.argv[1] if len(sys.argv) > 1 else "out.txt"

CT = bytes.fromhex(
    "2d55090d4f576242655d24030705490250210748502d54111f4450065f0f01070404"
    "1d5f6024485b500851457a5201384c68255b000613351141070859560b4a1c03094a"
    "0e1a505007471d0e0749080a5442074818160e48170f56")
KEY = b"#!s3kur1ty"

pt = "".join(chr(((c ^ KEY[i % len(KEY)]) - 67) % 128) for i, c in enumerate(CT))
flag, real, imag, max_iter, width, height = pt.split()
print("FLAG:", flag)
print(f"params: c = {real} + {imag}i, maxIter={max_iter}, {width}x{height}")

# --- verify: reproduce out.txt exactly (Fractal.renderJulia) ---------------
if not os.path.exists(OUT):
    print(f"(skipping render check: {OUT} not found)")
    raise SystemExit(0)

cx, cy = float(real), float(imag)
max_iter, width, height = int(max_iter), int(width), int(height)
pal = " .-:=+*#%@"
c = complex(cx, cy)
out = []
for y in range(height):
    row = ""
    for x in range(width):
        z = complex(-1.8 + 3.6 * x / (width - 1),
                    (-1.0 + 2.0 * y / (height - 1)) * 0.5)
        n = 0
        while abs(z) <= 2.0 and n < max_iter:
            z = z * z + c
            n += 1
        row += pal[min(len(pal) - 1, (n * len(pal)) // (max_iter + 1))]
    out.append(row)
rendered = "\n".join(out) + "\n"
print("out.txt reproduced exactly:", rendered == open(OUT).read())
