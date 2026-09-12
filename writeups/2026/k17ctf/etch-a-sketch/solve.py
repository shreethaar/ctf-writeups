#!/usr/bin/env python3
"""etch-a-sketch (K17CTF rev) -> K17{my_masterpiece}

The binary is a tiny ASCII pen-plotter:
  points[]  : 1216 packed int32, low16 = x, high16 = y. (-1,-1) = pen up,
              (-2,*) = end-of-drawing sentinel.
  line()    : Bresenham between consecutive points
  dab()     : stamps a (2*brush_r+1)^2 square into a 120x82 canvas
  brush_r   : 10  <-- the whole picture is one giant blob at this radius

main() walks points[0..324] (stopping at the sentinel at index 324), so only
the first drawing is used. Re-render it with radius 0 and the flag appears as
three rows of hand-drawn glyphs.
"""
import struct
import sys

BIN = sys.argv[1] if len(sys.argv) > 1 else "etchasketch"
POINTS_VA, POINTS_LEN = 0x2020, 0x1300   # file offset == vaddr for this PIE

d = open(BIN, "rb").read()
raw = d[POINTS_VA:POINTS_VA + POINTS_LEN]
pts = [struct.unpack_from("<hh", raw, i * 4) for i in range(POINTS_LEN // 4)]
seg = pts[:324]

strokes, cur = [], []
for p in seg:
    if p[0] < 0:
        if len(cur) > 1:
            strokes.append(cur)
        cur = []
    else:
        cur.append(p)
if len(cur) > 1:
    strokes.append(cur)

W, H = 120, 82
cv = [[" "] * W for _ in range(H)]

def line(p0, p1):
    x0, y0 = p0
    x1, y1 = p1
    dx, sx = abs(x1 - x0), (1 if x0 < x1 else -1)
    dy, sy = -abs(y1 - y0), (1 if y0 < y1 else -1)
    err = dx + dy
    while True:
        if 0 <= x0 < W and 0 <= y0 < H:
            cv[y0][x0] = "#"
        if x0 == x1 and y0 == y1:
            break
        e2 = 2 * err
        if e2 >= dy:
            err += dy
            x0 += sx
        if e2 <= dx:
            err += dx
            y0 += sy

for s in strokes:
    for a, b in zip(s, s[1:]):
        line(a, b)

for row in cv:
    print("".join(row).rstrip())
print("\nFLAG: K17{my_masterpiece}")
