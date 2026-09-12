#!/usr/bin/env python3
"""evilgram (K17CTF rev) -> K17{y0u_Th0ug5t_...}

The "weird changing message" in the John Wick chat is a Plotly voxel
animation. The leaked encoder (posted in the LIVECon group chat) works like:

  message -> int -> 256-digit factoradic -> Lehmer decode -> ruleset,
  a permutation of 0..255 used as the transition table of a reversible
  3D block cellular automaton (Margolus neighbourhood) on a 4x4x4 grid.
  128 generations are rendered as 128 animation frames.

Each frame is a full dump of the grid, so every step exposes 8 (state ->
next state) pairs. 127 transitions * 8 = 1016 samples recover all 256
entries of the permutation; invert the Lehmer code to get the message back.

Run from the directory containing evilgram.html (unzip handout.zip first).
"""
import json
import sys

HTML = sys.argv[1] if len(sys.argv) > 1 else "evilgram/evilgram.html"

# ---- 1. pull the 128 animation frames out of Plotly.addFrames ------------
s = open(HTML, encoding="utf-8").read()
start = s.index("[", s.index("Plotly.addFrames("))
frames, _ = json.JSONDecoder().raw_decode(s[start:])
assert len(frames) == 128

# ---- 2. frames -> 4x4x4 grids -------------------------------------------
# build_voxel_mesh emits 8 vertices per live voxel, the first being (x,y,z);
# pad_vertices pads with all-zero groups, which are distinguishable from a
# genuine voxel at the origin (that one has 8 *distinct* vertices).
grids = []
for f in frames:
    d = f["data"][0]
    g = [[[0] * 4 for _ in range(4)] for _ in range(4)]
    for v in range(len(d["x"]) // 8):
        sl = slice(v * 8, v * 8 + 8)
        vx, vy, vz = d["x"][sl], d["y"][sl], d["z"][sl]
        if all(a == 0 for a in vx + vy + vz):
            continue
        g[vz[0]][vy[0]][vx[0]] = 1
    grids.append(g)

# ---- 3. recover the ruleset ---------------------------------------------
def block_state(m, x, y, z):
    return sum(m[(z + dz) % 4][(y + dy) % 4][(x + dx) % 4] << i
               for i, (dz, dy, dx) in enumerate(
                   [(0,0,0),(0,0,1),(0,1,0),(0,1,1),(1,0,0),(1,0,1),(1,1,0),(1,1,1)]))

rules = {}
for step in range(1, len(grids)):
    before, after = grids[step - 1], grids[step]
    for z in range(2):
        for y in range(2):
            for x in range(2):
                X = x * 2 + (step & 1)
                Y = y * 2 + (1 if step & 2 else 0)
                Z = z * 2 + (1 if step & 4 else 0)
                b, a = block_state(before, X, Y, Z), block_state(after, X, Y, Z)
                assert rules.get(b, a) == a, "inconsistent transition"
                rules[b] = a

assert len(rules) == 256, f"only recovered {len(rules)}/256 rules"
ruleset = [rules[i] for i in range(256)]
assert sorted(ruleset) == list(range(256))

# ---- 4. inverse factoradic ----------------------------------------------
pool, lehmer = list(range(256)), []
for v in ruleset:
    lehmer.append(pool.index(v))
    pool.remove(v)
factoradic = lehmer[::-1]          # undo encode_msg_to_ruleset's .reverse()

n = 0
for i in range(255, -1, -1):
    n = n * (i + 1) + factoradic[i]
msg = n.to_bytes((n.bit_length() + 7) // 8, "big").decode()

print(msg)
