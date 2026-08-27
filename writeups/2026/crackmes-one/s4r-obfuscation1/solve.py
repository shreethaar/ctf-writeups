#!/usr/bin/env python3
"""
s4r's Obfuscation1 (crackmes.one) — recover the accepted argv[1].

The checker is one ~466 KB MBA-obfuscated function, but it only ever compares
transform(input[i]) against a 10-byte blob in .rodata, one character at a time,
with a `jne` that bails out on the first mismatch.

Rather than untangling the arithmetic, this:
  1. NOPs that early-exit `jne` in a *scratch copy* so the loop always runs all
     10 iterations,
  2. breakpoints the comparison under gdb and reads the transformed byte,
  3. tabulates the transform over all 95 printable characters (it is
     position-independent, so each run yields 10 entries),
  4. inverts the table against the blob.

Verify the result against the pristine, unpatched binary.
"""

import json
import re
import subprocess
import sys

LOAD_BASE = 0x8048000      # PT_LOAD maps vaddr 0x8048000 at file offset 0
JNE_ADDR  = 0x8098294      # jne 0x80a31c8 -- the per-character early exit
JNE_BYTES = bytes.fromhex("0f852eaf0000")
CMP_ADDR  = 0x8098292      # cmp ecx,edx   -- ecx = transform(input[i]), edx = blob[i]
IDX_OFF   = 0x28           # loop index lives at [ebp-0x28]

BLOB = [0xDF, 0xF0, 0xF3, 0xFF, 0xDF, 0xD3, 0xC1, 0xB6, 0xC7, 0xC0]
PASSWORD_LEN = 10          # enforced before the loop is entered


def make_patched(original, patched):
    """Copy the binary and neutralise the early-exit jne."""
    data = bytearray(open(original, "rb").read())
    off = JNE_ADDR - LOAD_BASE
    if data[off:off + len(JNE_BYTES)] != JNE_BYTES:
        sys.exit("unexpected bytes at %#x -- wrong binary?" % JNE_ADDR)
    data[off:off + len(JNE_BYTES)] = b"\x90" * len(JNE_BYTES)
    open(patched, "wb").write(data)
    import os
    os.chmod(patched, 0o755)


def gdb_quote(s):
    return "".join("\\" + c if c in '"\\' else c for c in s)


def run_batch(patched, arg):
    """Run one 10-character input, return {index: transformed_byte}."""
    script = "\n".join([
        "set confirm off",
        "set pagination off",
        "set startup-with-shell off",
        "break *%#x" % CMP_ADDR,
        "commands",
        "silent",
        'printf "IDX %%d ECX %%d\\n", *(int*)($ebp-%#x), $ecx' % IDX_OFF,
        "continue",
        "end",
        'run "%s"' % gdb_quote(arg),
        "quit",
        "",
    ])
    open("_batch.gdb", "w").write(script)
    # -nx: skip .gdbinit; pwndbg deadlocks on `commands` + `continue`.
    out = subprocess.run(["gdb", "-q", "-nx", "-batch", "-x", "_batch.gdb", patched],
                         capture_output=True, text=True, timeout=600).stdout
    return {int(i): int(v) for i, v in re.findall(r"^IDX (\d+) ECX (\d+)$", out, re.M)}


def build_table(patched):
    chars = [chr(c) for c in range(0x20, 0x7F)]      # printable ASCII
    table = {}
    for i in range(0, len(chars), PASSWORD_LEN):
        group = chars[i:i + PASSWORD_LEN]
        group += ["A"] * (PASSWORD_LEN - len(group))  # pad; length must be exactly 10
        hits = run_batch(patched, "".join(group))
        if len(hits) != PASSWORD_LEN:
            sys.exit("batch %r produced %d hits, expected %d"
                     % ("".join(group), len(hits), PASSWORD_LEN))
        for idx, val in hits.items():
            c = group[idx]
            if table.get(c, val) != val:
                sys.exit("transform is not position-independent for %r" % c)
            table[c] = val
    return table


def main():
    original = sys.argv[1] if len(sys.argv) > 1 else "./Obfuscation1"
    patched = "./_patched"

    make_patched(original, patched)
    table = build_table(patched)
    print("table size:", len(table))

    inverse = {}
    for c, v in table.items():
        inverse.setdefault(v, []).append(c)
    print("collisions:", {v: cs for v, cs in inverse.items() if len(cs) > 1})

    solution = ""
    for pos, b in enumerate(BLOB):
        cands = inverse.get(b, [])
        print("pos %d: blob=%#04x -> %s" % (pos, b, cands))
        solution += cands[0] if cands else "?"

    print("\nFLAG:", solution)
    json.dump({str(ord(k)): v for k, v in table.items()}, open("table.json", "w"))


if __name__ == "__main__":
    main()
