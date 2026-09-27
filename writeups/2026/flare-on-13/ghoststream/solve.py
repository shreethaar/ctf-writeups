#!/usr/bin/env python3
"""Flare-On 13 #2 GhostStream — static solve.

GhostStream.exe (parent) -> reads ADS PolyjuicePotion.txt:LordVoldemort, decodes it
in a WM_CREATE handler gated on 7 days of process uptime, sends it over
\\\\.\\pipe\\FlareChallenge to the dropped Partner_CTF.exe (child), which RC4-variant
decrypts the flag.
"""
import struct

# --- parent (GhostStream.exe) --------------------------------------------------
# Gate 1: dat_140006668 is never written; when forced to 1 the file read becomes
#         "%sPolyjuicePotion.txt:LordVoldemort" (the ADS).
# Gate 2: WM_CREATE decodes only if uptime_minutes > len("GhostStream.exe")*0x29f+0xf = 10080 (7 days).
ads = b"AlbusDumbledore \r\n"
K15 = bytes.fromhex("8b8f92858896989b948b95e6edf0e7")
PREV_MSG = 0x83                                    # WM_NCCALCSIZE precedes WM_CREATE
buf = bytearray(ads)
for i in range(len(buf)):
    buf[i] ^= 0x01 ^ PREV_MSG
for i in range(15):
    buf[i] ^= K15[i]
key = bytes(buf).split(b"\0")[0]                   # -> b"HarryPotter"

# --- child (Partner_CTF.exe, resource BIN/101) ---------------------------------
# ucrtbase!strlen is hot-patched with: s[i] = ((s[i] + i+1) & 0xff) ^ 0x13; return 0x13
def hooked_strlen_transform(s):
    return bytes(((c + i + 1) & 0xFF) ^ 0x13 for i, c in enumerate(s))

key2 = hooked_strlen_transform(b"Bxs]bv`^u)TpcnolVjN")   # -> b"Piertotum Locomotor"
# The hook's poisoned return value (0x13) must be replaced by the true
# strlen("Wingardium Leviosa") = 18 — the "debugger forces a confession" step.
L = len(b"Wingardium Leviosa")

ct = struct.pack("<QQQQIH", 0x8B397AD735875C96, 0xC85856BB286D0475,
                 0x37A956A4E1DAEE35, 0x0D340A27F9561581, 0x262C82EE, 0xF8A5)

S = list(range(256)); j = 0
for i in range(256):
    j = (j + key[i % len(key)] + S[i]) & 0xFF
    S[i], S[j] = S[j], S[i]
i = j = 0; out = bytearray()
for k, c in enumerate(ct):
    i = (i + L) & 0xFF; x = S[i]; j = (j + x) & 0xFF
    S[i], S[j] = S[j], x
    out.append(S[(S[i] + x) & 0xFF] ^ key2[k % len(key2)] ^ ((L + c) & 0xFF))

print("pipe key:", key, "| key2:", key2, "| L:", L)
print("flag:", out.decode())
