#!/usr/bin/env python3
"""Solver for cat-ctf 'Duo' (C++/CLI mixed-mode crackme).

Forward chain in the binary:
  input (41 chars)
    -> _cls_c._m3 : b = rol8(c ^ 0xF5, 3)
    -> _0x5d3     : AES-192-CBC encrypt, PKCS#7 pad to 48 bytes
                    key = _m_key ^ 0x22, iv = _m_iv ^ 0x22
    -> _c_bytes
    -> GetTickCount hook -> 21-byte shellcode: y = ror8(x - 0x10, 3) over 48 bytes
    -> hex(lower) == TARGET
"""
from Crypto.Cipher import AES

TARGET = bytes.fromhex(
    "a247e0a5158e91f45445b3d68d409e8ec84c0a3962e46c74afcab03475e9b24f"
    "2d8d16a900b758a035e3eac031e7b02e")

M_KEY = bytes.fromhex("0c6c11567d5011541150511 17d13517d4a1650461d1d1d1d".replace(" ", ""))
M_IV  = bytes.fromhex("5411505b7d6112124e7d13747d111611")

KEY = bytes(b ^ 0x22 for b in M_KEY)   # 24 bytes -> AES-192
IV  = bytes(b ^ 0x22 for b in M_IV)

rol8 = lambda b, n: ((b << n) | (b >> (8 - n))) & 0xFF
ror8 = lambda b, n: ((b >> n) | (b << (8 - n))) & 0xFF

print(f"AES-192 key : {KEY!r}")
print(f"AES    iv   : {IV!r}")

# 1. undo the GetTickCount-hook shellcode:  y = ror8(x - 0x10, 3)
ct = bytes((rol8(y, 3) + 0x10) & 0xFF for y in TARGET)
print(f"ciphertext  : {ct.hex()}")

# 2. undo AES-192-CBC
pt = AES.new(KEY, AES.MODE_CBC, IV).decrypt(ct)
print(f"padded pt   : {pt.hex()}  (pad byte {pt[-1]:#04x})")
assert pt[-pt[-1]:] == bytes([pt[-1]]) * pt[-1], "bad PKCS#7 padding"
pt = pt[:-pt[-1]]

# 3. undo _cls_c._m3:  out = rol8(c ^ 0xF5, 3)
flag = bytes(ror8(b, 3) ^ 0xF5 for b in pt)
print(f"\nlen         : {len(flag)}")
print(f"FLAG        : {flag.decode()}")
