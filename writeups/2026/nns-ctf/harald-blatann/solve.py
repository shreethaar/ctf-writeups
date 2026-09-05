#!/usr/bin/env python3
"""Harald Blatann (NNS CTF 2026) -- decrypt the flag out of nRF5340 firmware.

The BLE write handler for characteristic ...a031... calls

    psa_cipher_decrypt(key, PSA_ALG_CBC_NO_PADDING, 0x01028103, 0x60, out, 0x60, &n)

and memcmp's the plaintext against whatever was written over the air. The blob
at 0x01028103 is IV(16) + ciphertext(80); the AES-256 key passed to
psa_import_key sits immediately after it at 0x01028163. Both are plain flash
constants, so the flag falls out statically -- no radio and no nRF5340 needed.
"""
import sys
from Crypto.Cipher import AES

FLASH_BASE = 0x01000000
BLOB_ADDR = 0x01028103   # IV || ciphertext, 0x60 bytes
KEY_ADDR = 0x01028163    # psa_import_key data, 0x20 bytes (AES-256)


def parse_ihex(path):
    """Intel HEX -> {absolute address: byte}."""
    mem, base = {}, 0
    for line in open(path):
        line = line.strip()
        if not line.startswith(':'):
            continue
        rec = bytes.fromhex(line[1:])
        count, addr, rtype = rec[0], int.from_bytes(rec[1:3], 'big'), rec[3]
        data = rec[4:4 + count]
        if rtype == 0:
            for i, b in enumerate(data):
                mem[base + addr + i] = b
        elif rtype == 2:
            base = int.from_bytes(data, 'big') << 4
        elif rtype == 4:
            base = int.from_bytes(data, 'big') << 16
    return mem


def read(mem, addr, n):
    return bytes(mem[addr + i] for i in range(n))


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else 'harald-blatann.hex'
    mem = parse_ihex(path)

    blob = read(mem, BLOB_ADDR, 0x60)
    key = read(mem, KEY_ADDR, 0x20)
    iv, ct = blob[:16], blob[16:]

    print(f"key : {key.hex()}")
    print(f"iv  : {iv.hex()}")

    pt = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
    print(pt.split(b'\0')[0].decode())


if __name__ == '__main__':
    main()
