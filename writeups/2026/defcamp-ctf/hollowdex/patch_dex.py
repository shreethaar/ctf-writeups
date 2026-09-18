#!/usr/bin/env python3
"""HollowDex (DefCamp CTF 2026) — undo the runtime DEX hollowing, statically.

libhollowdex.so's JNI_OnLoad finds the mapped DEX via /proc/self/maps, XORs
Verifier.verifyFlag's insns[] with a 16-byte key from .rodata:0x700, and writes
the result back through /proc/self/mem. Everything it does at runtime is
derivable from classes.dex alone, so we patch the file instead.

Usage: ./patch_dex.py [classes.dex] [patched.dex]
"""

import hashlib
import struct
import sys
import zlib

# libhollowdex.so .rodata @ 0x700; key index is `i & 0xf` per the scalar tail.
KEY = bytes([0x59, 0x0E, 0x7A, 0x65, 0x14, 0xC3, 0xBE, 0xA1,
             0xE3, 0xC1, 0xE7, 0x81, 0xE3, 0xC1, 0xEF, 0x01])

TARGET_CLASS  = "Lcom/hollowdex/Verifier;"
TARGET_METHOD = "verifyFlag"


class Dex:
    def __init__(self, raw):
        self.d = bytearray(raw)

    def u32(self, o):
        return struct.unpack_from("<I", self.d, o)[0]

    def uleb(self, o):
        r = s = 0
        while True:
            b = self.d[o]
            o += 1
            r |= (b & 0x7F) << s
            s += 7
            if not b & 0x80:
                return r, o

    def string(self, i):
        n, o = self.uleb(self.u32(self.u32(0x3C) + 4 * i))
        return self.d[o:o + n].decode("utf-8", "replace")

    def type_str(self, i):
        return self.string(self.u32(self.u32(0x44) + 4 * i))

    def method_name(self, idx):
        # method_id_item: class_idx(2) proto_idx(2) name_idx(4)
        return self.string(self.u32(self.u32(0x5C) + 8 * idx + 4))

    def find_code_off(self, class_desc, method_name):
        """Walk class_data_item to the target method's code_off."""
        cds, cdo = self.u32(0x60), self.u32(0x64)
        cd = next((cdo + 32 * i for i in range(cds)
                   if self.type_str(self.u32(cdo + 32 * i)) == class_desc), None)
        if cd is None:
            raise SystemExit(f"class {class_desc} not found")

        o = self.u32(cd + 24)
        sf, o = self.uleb(o)
        inf, o = self.uleb(o)
        dm, o = self.uleb(o)
        vm, o = self.uleb(o)
        for _ in range(sf + inf):            # static_fields + instance_fields
            _, o = self.uleb(o)
            _, o = self.uleb(o)

        found = None
        for count in (dm, vm):               # direct_methods, then virtual_methods
            idx = 0
            for _ in range(count):
                diff, o = self.uleb(o)
                _acc, o = self.uleb(o)
                code_off, o = self.uleb(o)
                idx += diff
                name = self.method_name(idx)
                print(f"  {name:14s} code_off={code_off:#x}")
                if name == method_name:
                    found = code_off
        if found is None:
            raise SystemExit(f"method {method_name} not found")
        return found

    def reseal(self):
        """DEX header: SHA-1 over [32:], then Adler-32 (NOT CRC-32) over [12:]."""
        self.d[12:32] = hashlib.sha1(bytes(self.d[32:])).digest()
        struct.pack_into("<I", self.d, 8, zlib.adler32(bytes(self.d[12:])) & 0xFFFFFFFF)


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else "classes.dex"
    dst = sys.argv[2] if len(sys.argv) > 2 else "patched.dex"

    dex = Dex(open(src, "rb").read())
    code_off = dex.find_code_off(TARGET_CLASS, TARGET_METHOD)
    print(f"\n{TARGET_METHOD} code_item @ {code_off:#x}")

    # code_item: ... insns_size u32 @ +0xc (16-bit units), insns[] @ +0x10
    n_bytes   = dex.u32(code_off + 0xC) << 1        # exactly what the .so computes
    insns_off = code_off + 0x10
    print(f"insns {n_bytes} bytes at {insns_off:#x}")
    print("encrypted:", dex.d[insns_off:insns_off + n_bytes].hex())

    dec = bytes(dex.d[insns_off + i] ^ KEY[i & 0xF] for i in range(n_bytes))
    print("decrypted:", dec.hex())
    dex.d[insns_off:insns_off + n_bytes] = dec

    dex.reseal()
    open(dst, "wb").write(bytes(dex.d))
    print(f"\nwrote {dst}  ->  jadx -d out {dst}")


if __name__ == "__main__":
    main()
