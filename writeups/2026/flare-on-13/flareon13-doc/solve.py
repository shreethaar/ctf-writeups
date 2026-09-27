#!/usr/bin/env python3
"""Flare-On 13 — FlareOn13.doc (polyglot) — final stage.

flareon13.doc is simultaneously: DOS COM, PDF, raw 2352-byte CD image (UDF inside),
Mach-O fat binary (Odin + Crystal slices), ZIP, and a fixed VHD. Each layer yields one
phrase; the Crystal slice (click_me, cpusubtype 3) wants all six as argv, checks
each against a set of six MD5 digests, then RC4-decrypts the flag with
key = XOR of SHA-256(phrase) over all six.
"""
import hashlib

PHRASES = [
    b"FLARE-STANDARD-ANTIVIRUS-TEST-FILE!",  # COM stub: self-patched EICAR prints this
    b"mainframe_ebcdic_ghost",               # PDF (RC4-40, empty pw): invisible text, EBCDIC cp037
    b"jbig2_fax_geometry",                   # PDF: off-page JBIG2 image
    b"udf_tagged_descriptor",                # CD->UDF: Implementation Use Vol. Descriptor LVInfo2
    b"reduce_not_deflate",                   # ZIP flag.txt: ZipCrypto (bkcrack, zero follower-set
                                             #   table as known plaintext) + PKZIP Reduce
    b"\xc3\x98d1n_373rn4l_fl4r3",            # Mach-O Odin slice: hashed/XORed status-line text
]

# Crystal slice: digests stored as 0x80|nibble at 0x100035e30, ciphertext at 0x100035ef0
DIGESTS = {
    "d82180ab7986e8c8286ef00f16c04885", "555cca3a364f57bd4e550e8758f1c08d",
    "c790cb74ddc76a4f9f83c9f79882d6fc", "cf0cbd1b55755a81ff87f2be8fba8ebf",
    "d400db493c31ebf21fa0b2a4adeae070", "9fc1de183e2761585dfce907afa249dc",
}
CT = bytes.fromhex("645128013769750e50451f917558f493e3aeed5a51d0cbfae98eed185e1b00b042a8f813a9d5551c")

assert {hashlib.md5(p).hexdigest() for p in PHRASES} == DIGESTS

key = bytearray(32)
for p in PHRASES:
    for i, b in enumerate(hashlib.sha256(p).digest()):
        key[i] ^= b

S = list(range(256)); j = 0
for i in range(256):
    j = (j + S[i] + key[i % 32]) & 0xFF
    S[i], S[j] = S[j], S[i]
i = j = 0; out = bytearray()
for c in CT:
    i = (i + 1) & 0xFF; j = (j + S[i]) & 0xFF
    S[i], S[j] = S[j], S[i]
    out.append(c ^ S[(S[i] + S[j]) & 0xFF])
print(out.decode())
