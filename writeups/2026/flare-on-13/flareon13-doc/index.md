# FlareOn13.doc

- Category: rev

"As part of our testing protocols, we need to assess your level of stress when examining a simple document file."

`flareon13.doc` is not a document — it is a six-way **polyglot**. The same bytes parse simultaneously as a DOS COM executable, a PDF, a raw 2352-byte-per-sector CD image (with UDF inside), a Mach-O fat binary, a ZIP archive, and a fixed-size VHD. Each container hides one phrase, and a Mach-O slice buried in the file is the checker: it wants all six phrases as `argv`, validates each by MD5, and only then decrypts the flag. The "stress test" is that every layer is a different file-format rabbit hole.

### Solution

##### 1. Enumerate the containers

Carving the file apart, the interesting fat Mach-O has two arm64 slices: an **Odin** slice and a **Crystal** slice (`click_me`, `cpusubtype 3`). The Crystal slice is the real gatekeeper — it reads six command-line arguments, MD5s each, compares against a stored set of six digests (kept at `0x100035e30` as `0x80 | nibble` values), and if all six match, RC4-decrypts the ciphertext at `0x100035ef0`. The RC4 key is the XOR of `SHA-256(phrase)` across all six phrases. So the whole challenge reduces to recovering the six phrases from the other five containers plus the Odin slice.

##### 2. Phrase 1 — the COM stub (EICAR)

The file's very start is a runnable DOS COM stub: a self-patching variant of the **EICAR** antivirus test string. Executed, it prints `FLARE-STANDARD-ANTIVIRUS-TEST-FILE!` — phrase one.

##### 3. Phrases 2 & 3 — inside the PDF

The PDF layer is RC4-40 encrypted with an empty user password, so it opens without a prompt. Two things are hidden in it:

- **Invisible text** rendered in **EBCDIC cp037**, which decodes to `mainframe_ebcdic_ghost`.
- An **off-page JBIG2 image** (the fax-compression codec), giving `jbig2_fax_geometry`.

##### 4. Phrase 4 — the CD image / UDF

Treated as a raw 2352-byte/sector CD-ROM image, the file contains a **UDF** filesystem. The phrase lives in the *Implementation Use Volume Descriptor*'s `LVInfo2` field: `udf_tagged_descriptor`.

##### 5. Phrase 5 — the ZIP (Reduce, not Deflate)

The ZIP's `flag.txt` is protected with legacy **ZipCrypto** and, unusually, compressed with **PKZIP Reduce** rather than Deflate — which is itself the hint (`reduce_not_deflate`). ZipCrypto falls to a known-plaintext attack with [bkcrack]; the Reduce format's fixed *follower-set* table (all-zero here) serves as the known plaintext to recover the keys and extract the phrase `reduce_not_deflate`.

##### 6. Phrase 6 — the Odin slice

The other Mach-O slice is an **Odin**-language binary. Its status-line text is hashed/XORed before display; reversing that step yields `Ødin_373rn4l_fl4r3` (bytes `\xc3\x98d1n_373rn4l_fl4r3`).

##### 7. Derive the key and decrypt

With all six phrases in hand, confirm them against the stored MD5 set, build the RC4 key as the XOR of their SHA-256 digests, and decrypt:

```python
PHRASES = [
    b"FLARE-STANDARD-ANTIVIRUS-TEST-FILE!",
    b"mainframe_ebcdic_ghost",
    b"jbig2_fax_geometry",
    b"udf_tagged_descriptor",
    b"reduce_not_deflate",
    b"\xc3\x98d1n_373rn4l_fl4r3",
]
key = bytearray(32)
for p in PHRASES:
    for i, b in enumerate(hashlib.sha256(p).digest()):
        key[i] ^= b
# standard RC4 over the 40-byte ciphertext with `key`
```

Full script (with the MD5 check and ciphertext): [`solve.py`](solve.py).

**Flag:** `Ju$7_4_l177l3_7r34$ur3_HUN7@flare-on.com`
