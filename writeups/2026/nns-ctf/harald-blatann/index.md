# Harald Blåtann

- Category: rev
- Difficulty: none
- Author: simen

"Cables are for the previous century. We are now checking flags over the air."

The handout is a single Intel HEX file — no ELF, no PE, and nothing to run without an nRF5340 and a BLE central. Harald Blåtann is Harald Bluetooth, and Nordic Semiconductor is Norwegian: the target is Zephyr firmware for the nRF5340 network core. It comes apart entirely statically.

### Solution:

##### 1. Place the image

Parsing the HEX gives two regions and, from the extended-linear-address records, a `0x01000000` base — the nRF5340 **network core** flash window. The reset vector confirms the layout:

```
[0] 0x21005c50    initial SP  -> RAM at 0x21000000
[1] 0x01013065    reset handler (thumb) — matches the HEX start-address record
```

Cortex-M33, Thumb-2, running nRF Connect SDK 3.4 / Zephyr 4.4 per the boot banner.

##### 2. Fix the flash→RAM mapping before trusting any xref

The obvious strings resolve fine, but `NNS{th15_is_n0t_th3_fl4g}` and the three 128-bit UUIDs had **no** cross-references at all — because they live in the `.data` load image and are referenced by their post-copy RAM addresses, not their flash ones.

Scanning literal pools for an adjacent (region-2 pointer, RAM pointer) pair finds the copy:

```
0x01012be8:  rom=0x010282c0  ram=0x21000000
```

Cross-checked against the Device Information Service, whose PnP ID `user_data` is `0x210006d1` → flash `0x01028991` → `01 00 00 00 01 00 64`, a well-formed 7-byte PnP struct. With `ram = rom - 0x010282c0 + 0x21000000` the missing xrefs all appear.

##### 3. Walk the GATT table to the write handler

The custom service resolves at `0x1026ea8`:

| Attribute | UUID | Handler |
|---|---|---|
| Primary service | `0000a030-6f9b-31b1-25ec-7525454a44b5` | — |
| Flag submission | `…a031…` | **write → `0x01011b14`** |
| CCC | `0x2902` | notify subscription |
| Result | `…a032…` | notified value |

Write the candidate flag to `…a031…`, get a boolean back on `…a032…`. The decoy string is what the readable side of the service hands out.

##### 4. The checker decrypts a constant

```asm
01011b1e:  movs  r3, #0x60                 ; input_length
01011b20:  ldr   r0, [pc, #0x50]           ; &key_id  (0x210029f8)
01011b24:  str   r3, [sp, #4]              ; output_size = 0x60
01011b26:  str   r6, [sp]                  ; output = 96-byte stack buffer
01011b28:  ldr   r1, [pc, #0x4c]           ; alg = 0x04404000
01011b2e:  ldr   r2, [pc, #0x4c]           ; input = 0x01028103
01011b30:  bl    #0x101e188                ; psa_cipher_decrypt
01011b3e:  cmp   r4, #0x3c                 ; written length must exceed 60
01011b40:  bhi   #0x1011b54
01011b64:  bl    #0x10264b8                ; memcmp(plaintext, buf+offset, min(len,0x60))
```

`0x04404000` is `PSA_ALG_CBC_NO_PADDING`, so the blob at `0x01028103` is IV(16) + ciphertext(80). The `len > 0x3c` gate is a free hint that the answer is 61 characters.

The key comes from the second reference to the same key slot, at `0x01011b80`:

```asm
01011b8e:  mov.w r1, #0x300                ; usage = ENCRYPT|DECRYPT
01011b94:  movs  r2, #0x20                 ; key length -> AES-256
01011ba2:  ldr   r1, [pc, #0x18]           ; key data = 0x01028163
01011ba4:  bl    #0x101e020                ; psa_import_key
```

with attributes `0x01002400` (`PSA_KEY_TYPE_AES`) and alg `0x04404000`. The 32-byte key sits immediately after the 96-byte blob, at `0x01028163`.

##### 5. Decrypt

```
key: 2fe96d47402f3ea712adb224b1be475185e524848646c58897be4893f67abf76
iv : 43a70bc8e54e61cfff8d0a6d7d09fe20
```

```
$ ./solve.py harald-blatann.hex
NNS{w1r3lessly_s3nt_4nd_ch3ck3d_by_th3_p0w3r_0f_k1ng_bl4t4nn}
```

The plaintext is 61 bytes followed by `0x10 × 16` of padding — matching the `len > 60` gate exactly, which is a good sign nothing was misread.

Full script: [solve.py](solve.py)

**Flag:** `NNS{w1r3lessly_s3nt_4nd_ch3ck3d_by_th3_p0w3r_0f_k1ng_bl4t4nn}`

### Takeaways

- On bare-metal firmware, "no cross-references" usually means wrong address space, not dead data. Anything in `.data` is referenced by its post-copy RAM address; find the startup copy loop (a literal pool pairing a flash pointer with a RAM pointer) before concluding a string is unused.
- The load address is worth deriving rather than guessing: the HEX extended-address records plus the initial SP in the vector table pinned this to the nRF5340 network core, which is what makes every subsequent address meaningful.
- PSA algorithm IDs are readable constants and identify the primitive without any symbols — `0x04404000` is CBC-no-padding, and the `psa_import_key` length argument gives the AES variant. Grepping literal pools for `0x04…` values is a fast way into a Zephyr crypto path.
- A length gate right next to the comparison leaks the answer's size for free, and afterwards doubles as a consistency check on the recovered plaintext.
