# GhostStream

- Category: rev

"Passing the baseline test was clearly a statistical fluke, so we've locked you in with a haunted executable and a botched vial of PolyjuicePotion.txt. It refuses to talk to the naked eye, and you aren't getting your nutrient paste until your debugger forces a confession out of it."

`GhostStream.exe` is a GUI parent that hides its payload in an NTFS alternate data stream and only decodes it after a week of uptime, then pipes it to a dropped child that does the actual flag decryption. Nothing runs usefully "as-is" — the whole challenge is spotting the three gates that keep the payload dark and stepping over them. The theme is Harry Potter spells; the flag, fittingly, is not.

### Solution

##### 1. The payload lives in an alternate data stream

The parent builds its input path with a format string, `"%sPolyjuicePotion.txt"`, but the branch that actually opens the file appends `:LordVoldemort` — an NTFS **alternate data stream** on `PolyjuicePotion.txt`. That branch is gated by `dat_140006668`, a global that is never written anywhere in the binary, so it is always `0` and the ADS is never read. Forcing it to `1` (or just reading `PolyjuicePotion.txt:LordVoldemort` directly) is gate one. The stream holds `AlbusDumbledore \r\n`.

##### 2. The WM_CREATE handler is time-locked to 7 days

Decoding happens inside the window procedure's `WM_CREATE` case, behind an uptime check:

```
uptime_minutes > len("GhostStream.exe") * 0x29f + 0xf
             = 15 * 671 + 15 = 10080 minutes = 7 days
```

So the program must believe it has been running for a week before it will touch the stream. In a debugger you patch the comparison (or fake `GetTickCount`); the point of the check is just to keep casual execution from ever reaching the decode.

##### 3. Recovering the named-pipe key

The decode XORs the ADS bytes against a value derived from the **previous window message**. `WM_CREATE` (`0x1`) is preceded by `WM_NCCALCSIZE` (`0x83`), and each byte is XORed with `0x01 ^ 0x83`, then the first 15 bytes are XORed with a hardcoded 15-byte table. `AlbusDumbledore \r\n` collapses to the string `HarryPotter`, which is the key the parent uses to talk to the child over `\\.\pipe\FlareChallenge`.

```python
ads = b"AlbusDumbledore \r\n"
K15 = bytes.fromhex("8b8f92858896989b948b95e6edf0e7")
buf = bytearray(ads)
for i in range(len(buf)):
    buf[i] ^= 0x01 ^ 0x83            # WM_CREATE ^ preceding WM_NCCALCSIZE
for i in range(15):
    buf[i] ^= K15[i]
key = bytes(buf).split(b"\0")[0]     # -> b"HarryPotter"
```

##### 4. The child hides its second key inside a hooked `strlen`

The child (`Partner_CTF.exe`, dropped from resource `BIN/101`) hot-patches `ucrtbase!strlen`. The hook rewrites its argument in place — `s[i] = ((s[i] + i + 1) & 0xff) ^ 0x13` — and then **always returns `0x13`** regardless of the real length. Running that transform on the stored blob `Bxs]bv`^u)TpcnolVjN` yields the second key, `Piertotum Locomotor`:

```python
def hooked_strlen_transform(s):
    return bytes(((c + i + 1) & 0xFF) ^ 0x13 for i, c in enumerate(s))

key2 = hooked_strlen_transform(b"Bxs]bv`^u)TpcnolVjN")   # -> b"Piertotum Locomotor"
```

The poisoned `0x13` return value is the "confession" the prompt wants: the decryption needs the *true* `strlen("Wingardium Leviosa") = 18`, which the hook has hidden. Supplying `L = 18` is what a debugger (or careful static reading) forces out.

##### 5. The RC4 variant

The final cipher is RC4 keyed with `HarryPotter`, but with three tweaks driven by the values above: the PRGA advances `i` by `L` (18) instead of `1`, and each output byte is additionally XORed with `key2` (cycled) and with `(L + ciphertext_byte) & 0xff`. Standard KSA, modified PRGA:

```python
S = list(range(256)); j = 0
for i in range(256):
    j = (j + key[i % len(key)] + S[i]) & 0xFF
    S[i], S[j] = S[j], S[i]
i = j = 0; out = bytearray()
for k, c in enumerate(ct):
    i = (i + L) & 0xFF; x = S[i]; j = (j + x) & 0xFF
    S[i], S[j] = S[j], x
    out.append(S[(S[i] + x) & 0xFF] ^ key2[k % len(key2)] ^ ((L + c) & 0xFF))
```

Full script: [`solve.py`](solve.py).

**Flag:** `y0u_kn0w_n07h1n6_j0n_5n0w@flare-on.com`
