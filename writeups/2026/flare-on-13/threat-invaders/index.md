# Threat Invaders

- Category: rev

"How about a nice retro space-shooter to blow off some steam. Don't ask why it is over a hundred megabytes, there are sophisticated score-keeping algorithms that need to communicate with our official record keeping servers. Its all very legit. We have provided a pcap file with some communication to the high-score server so you can see what a real gamer looks like."

`ThreatInvaders.exe` is a 116 MB .NET 10 self-contained single-file Space Invaders. The trap is that the managed game is a *decoy*: every byte of the `SpaceInvaders` DLL is benign, and the malware is compiled into the native apphost, which rewrites the JITted managed telemetry method at runtime so outgoing "feedback" smuggles encrypted exfil to the high-score server. The flag never appears in the binary or the process — it is in the pcap, encrypted by a cipher that only exists in native code. So this "rev" challenge is really: prove the disk image is a lie, find the cipher in the host, and decrypt the capture.

### Solution

##### 1. Two binaries in one, and a pcap that can't come from the decoy

Parsing the single-file bundle and decompiling the managed `ThreatInvaders.dll` (ilspy and dnSpy agree) gives a completely ordinary highscore client: plain-JSON API, no crypto. It even stores a `_machineId` (HKLM `MachineGuid`) field that is written once and **never read** — a loose thread worth remembering. The only "flag" in the managed code is an obvious decoy in the updater args (`..._flag@no-flare.com`).

But the provided `challenge.pcapng` proves the shipped program does something the decoy cannot. The telemetry POSTs carry a `feedback_b64` field (base64 of a fixed 4096-byte buffer) and a `feedback_length` that the benign `BuildDocument` could never produce:

- a POST with `feedback_length = 0` but 4096 non-zero bytes — impossible for the managed code, which sets the length to the buffer size;
- a POST with `feedback_length = 8208` = `(2 << 12) | 16`, followed by exactly 16 binary bytes.

That `(tag << 12) | len` framing is the malware's signature. The managed IL on disk (and in a full process dump) is identical and benign, so the injection is **native**.

##### 2. The malware is the apphost, and it hides behind a fake runtime string

The apphost is a `.NET 10.0.11 singlefilehost` with statically-linked `coreclr`, but a byte-diff against the stock host shows `.text` recompiled and ~93 KB larger — malware compiled *into* the runtime. It imports the hooking primitives a normal host never needs (`VirtualProtect`, `GetProcAddress`, `CreateThread`, `CreateThreadpoolTimer`): it installs a hook + timer that rewrites the JITted body of managed `TelemetryReporter.EncodeFeedbackBuffer`.

The whole malicious cluster is reachable statically from one tell. The runtime keeps a table of `TieredCompilationManager::…` diagnostic strings; wedged into the middle of it is a string that does not belong to coreclr:

```
0x140755dd0  "ReplaceHighscores"
```

Its only cross-reference is `sub_1400c6099`, and from there the cluster around `0x1400c65e0`–`0x1400c6ba0` unravels — a self-contained set of native functions with their own globals, none of which exist in the stock host.

##### 3. The framing method, and a key hidden in plain sight

`sub_1400c6ba0` is the native reimplementation of `EncodeFeedbackBuffer`. It frames every payload as `feedback_length = (tag << 12) | len`, and its first-run branch builds the 16-byte **tag 2** handshake byte-by-byte:

```
out[i] = sessionId[15 - i]  XOR  machineId[i]
```

where `machineId` is the 16 raw bytes at `0x1407ffa30` — the very `_machineId` (HKLM `MachineGuid`) the decoy stored and "never read". The native code reads it. That makes the handshake a gift: the pcap gives both `out` and the session GUID, so the author's machine GUID falls straight out.

```
tag2       = 54ae032ea875b0f8cc578a511fe71631
sessionId  = 478b635d-c335-4c12-b1de-16e0565be335
machineId  = tag2[i] ^ sessionId[15-i]
           = 614d587848636e4980454964586c756c
           = GUID 78584d61-6348-496e-8045-4964586c756c
```

Read as ASCII, those GUID digits spell a `…MacHInEId…` easter egg — the author confirming the scheme. This 16-byte machineId is the cipher key.

The rest of the cluster is a small pipeline. During gameplay a harvester (`sub_1400c6a70`) serializes stolen data into a work buffer, encrypts it, and marks a **tag 4** payload pending; the framer ships it. A separate hash-gated routine (`sub_1400c66f0`) encrypts special "reward" leaderboard comments with the *same* cipher.

![Curated call graph of the native exfil cluster: the JIT-rewritten managed EncodeFeedbackBuffer calls the emitter/framer sub_1400c6ba0; the harvester sub_1400c6a70 builds a payload via sub_1400c65c0 and encrypts it with the stream cipher sub_1400c65e0 before the framer POSTs it as a tag4 feedback_b64 blob; the reward-comment encoder shares the same cipher, and the LCG state is seeded from the machineId key](callgraph.png)

##### 4. The cipher: an LCG keystream seeded from the machineId

The encryptor `sub_1400c65e0` XORs the buffer with a keystream from a truncated linear-congruential generator. On the first call it derives a 64-bit seed from the 16-byte machineId — a `boost::hash_combine` of the two halves, followed by a MurmurHash3-style finalizer (the standard multipliers, but with shifts 33/29/32):

```asm
; x = ((a>>2) + 0x9e3779b97f4a7c15 + (a<<6) + b) ^ a      ; hash_combine(a=key[0:8], b=key[8:16])
mov  rax, rdx
shr  rax, 0x21            ; x >> 33
xor  rax, rdx
imul rax, 0xff51afd7ed558ccd
shr  rcx, 0x1d            ; >> 29
...
imul rcx, 0xc4ceb9fe1a85ec53
shr  rax, 0x20            ; >> 32
mov  [0x1407ffa20], rax   ; seed -> LCG state
```

Then each output byte advances the LCG and takes the top byte:

```asm
imul rax, 0x5851f42d4c957f2d   ; state *= MULT   (Knuth/PCG MMIX multiplier)
lea  rdx, [rax + r9]           ; state += 0x14057b7ef767814f
mov  [0x1407ffa20], rdx        ; store state
shr  rdx, 0x38                 ; keystream byte = state >> 56
xor  [rbx + rcx], dl           ; buf[i] ^= ks[i]
```

For our recovered machineId the seed is `0xc4bfc80d59d86b9b`.

##### 5. One continuous keystream, and the flag

The subtlety that defeats a naive attack: the LCG state at `0x1407ffa20` is seeded **once** and never reset, so every encrypt call in a session draws from a single continuous keystream. Decrypting each tag 4 blob from keystream offset 0 gives garbage; the blobs sit further along the stream, after earlier encryptions consumed keystream.

Sliding the keystream against the two tag 4 payloads pins the offsets exactly — and the gaps between them account for themselves:

```
offset   0 .. 18    BANANA reward comment   (18 bytes)
offset  18 .. 548   tag4 #1  (530 bytes)
offset 548 .. 576   BENIGN reward comment   (28 bytes)
offset 576 .. 622   tag4 #2  (46 bytes)
```

The 18- and 28-byte gaps are precisely the two reward comments encrypted during play — the model is self-consistent. Decrypting confirms it: tag 4 #1 is an exfiltrated directory listing, which conveniently names a 46-byte `flag.txt`; tag 4 #2 is those 46 bytes.

```
 Directory of Z:\...\SpaceInvaders\bin\Release\net10.0-windows\publish\win-x64
...
30/08/2026  23:23                46 flag.txt
...
```

Full pipeline (pcap → reassemble → deframe → LCG decrypt): [`solve.py`](solve.py).

**Flag:** `wh4t_4_l0ng_str4ng3_tr1p_1ts_b33n@flare-on.com`
