# Silent Stranger

- Category: rev

"Who are you with the lights out?"

`launcher.exe` is a 170 KB PE32 that wants three arguments. Each level's code is encrypted under the *previous* answer, so they only fall in order, and the flag is a final blob keyed by all three together. The third level is the interesting one: its control flow is not branches, it is structured exception handling — it faults on purpose and lets its own SEH handlers decide where execution resumes.

### Solution:

##### 1. Two sections that are empty on disk

```
$ rabin2 -S launcher.exe
nth paddr          size vaddr         vsize perm name
0   0x00000400  0x19600 0x00401000  0x1a000 -r-x .text
1   0x00019a00   0xe400 0x0041b000   0xf000 -r-- .rdata
2   0x00027e00    0xa00 0x0042a000   0x2000 -rw- .data
3   0x00028800   0x1c00 0x0042c000   0x2000 -rwx .lvl3
4   0x0002a400    0x200 0x0042e000   0x1000 -rw- .fptable
```

Two non-standard section names, and only one of them is the challenge. `.fptable` turns out to be the MSVC runtime's lazily-resolved API pointer cache — `VirtualProtect(0x42e000, 0x80, PAGE_READWRITE)`, store a `GetProcAddress` result, flip it back — so it is a red herring. `.lvl3` is the real one: RWX, zero entropy, all-zero on disk, and written at run time.

The imports say what writes it: `VirtualAlloc` + `VirtualProtect` + `FlushInstructionCache` for the code, and six `bcrypt.dll` entries (`BCryptOpenAlgorithmProvider`, `BCryptCreateHash`, `BCryptHashData`, `BCryptFinishHash`, …) — both algorithm identifiers are the wide string `"SHA256"` — for the key schedule. `IsDebuggerPresent` is imported too, but its only two call sites are the MSVC CRT's own fatal-error paths — every anti-debug check that matters here is hand-rolled out of the PEB.

`strings` finds no prompts beyond the arguments and the failure messages, which is the whole plot in four lines:

```
arg1:   %255s   arg2:   %255s   arg3:   %255s
level 1 failed
level 2 failed
level 3 failed
```

##### 2. `main` is a three-stage gate, and each stage decrypts the next

`sub_401470`, trimmed to the spine:

```c
if (a0 != 4) { /* prompt for v3, v4, v5 */ } else { v13 = argv[1]; v14 = argv[2]; v10 = argv[3]; }

v9  = sub_401340(0x41b1b0, dat_420500);            // level 1: copy -> RX
if (sub_4013c0(v9, v13) != 1) { puts("level 1 failed"); return 1; }

v11 = malloc(dat_420504);
sub_401220(v11, 0x420508, dat_420504, v13, strlen(v13));   // decrypt level 2 with arg1
v8  = sub_401340(v11, dat_420504);
if (sub_401400(v8, v14, sub_401440) != 1) { puts("level 2 failed"); return 1; }

sub_401220(0x42c000, 0x420aa8, dat_4224e0, v14, strlen(v14));  // decrypt level 3 with arg2
FlushInstructionCache(GetCurrentProcess());
if (sub_4013c0(0x42c000, v10) != 1) { puts("level 3 failed"); return 1; }

sub_4010d0(v13, v14, v10, v6);                     // v6 = SHA256(a1 | a2 | a3)
v12 = malloc(dat_4224e4 + 1);
sub_401220(v12, 0x4224e8, dat_4224e4, v6, 0x20);   // decrypt the flag with the digest
puts(v12);
```

Two helpers carry everything. `sub_401340` is the loader — `VirtualAlloc`, copy, `VirtualProtect(PAGE_EXECUTE_READ)`, `FlushInstructionCache`. `sub_401220` is the cipher, and its disassembly is unambiguous:

```asm
401266:  mov    eax,DWORD PTR [ebp-0x4]
401269:  and    eax,0x1f
40126c:  jne    0x401311                    ; refresh only every 32 bytes
401281:  call   0x402520                    ; memcpy(buf, key, keylen)
401294:  mov    BYTE PTR [ebp+edx*1-0xc],al ; counter, little-endian
4012de:  call   0x402520                    ; memcpy(buf + keylen, &counter, 4)
4012f8:  call   0x401000                    ; SHA256(buf, keylen + 4) -> digest[32]
401311:  mov    eax,DWORD PTR [ebp+0xc]
401317:  movzx  ecx,BYTE PTR [eax]
40131d:  and    edx,0x1f
401320:  movzx  eax,BYTE PTR [ebp+edx*1-0x2c]
401325:  xor    ecx,eax
40132d:  mov    BYTE PTR [edx],cl
```

```python
def keystream_xor(src, key):                 # sub_401220
    out, ctr, dig = bytearray(), 0, b''
    for i, b in enumerate(src):
        if i % 32 == 0:
            dig = hashlib.sha256(key + struct.pack('<I', ctr)).digest(); ctr += 1
        out.append(b ^ dig[i % 32])
    return bytes(out)
```

`sub_4010d0` is the same SHA-256 with `0x7c` (`|`) hashed between the three arguments. Reading the four size dwords out of `.rdata` gives the whole layout:

| blob | va | length | key |
|---|---|---|---|
| level 1 | `0x41b1b0` | 21327 | *none — plaintext* |
| level 2 | `0x420508` | 1437 | arg1 |
| level 3 | `0x420aa8` | 6712 | arg2 |
| flag | `0x4224e8` | 79 | `SHA256(arg1 \| arg2 \| arg3)` |

![Call graph of launcher.exe: main loads the plaintext level 1 through a VirtualAlloc and VirtualProtect loader, level 1 gates on a 31-byte arg1, its success unlocks a SHA-256 counter-mode decryption of level 2 under arg1, level 2 gates on a 24-byte arg2 and unlocks level 3 under arg2, level 3 gates on a 33-byte arg3 via SEH-dispatched per-byte checks and also contains a decoy path, and only the real path reaches the SHA-256 of all three arguments that decrypts the flag blob](callgraph.png)

Only level 1 is visible to any static tool — levels 2 and 3 have no code cross-references at all until they are decrypted, which is also why the tool counts look fine and mean nothing (`r2 -A`: 685 functions, `kuna`: 792; the 6712-byte level 3 is in neither number).

##### 3. Level 1: 248 bit checks, each poisoned twice

```asm
   d:  push  ebp ...
  11:  cmp   DWORD PTR [esp+0x18],0x1f       ; len(arg1) == 31
  2a:  mov   eax,fs:0x30
  30:  movzx ebp,BYTE PTR [eax+0x2]          ; ebp = PEB->BeingDebugged
  37:  call  0x27b5                          ; the expected bit
  3c:  xor   eax,ebp
  3e:  and   eax,0x1
  41:  movzx edx,BYTE PTR [edi]              ; input[0]
  44:  and   edx,0x1                         ; bit 0
  47:  xor   eax,edx
  49:  xor   eax,0x1
  4c:  add   ebx,eax                         ; +1 if the bit matched
...
27a2:  cmp   ebx,0xf8                        ; 31 * 8 -> every bit
27a8:  sete  al
```

248 copies of that block, one per bit, separated by twelve `nop`s. The generators are all the same shape:

```asm
27c2:  mov   edx,DWORD PTR [esp]             ; own return address
27c5:  xor   ecx,ecx
27c7:  cmp   BYTE PTR [edx],0xcc             ; software breakpoint at the call site?
27ca:  sete  cl
27cd:  mov   eax,0xe21fcd24
27d2:  xor   eax,0x6b3d96e3
27d7:  shr   eax,0xa
27da:  and   eax,0x1
27dd:  xor   eax,ecx                         ; flip the answer if patched
27e2:  ret
```

So the expected bit is poisoned by `PEB->BeingDebugged` in the caller *and* by an `int3` check on its own return address. Both are free to satisfy — emulate instead of debugging. With `fs:` served by a real GDT entry, the blob runs as-is, and `EAX` at each `movzx edx, byte [edi+k]` **is** the expected bit:

```python
sites[addr] = (k, j)          # from capstone: movzx edx,[edi+k] then optional shr edx,j
...
uc, eax = emu.call(code, 0, [INPUT, 31], hook=record_eax_at_sites)
for (k, j), b in bits.items(): out[k] |= b << j
```

```
check sites found: 248
arg1 = b'V01c3S_F1ll_My_H34d_W1th_No1ses'
verify lvl1(arg1) = 1
```

##### 4. Level 2: 24 arithmetic constraints, handed to z3

Decrypting with `arg1` gives 1437 bytes that open with a length gate of `0x18` and a callback pointer:

```asm
   c:  cmp   DWORD PTR [ebp+0xc],0x18        ; len(arg2) == 24
  16:  cmp   DWORD PTR [ebp+0x10],0x0        ; callback must be non-null
  42:  movzx eax,BYTE PTR [esi+0x16]
  46:  imul  eax,eax,0x3
  49:  add   eax,0xb
  4c:  cmp   eax,0x158
  51:  setne dl
  57:  or    edi,edx                         ; failures accumulate into edi
...
 585:  xor   eax,eax
 587:  test  edi,edi
 589:  sete  al                              ; return edi == 0
```

24 of those, mixing `imul`/`add`/`sub`/`xor`/`shl` over two or three input bytes, interleaved with junk `jg`/`je`/`jl` triples that all converge and `jecxz`/`loop` guards over `ud2`. Three things perturb the arithmetic, all through one register:

```asm
 16d:  mov   eax,fs:0x30
 173:  mov   eax,DWORD PTR [eax+0x18]        ; PEB->ProcessHeap
 176:  mov   ecx,DWORD PTR [eax+0x40]        ; Flags
 179:  and   ecx,0xfffffffd
 17c:  mov   edx,DWORD PTR [eax+0x44]        ; ForceFlags
 188:  imul  eax,eax,0x31
 18b:  add   ebx,eax                         ; ebx = poison
```

plus two probes through the host callback — `sub_401440`, which answers `*out = (len == 0x1f)` — asked once with `0x1f` and once with `0x1e`, so the honest answers are 1 and 0 and both contribute zero. On a clean run `ebx` is 0 throughout, which makes every constraint a plain equation. Walk the instruction stream, fix `ebx = 0`, skip anything writing to it, and emit the comparisons to z3:

```
constraints: 24   unhandled mnemonics: []
arg2 = b'Dr41n_M3_oFf_Th1S_PO1son'
unique in printable ASCII: True
```

Then re-run the *untouched* blob in Unicorn with a faithful callback, rather than trusting the model:

```
lvl2(arg2)      = 1
lvl2("A"*24)    = 0
```

##### 5. Level 3: the dispatcher is SEH

Level 3 is decrypted into `.lvl3` at its own section VA, so unlike the first two it is position-dependent and has to be emulated in the real image layout. The prologue is ordinary enough — `cmp [ebp+0xc],0x21`, so `len(arg3) == 33`, and a `call`/`pop`/`sub` delta pins `esi = 0x42c000` — and then it stops looking like code:

```asm
156d:  mov   eax,DWORD PTR fs:[0]
1573:  mov   DWORD PTR [ebx+0x8],eax         ; save the old chain head
 d20:  push  ebx
 d21:  lea   ecx,[esi+0x16aa]                ; handler 1
 d27:  push  ecx
1592:  push  eax
124a:  lea   ecx,[esi+0x414]                 ; handler 2
1911:  lea   ecx,[esi+0x1934]                ; handler 3
1346:  xor   eax,eax
1348:  mov   DWORD PTR fs:[eax],edx          ; install the chain
 dab:  mov   eax,0x7bd889d5
 db0:  xor   edx,edx
 db2:  mov   ecx,DWORD PTR [edx+0x1]         ; fault on purpose
```

Three handlers, then a deliberate access violation. The handlers dispatch on the exception code, and their tail is the giveaway:

```asm
1763:  inc   DWORD PTR [edx+0x10]
1766:  mov   ecx,DWORD PTR [esp+0x4]         ; CONTEXT *
176a:  mov   edi,DWORD PTR [ecx+0xc0]        ; CONTEXT.EFlags
1770:  and   edi,0x100                       ; trap flag -> single-stepping?
1779:  mov   edi,DWORD PTR [ecx+0x4]         ; Dr0
177c:  or    edi,DWORD PTR [ecx+0x8]         ; Dr1
177f:  or    edi,DWORD PTR [ecx+0xc]         ; Dr2
1782:  or    edi,DWORD PTR [ecx+0x10]        ; Dr3   -> hardware breakpoints?
1788:  mov   ecx,DWORD PTR fs:0x30
178f:  movzx edi,BYTE PTR [ecx+0x2]          ; BeingDebugged
1793:  mov   ecx,DWORD PTR [ecx+0x68]
1796:  and   ecx,0x70                        ; NtGlobalFlag heap bits
179e:  mov   ecx,DWORD PTR [edx+0x14]        ; accumulated detections
17a1:  neg   ecx
17a3:  sbb   ecx,ecx                         ; 0 if clean, else 0xFFFFFFFF
17a5:  mov   edi,DWORD PTR [edx+0x4]
17a8:  add   edi,0x1945                      ; the decoy continuation
17ae:  xor   edi,eax
17b0:  and   edi,ecx
17b2:  xor   eax,edi                         ; clean -> real target, else swap
17b8:  mov   DWORD PTR [ecx+0xb8],eax        ; CONTEXT.Eip := target
 5c1:  popa
 7bc:  xor   eax,eax                         ; ExceptionContinueExecution
```

The next instruction pointer is *computed in the handler* from five debugger tells at once, and a debugger doesn't just fail the check — it silently routes execution somewhere else. There is no branch to patch.

That means emulating the CPU is not enough; the dispatcher has to exist. About 120 lines on top of Unicorn: build a `CONTEXT` and an `EXCEPTION_RECORD` below `ESP`, walk `fs:[0]`, call each handler cdecl as `handler(rec, frame, ctx, disp)`, and on a `0` return reload the (handler-modified) `CONTEXT` and resume at its `Eip`.

Two Unicorn quirks cost time and are worth writing down. Its `intno` is not the architectural vector — the same `div ecx` with `ecx = 0` arrived once as 0 and once as 8 — so classify from the faulting opcode instead. And it will occasionally halt *on* a faulting instruction without firing any hook, so treat "stopped, and EIP is not the magic return address" as an exception too. With both handled:

```
lvl3("A"*33)            -> ret 0, 33 exceptions
lvl3("A"*33), debugged  -> ret 0,  1 exception
```

33 exceptions for 33 input bytes, and a single exception once `BeingDebugged` is set — the divergence is immediate.

##### 6. The decoy

One of those handler tails does something different:

```asm
d945:  mov   edi,DWORD PTR [ebx+0x4]
d948:  add   edi,0x1991
d95d:  mov   ecx,0x10
d962:  mov   al,BYTE PTR [edi]
d964:  xor   al,0xa7                         ; decrypt 16 bytes
d972:  mov   ecx,0xf                          ; compare 15
d977:  mov   dl,BYTE PTR [esi]
d979:  xor   dl,BYTE PTR [edi]
d97b:  or    al,dl
d983:  sete  al                               ; and return 1
```

```
$ python3 -c "print(bytes(b ^ 0xa7 for b in blob(0x1991, 16)))"
b'N1ce_Try_But_n0\x00'
```

An input starting `N1ce_Try_But_n0` makes level 3 return success — and then feeds a different `SHA256(arg1|arg2|arg3)`, so the last `sub_401220` decrypts 79 bytes of noise. The trap is that the gate and the flag are keyed independently: passing the check is not the same as being right.

##### 7. A per-byte oracle beats 95^33

Every check in level 3 ends the same way:

```asm
 60c:  setne al
 60f:  movzx eax,al
 6a9:  or    DWORD PTR [edx+0xc],eax          ; one hit per input byte
```

Hooking that single instruction turns the one boolean the function returns into 33 independent pass/fail bits. And the checks are position-independent — changing `input[0]` leaves the other 32 bits untouched — so a *uniform* input resolves every position that happens to equal that character, and the whole string falls out in one sweep of the printable range:

```python
for c in range(0x20, 0x7f):
    for i, bit in enumerate(flags(bytes([c]) * 33)):
        if bit == 0: sol[i] = c
```

```
sweep 0.9s
arg3 = b'I_W1ll_N3v3R_LeT_Th3m_S3e_My_F4c3'
verify ret = 1
```

##### 8. The flag

```
$ ./solve.py
arg1 (31) = V01c3S_F1ll_My_H34d_W1th_No1ses
arg2 (24) = Dr41n_M3_oFf_Th1S_PO1son
arg3 (33) = I_W1ll_N3v3R_LeT_Th3m_S3e_My_F4c3

sha256 = 2102c38296a8c261988d649e1d5f5cb3440af6b3412a46256a1f07d0fc781321
CATF{AnD_i_W1ll_d1E_4_s1l3nT_StR4Nger_e1627f4536b5bf47989810fa4afa47e02cbd3fa8}
```

Full script: [solve.py](solve.py), with the harness in [emu.py](emu.py) and the SEH dispatcher in [seh.py](seh.py). It goes from the shipped `launcher.exe` to the flag in about a second, with no patched copy anywhere.

Confirmed against the untouched binary:

```
$ wine ./launcher.exe "V01c3S_F1ll_My_H34d_W1th_No1ses" \
                      "Dr41n_M3_oFf_Th1S_PO1son" \
                      "I_W1ll_N3v3R_LeT_Th3m_S3e_My_F4c3"
CATF{AnD_i_W1ll_d1E_4_s1l3nT_StR4Nger_e1627f4536b5bf47989810fa4afa47e02cbd3fa8}
```

The three arguments read as a verse, which is the "silent stranger" of the title.

**Flag:** `CATF{AnD_i_W1ll_d1E_4_s1l3nT_StR4Nger_e1627f4536b5bf47989810fa4afa47e02cbd3fa8}`

### Takeaways

- When anti-debug is a *computed jump target* rather than a check, patching is the wrong tool. Here five tells — `BeingDebugged`, `NtGlobalFlag`, heap `Flags`/`ForceFlags`, `EFlags.TF` and `Dr0-Dr3` — are OR'd into one word that `neg`/`sbb` turns into an all-ones mask over the next `CONTEXT.Eip`. There is no branch to `nop`, and a debugger produces a wrong answer rather than an obvious failure. Emulating with a clean synthetic TEB/PEB sidesteps the whole class.
- SEH is a legitimate dispatcher and emulators don't implement it. A `CONTEXT` + `EXCEPTION_RECORD` + `fs:[0]` walk is roughly 120 lines on top of Unicorn and turns an unreadable blob into something you can run 3000 times a second — far cheaper than statically untangling six exception-mediated jumps.
- Find the accumulator, not the verdict. Each level ORs its per-item failures into one word before the final `test`; hooking that one instruction converts a single boolean into a per-byte oracle, which is the difference between a 95^33 search and 95 emulations.
- A check that passes is not an answer that is right. Level 3's decoy returns success for `N1ce_Try_But_n0…` but the flag is keyed by a hash of all three arguments, so the gate and the payload can disagree. Always derive the flag from the real key material rather than stopping at "the binary said Correct".
