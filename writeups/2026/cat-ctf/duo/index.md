# duo

- Category: rev

"REV challenges doesn't need a description." The handout is 37 KB of `challenge.exe` and nothing else.

The name is the hint. `file` calls it a .NET assembly, `diec` calls it an MSVC C++ binary, and both are right — it is a C++/CLI mixed-mode assembly. The flag check crosses the managed/native boundary four times, and one of its stages is not in the call graph at all: it is an inline hook on `kernel32!GetTickCount`.

### Solution:

##### 1. One file, two toolchains

```
$ file challenge.exe
PE32+ executable for MS Windows 6.00 (console), x86-64 Mono/.Net assembly, 6 sections
$ diec challenge.exe
PE64
    Compiler: Microsoft Visual C/C++(19.50.35228)[C++]
    Library: .NET Framework(CLR 4.0.30319)
```

The section table settles it, and adds a section that is not part of any normal layout:

```
.text    va=0x1000 vs=0x2326 raw=0x2400
.nep     va=0x4000 vs=0x50   raw=0x200    <- executable, 80 bytes
.rdata   va=0x5000 vs=0x62b0 raw=0x6400
.data    va=0xc000 vs=0x8dc  raw=0x200
```

Data directory 14 points at a real CLR header, and the metadata behind it is real too:

```
CLR hdr   cb=72 ver=2.5  meta rva=0x5670 size=20900  entrytok=0x600002f
meta      b'BSJB\x01\x00\x01\x00...v4.0.30319'
```

But a *pure* C# assembly has a `.text` of about eight bytes — a jump thunk into `mscoree!_CorExeMain` — and imports nothing else. This one has 8998 bytes of native code, `VCRUNTIME140.dll`, the whole `api-ms-win-crt-*` set, `VirtualAlloc`, `IsDebuggerPresent`, *and* `mscoree.dll!_CorExeMain`. The metadata string heap names the toolchain outright:

```
$ strings -a challenge.exe | grep -E 'cppcli|CppImpl|gcroot'
vc.cppcli.modopts
<CppImplementationDetails>
gcroot<System::String ^>
```

So: C++/CLI. And `.nep` — native entry point — is exactly five 16-byte thunks:

```
eb 08                 jmp  +8
0f 0b                 ud2
ff 25 f6 7f 00 00     jmp  QWORD PTR [rip+0x7ff6]
ff 25 f8 7f 00 00     jmp  QWORD PTR [rip+0x7ff8]
```

0x50 bytes for five of them, the `__unep@?_0xca1` / `__unep@?_0xdb2` stubs the CLR fills in at load. They are how the native half calls *back* into managed code, and the chain below crosses that bridge twice.

This shape breaks the usual first move. `r2` dispatches on the CLR header, sets `asm.arch` to `cil`, and gives up:

```
$ r2 -A -q -c "afl~?" challenge.exe
ERROR: asm.arch: cannot find 'cil'
0
$ kuna functions ./challenge.exe --json | jq '.count'
83
```

Neither half is optional — the managed side needs ILSpy, the native side needs a native decompiler, and the answer only falls out of both.

##### 2. The managed half, and a free symbol table

```
$ ilspycmd challenge.exe > managed.cs
```

Four classes, and the chain is legible end to end:

```csharp
public static int Main(string[] args) {
    Console.Write("Enter the flag: ");
    string text = Console.ReadLine();
    _cls_a._m0();                                   // writes %TEMP%\34412.txt
    if (!string.IsNullOrEmpty(text) && text.Length == 41) {
        IntPtr hglobal = Marshal.StringToHGlobalAnsi(text);
        <Module>._0xbd9((sbyte*)hglobal.ToPointer(), __unep@?_0xca1);
        ...
```

```csharp
public static void _m3(string flag) {               // _0xca1 lands here
    byte[] bytes = Encoding.ASCII.GetBytes(flag);
    for (int i = 0; i < bytes.LongLength; i++) {
        byte b = (byte)(bytes[i] ^ 0xF5);
        bytes[i] = (byte)((byte)(b << 3) | (b >>> 5));   // rol8(c ^ 0xF5, 3)
    }
    <Module>._0x5d3(ptr, bytes.LongLength, __unep@?_0xdb2);
}

public static void _m2() {                          // _0xdb2 lands here
    uint tickCount = <Module>.GetTickCount();
    byte[] array = new byte[48];
    Marshal.Copy(&<Module>._c_bytes, array, 0, 48);
    string text  = BitConverter.ToString(array).Replace("-", "").ToLower();
    string text2 = "a247e0a5158e91f45445b3d68d409e8ec84c0a3962e46c74afcab03475e9b24f"
                 + "2d8d16a900b758a035e3eac031e7b02e";
    Console.WriteLine(text == text2 ? "Correct!" : "nope");
}
```

41 input bytes, 48 output bytes — three blocks with seven bytes of padding.

The real gift is that in a mixed-mode assembly the *native* globals are declared as `<Module>` fields, so the metadata carries their names **and** their initializers. No RVA hunting:

| field | bytes |
|---|---|
| `_sbox_data` | `63 7C 77 7B F2 6B ... BB 16` — the standard AES S-box |
| `_rcon_data` | `00 01 02 04 08 10 20 40 80 1B 36` — standard Rcon |
| `_m_key` | 24 bytes, `0C 6C 11 56 7D 50 ...` |
| `_m_iv` | 16 bytes, `54 11 50 5B 7D 61 ...` |
| `_sc_key` | `46 35 5F 49 44 41` = `"F5_IDA"` |
| `_enc_sc` | 21 bytes |
| `_sc_data1` | 125 bytes, starting `48 8D 0D 03 00 00 00 FF E1 90` |
| `_k_enc` | `0E 00 17 0B 00 09 76 77` |

An S-box plus an Rcon is AES; a 24-byte key is AES-192. `_sc_data1` opening with `lea rcx,[rip+3]` / `jmp rcx` is shellcode.

##### 3. The native half is AES-192-CBC, keyed with a XOR-0x22 string

`_0x5d3` is `sub_140001660`, and kuna renders it cleanly:

```c
v1 = 0;
do { v6[v1] = *(unsigned char *)(v1 + 0x140005350) ^ 0x22; v1 += 1; } while (v1 < 0x18);
v9  = s_140005440._0_4_ ^ dat_140005368;     // iv, also ^ 0x22
...
v4 = 0x10 - (unsigned long long)((unsigned int)v11 & 0xf);
memcpy(v7,a0,v11);
memset(&v7[v11], v4 & 0xffffffff, v4);       // PKCS#7
sub_140001824(v6,v8);                        // key schedule -> 208 bytes
do {
  v3 = 0x10; v10 = &v7[v12]; v2 = v10;
  do { *v2 = *v2 ^ v2[v1]; ... } while (v3); // XOR the previous ciphertext
  sub_14000190c(v10,v8);                     // encrypt block
  memcpy(&v9,v10,0x10);                      // ... which becomes the next IV
  v12 += 0x10; v1 -= 0x10;
} while (v12 < v4 + v11);
memcpy(0x14000c108,v7,0x30);                 // -> _c_bytes
```

`s_140005440` is sixteen bytes of `0x22`, so key and IV are just the stored blobs XORed with `0x22`:

```
_m_key ^ 0x22 = ".N3t_r3v3rs3_1s_h4rd????"    (24 bytes -> AES-192)
_m_iv  ^ 0x22 = "v3ry_C00l_1V_343"
```

The schedule expands to `0xd0` = 208 bytes (13 round keys) and `sub_14000190c` runs `while (v8 <= 0xc)` with MixColumns gated on `if (v8 <= 0xb)` — twelve rounds, MixColumns skipped on the last. Textbook AES-192-CBC; the `((char)x >> 7) * '\xe5'` in the decompiled MixColumns is just `xtime`'s `0x1b` reduction written as a multiply.

##### 4. `_sc_data1` self-decrypts, checks for a debugger, and installs a hook

`_0xbd9` is thin — copy 0x7c bytes to an RWX page and call it with `(0, input, callback)`:

```c
v1 = (void *)VirtualAlloc(0,0x7c,0x3000,0x40);
memcpy(v1,0x1400053a0,0x7c);
(*v1)(0,a0,a1);
VirtualFree(v1,0,0x8000);
```

Linear disassembly of the blob desyncs, because most of it is ciphertext:

```asm
  0:  lea    rcx,[rip+0x3]
  7:  jmp    rcx                  ; skip the 0x90
  a:  push   rdi ... push rsi
 11:  mov    rbx,rdx              ; rbx = input
 14:  mov    rsi,r8               ; rsi = callback
 1b:  call   0x5d                 ; push 0x20 as the "return address"
 20:  xor    BYTE PTR [rdi+rcx*1],r14b     <- decrypt loop
 24:  add    r14b,BYTE PTR [rdi+rcx*1]
 28:  loop   0x20
 2a:  <51 bytes of ciphertext>
 5d:  mov    rdi,QWORD PTR [rsp]  ; 0x20
 61:  add    rdi,0x9              ; 0x29
 65:  mov    r14b,0xda
 68:  mov    ecx,0x33             ; 51 bytes
 6d:  mov    rax,QWORD PTR gs:0x60
 76:  movzx  r15d,BYTE PTR [rax+0x2]       ; PEB->BeingDebugged
 7b:  ret                                  ; -> 0x20, run the decrypt loop
```

A rolling XOR whose key is fed by its own plaintext: `p = c ^ k; k = (k + p) & 0xff`, starting at `k = 0xDA` and walking `[0x2A..0x5C]` backwards. Undo it and stage 2 appears:

```asm
 2e:  test   r15d,r15d
 31:  je     0x35
 33:  ud2                                  ; debugger -> crash
 35:  mov    rax,QWORD PTR gs:0x60
 3e:  mov    rax,QWORD PTR [rax+0x10]      ; PEB->ImageBaseAddress
 42:  add    rax,0x1114
 48:  call   rax                           ; sub_140001114
 4a:  mov    rcx,rbx                       ; input
 4d:  mov    rax,rsi
 50:  add    rsp,0x28 ... pop rdi
 5b:  jmp    rax                           ; tail-call _0xca1
```

`sub_140001114` walks the PEB loader list looking for a name stored as `_k_enc ^ 0x45` — `"KERNEL32"` — then resolves two exports by hash. The hash (`sub_1400017cc`) is CRC32C over the uppercased name, poly `0x82f63b78`, init 0, no final XOR:

```
$ python3 -c 'print(hex(crc32c("VirtualProtect")), hex(crc32c("GetTickCount")))'
0xf01db58 0xa43b0e1
```

Exactly the two constants `sub_140001114` searches for. It then `VirtualProtect`s the second one and writes twelve bytes over its prologue:

```c
v5 = 0xb848;                 // mov rax, imm64
v6 = sub_1400010a4;
v7 = 0xe0ff;                 // jmp rax
memcpy(v1,&v5,0xc);
```

From here on, every `GetTickCount()` in the process runs `sub_1400010a4`.

##### 5. The hook is a transform, not an anti-debug trick

```c
void sub_1400010a4(void) {
  v3 = 0;
  if (dat_14000c100) {
    do { ... *v1 = "F5_IDA"[v3 % 6] ^ _enc_sc[v3]; v3 += 1; } while (v3 < 0x15);
    (*dat_14000c100)(0x14000c108,0x30);          // _c_bytes, 48
  }
  GetTickCount64();                              // tail-call, so callers still work
}
```

21 bytes XORed with `"F5_IDA"` gives a fifth stage:

```asm
85 D2        test edx, edx
7E 10        jle  +0x10
8A 01        mov  al, [rcx]
2C 10        sub  al, 0x10
C0 C8 03     ror  al, 3
88 01        mov  [rcx], al
48 FF C1     inc  rcx
FF CA        dec  edx
75 F0        jnz  -0x10
C3           ret
```

That is the piece with no call edge to it. `_cls_b._m2` calls `GetTickCount()` on the line *before* it copies `_c_bytes` out, so the ciphertext gets one extra pass of `y = ror8(x - 0x10, 3)` between being written and being compared.

Exactly one pass, too. The other `GetTickCount()` in the program is in `_cls_a._m0`, which `Main` calls *before* `_0xbd9` — so it runs while the hook is still uninstalled and `_c_bytes` is still zeroed, and `_0x5d3` overwrites it afterwards anyway.

![Call graph of challenge.exe: Program.Main checks the input length and calls native _0xbd9, which runs two stages of self-decrypting shellcode; stage 2 crashes under a debugger, otherwise installs an inline hook on kernel32 GetTickCount and tail-calls back into managed code for a rol/xor transform, then native AES-192-CBC, then the managed comparison whose GetTickCount call diverts into the hook for one final byte transform before the hex compare decides between Correct and nope](callgraph.png)

`r2` finds nothing here and even the native decompiler cannot draw the numbered path: steps 2, 9 and 10 run out of `VirtualAlloc`ed pages, and step 8 is an edge that only exists after the import table has been overwritten at run time. The graph is hand-built from the analysis above.

##### 6. Run the four stages backwards

```python
TARGET = bytes.fromhex("a247...b02e")                       # 48 bytes
KEY = bytes(b ^ 0x22 for b in M_KEY)                        # b'.N3t_r3v3rs3_1s_h4rd????'
IV  = bytes(b ^ 0x22 for b in M_IV)                         # b'v3ry_C00l_1V_343'

ct = bytes((rol8(y, 3) + 0x10) & 0xFF for y in TARGET)      # undo the hook stub
pt = AES.new(KEY, AES.MODE_CBC, IV).decrypt(ct)             # undo AES-192-CBC
pt = pt[:-pt[-1]]                                           # PKCS#7, pad byte 0x07
flag = bytes(ror8(b, 3) ^ 0xF5 for b in pt)                 # undo _cls_c._m3
```

```
$ ./solve.py
AES-192 key : b'.N3t_r3v3rs3_1s_h4rd????'
AES    iv   : b'v3ry_C00l_1V_343'
padded pt   : b5a50d9d...070707070707  (pad byte 0x07)
len         : 41
FLAG        : CATF{S1ngl3_l4ngu4g3_n0t_3n0ugh_4ny_m0r3}
```

41 characters, which is the length `Main` demanded. Full script: [solve.py](solve.py)

##### 7. Confirm against the binary

Running the chain forwards reproduces the stored hex exactly, and wine's mono is happy to load a mixed-mode assembly:

```
$ echo "CATF{S1ngl3_l4ngu4g3_n0t_3n0ugh_4ny_m0r3}" | wine ./challenge.exe
Enter the flag: Correct!
Time taken to solve challenge: 0 hr 0 min 0 s
```

**Flag:** `CATF{S1ngl3_l4ngu4g3_n0t_3n0ugh_4ny_m0r3}`

### Takeaways

- A CLR header does not mean "stop, use ILSpy". C++/CLI produces one file with native code *and* metadata, and tools that branch on the header alone will hand back nothing — `r2 -A` reported zero functions here purely because it believed the `cil` arch tag. Check `.text`'s size against what a pure managed assembly would have (about eight bytes) before trusting the classification.
- In mixed mode the metadata is a free symbol table for the *native* side. `_sbox_data`, `_m_key`, `_m_iv`, `_sc_key` and their contents all came out of the `<Module>` field initializers, which is faster and less error-prone than chasing RVAs through the decompilation.
- An IAT/inline hook can be an algorithm step rather than an anti-analysis trick. The final `ror8(x - 0x10, 3)` never appears on any call path — it runs because the comparison function happens to call `GetTickCount()` first, which is also why the hook tail-calls `GetTickCount64` so nothing downstream notices.
