---
title: "Ninth Circle"
layout: default
---

# Ninth Circle

Goal: derive a valid serial for any operator ID. Operator IDs are 4-24 characters of `A-Z`, `0-9`, `_`, `-`; serials are `XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX`. A correct serial prints `ACCESS GRANTED :: VM KEY ACCEPTED`.

- Category: rev
- Difficulty: 5.0
- Challenge author: WhistleDev
- Challenge link: [crackmes.one](https://crackmes.one/crackme/6a82185591dca16886160d46)
- Platform: Windows x86-64 (PE32+ console), Go — solved from Linux under wine

The description lists a custom VM with per-build randomised opcodes, encrypted bytecode and immediates, stripped and obfuscated Go build metadata via [garble](https://github.com/burrowers/garble), an anti-debug layer, and an "anti-trivial-patching" success path. It also states the rule that matters: patching the final branch is not a solution, so the algorithm has to come out whole.

Two of those protections turn out to be load-bearing and the rest are noise. The anti-debug is not a check that fails — it silently *selects a different decryption key*, so a debugged run decrypts the VM program to garbage instead of refusing to start. And the "stripped" Go metadata is not stripped at all: garble scrambles the pclntab **magic** while leaving the table itself intact, so all 3,940 function names are still sitting in the file waiting for a parser that does not bail on a bad magic. Recovering those names is what turns a 3.6 MB Go binary into a twenty-minute problem.

### Solution:

##### 1. A Go binary that claims to have no symbols

```bash
$ file NinthCircle.exe
NinthCircle.exe: PE32+ executable for MS Windows 6.01 (console), x86-64, 8 sections
$ diec NinthCircle.exe
PE64
    Compiler: Go(1.18.X-1.24.0)
```

Sections are ordinary (`.text` 2 MB, no packer), and the import table is stock Go runtime — `VirtualAlloc`, `WriteConsoleW`, `GetStdHandle`. Nothing to unpack.

`kuna functions` returns 3,787 functions and every single one is `sub_<addr>`. The Go build info confirms the metadata has been worked over:

```
b'\xff Go buildinf:\x08\x02...\x07unknown'
```

Version `unknown`. And scanning for a pclntab header — magic, `00 00`, `minLC`, `ptrSize` — finds nothing anywhere in the file.

That last result is the suspicious one. Go needs the pclntab at runtime for GC and stack unwinding; it cannot simply be absent. So the table exists and the *magic* is what's wrong.

##### 2. Finding the moduledata the hard way

`runtime.firstmoduledata` contains `text` and `etext` as raw pointers, so instead of looking for the header, look for pointers to the start of `.text`:

```python
ptrs to 0x140001000: ['0x244770', '0x355ce0', '0x355cf0']
```

The two adjacent hits at `.data` offsets `0x355ce0`/`0x355cf0` are `minpc` and `text`. Walking backwards from there gives the whole structure — six slices, then `findfunctab`, then the four pc bounds:

```
pcHeader     0x140251a68
funcnametab  ptr=0x140251ab0 len=0x5270
cutab        ptr=0x140256d20 len=0x1c2
filetab      ptr=0x140257428 len=0xf50
pctab        ptr=0x140258378 len=0x6e730
pclntable    ptr=0x1402c6aa8 len=0x5cc50
ftab         ptr=0x1402c6aa8 len=0xf65
minpc 0x140001000  maxpc 0x1401f8541
text  0x140001000  etext 0x1401f8550
```

And there is the trick, in the first sixteen bytes of the pcHeader:

```
ad74f29c 0000 01 08   640f000000000000
^^^^^^^^                ^^^^ nfunc = 0xf64 = 3940
```

Expected magic is `f1ffffff`. Everything after it — the `00 00` padding, `minLC = 1`, `ptrSize = 8`, the function count — is untouched. Garble randomises those four bytes precisely so that every tool which validates the magic first concludes there is no symbol table. Parsing `ftab` and `funcnametab` directly, ignoring the magic, recovers all 3,940 names.

##### 3. Names narrow it to 45 functions

Garble renames packages to random identifiers, but the *shape* survives, and `main.main` is not the only landmark:

```
0x1400b0a60 boonp3vl.(*JanhwymI5iEc).ReadSlice       <- bufio
0x1400acac0 bEUdIe9J.(*YShZ0YOtJ).Grow               <- strings
0x1401e2c20 oDTOecug.(*ht9j65oVoh).SkipSpace         <- fmt
0x1401f3ba0 cSlwWI.(*Dxa935Q5).Run                   <- the VM
0x1401f8080 main.(*g7LfopTO).Replace
```

Method names on exported interfaces cannot be renamed away, so `Run` announces the interpreter outright. `main.*` lands at the very end of `.text`, and everything user-written lives in the tail past `0x1401f2000` — 45 functions instead of 3,787.

Building a call graph over that tail (any function with no direct callers is a candidate for the runtime-invoked `main.main`) gives the whole program:

```
main.main                 0x1401f6540  (4320 bytes, called indirectly by runtime.main)
 ├─ wWl8Nx_ve0EB.UHbsuWJekz7T  0x1401f51e0   operator ID validation
 ├─ wWl8Nx_ve0EB.E_Q2dRX       0x1401f52c0   serial parsing (4 x uint32 from hex)
 └─ wWl8Nx_ve0EB.UoaZICEzzce   0x1401f5a60   the check
     └─ sub_1401f5780
         ├─ H_r5Q3.BjH6qXBa       0x1401f2c40   anti-debug  -> bool
         ├─ cSlwWI.MzNqIPvkHr     0x1401f4ce0   bytecode decryptor
         └─ cSlwWI.(*Dxa935Q5).Run 0x1401f3ba0  the VM
```

##### 4. The anti-debug does not gate — it poisons the key

`sub_1401f5780` calls the anti-debug first and passes its **boolean result into the decryptor** as an argument:

```asm
1401f57ce:  call  0x1401f2c40     ; H_r5Q3.BjH6qXBa -> al
1401f57d3:  call  0x1401f4ce0     ; MzNqIPvkHr(al)
```

`BjH6qXBa` itself is unremarkable — three `LazyProc.Call` invocations into kernel32 (`IsDebuggerPresent`-family), returning a bool. What matters is what the decryptor does with it:

```asm
1401f4cf6:  mov   edx, [rip+...]      ; 0x140357d14
1401f4cfc:  rol   edx, 7
1401f4cff:  xor   edx, [rip+...]      ; 0x140357d10
1401f4d05:  mov   esi, [rip+...]      ; 0x140357d18
1401f4d0b:  rol   esi, 0xd
1401f4d0e:  xor   edx, esi
1401f4d10:  mov   esi, [rip+...]      ; 0x140357d1c
1401f4d16:  rol   esi, 0x15
1401f4d19:  xor   esi, edx
1401f4d1b:  mov   [rsp+0x18], esi     ; key0  (clean)
1401f4d1f:  xor   esi, 0xcce9e69
1401f4d25:  mov   [rsp+0x1c], esi     ; key1  (debugger seen)
...
1401f4d58:  test  dil, dil
1401f4d64:  cmovne edi, r8d           ; <- picks key1 if debugged
```

The key is folded from four dwords sitting in `.data` at `0x140357d10`:

```
4308b333  fc1a9157  b7a8e3f9  c7586acc
key0 = rol(k1,7) ^ k0 ^ rol(k2,13) ^ rol(k3,21)  =  0x0BA7C535
key1 = key0 ^ 0x0CCE9E69                         =  0x07695B5C
```

There is no branch to failure. Under a debugger the program decrypts the VM bytecode with `key1`, gets noise, executes noise, and reports `ACCESS DENIED` — indistinguishable from simply having the wrong serial. This is also the "anti-trivial-patching" claim: patching the anti-debug to return false is harmless, but patching the *verdict* branch is pointless because the derived serial is what you actually need.

The decryptor proper is a byte-wise keystream with feedback:

```c
state = key ^ 0xC3D2E1F0;
for (i = 0; i < len; i++) {
    shift    = (i & 3) * 8;
    plain[i] = (state >> shift) ^ src[i] ^ (i * 0x1D + 0x47);
    state    = rol32(i * 0x9E3779B9 + plain[i] + state, 5) ^ 0xA5C31F27;
}
```

##### 5. Getting the ciphertext out without a debugger

The encrypted blob's address is a runtime global (`0x140372D90`, with length `0x1D5` = 469 at `0x140372D98`) written by a garble literal-decrypt loop during package init, so it is not simply a `.rdata` offset to read off disk.

Attaching a debugger is available in principle — the anti-debug reads the Windows PEB, which Linux `gdb` never touches — but `ptrace_scope` was set to 1:

```bash
$ cat /proc/sys/kernel/yama/ptrace_scope
1
```

which blocks attaching to an already-running process, and launching wine *under* gdb is awkward because wine forks and re-execs before the PE is mapped.

The cheap way around both problems: Yama scope 1 still permits a process to read its own **descendants**. Spawning the program from a Python parent, driving it to the `serial>` prompt (so package init has definitely run), and reading `/proc/<pid>/mem` needs no ptrace at all:

```python
p = subprocess.Popen(["wine","work.exe"], stdin=PIPE, stdout=PIPE)
wait_for(b"operator>"); p.stdin.write(b"TESTOP\n")
wait_for(b"serial>")
pid = int(subprocess.run(["pgrep","-x","work.exe"],...).stdout.split()[0])
def rd(a,n):
    with open(f"/proc/{pid}/mem","rb",0) as f: f.seek(a); return f.read(n)
ptr = struct.unpack("<Q", rd(0x140372D90, 8))[0]
blob = rd(ptr, 469)
```

wine maps the PE at its preferred base `0x140000000`, so every static address is usable as-is. Decrypting the 469 bytes with `key0` gives something obviously structured — and with `key1`, uniform noise, which confirms the key selection was read correctly:

```
key0: 3200bbfdeddd 3201292cb830 320247ed7007 3203085a05f5 3204ccec15e8 ...
key1: 5bfe1b09ef7d8ed3274da4711bbc5cec101fdd104abbd91091046c50ee86546a...
```

`32 00 <imm32>`, `32 01 <imm32>`, `32 02 ...` — five consecutive load-immediates into registers 0 through 4.

##### 6. The VM state, from Run's prologue

```asm
1401f3bc5:  movups [rax], xmm15          ; zero 0x00..0x2f
1401f3bc9:  movups [rax+0x10], xmm15
1401f3bce:  movups [rax+0x20], xmm15
1401f3bd3:  mov    [rax+0x38], r8
1401f3bd7:  mov    [rax+0x40], r9
1401f3c08:  mov    [rax+0x30], rsi
1401f3c0c:  mov    qword ptr [rax+0x48], 0
1401f3c20:  cmp    rsi, 0x4e20            ; 20000-step budget
```

48 bytes of zeroed state plus a `cmp r9, 0xc` bound on every register operand gives **12 x uint32 registers**, and the rest of the struct follows:

| offset | role |
|--------|------|
| `+0x00` | 12 x uint32 registers |
| `+0x30` | input data pointer (the operator ID bytes) |
| `+0x38` | input length |
| `+0x40` | input capacity |
| `+0x48` | PC |

`Run(vm*, code, codelen, codecap, data, datalen, datacap)` — the code is the decrypted blob, the data is the operator ID.

##### 7. Immediates are encrypted per position

Every `imm32` goes through the helper at `0x1401f3b20` rather than being read directly:

```asm
1401f3b3f:  imul  r8d, edx, 0x9e3779b9   ; edx = pc
1401f3b49:  movabs rax, 0x8d3dcb08d3dcb08e
1401f3b56:  mul   rdx                     ; -> pc / 29
1401f3b5d:  imul  rdx, rdx, 0x1d
1401f3b64:  sub   rbx, rdx                ; rbx = pc % 29
1401f3b6b:  lea   eax, [r8 - 0x69cfb59a]
1401f3b78:  rol   eax, cl                 ; cl = (pc % 29) + 1
1401f3b7a:  xor   eax, [rbx + r9]         ; ^ le32(code[pc])
1401f3b81:  xor   eax, 0x6d2b79f5
```

So an immediate at bytecode offset `p` decodes as:

```python
imm32 = rol32(p * 0x9E3779B9 - 0x69CFB59A, (p % 29) + 1) ^ le32(code[p:p+4]) ^ 0x6D2B79F5
```

Position-dependent, so the same constant appearing twice in the program looks different both times.

##### 8. The ISA

Dispatch is a binary search on the opcode byte (`cmp r9b, 0x56 / ja`, `cmp r9b, 0x2e / ja`, ...), not a jump table, which makes the eighteen handlers easy to enumerate by walking the comparison chain. Randomising opcode values per build costs nothing to defeat once the handlers are read:

| opcode | mnemonic | len | semantics |
|--------|----------|-----|-----------|
| `0x32` | `MOVI rd, imm32` | 6 | `rd = imm` |
| `0x16` | `MULI rd, imm32` | 6 | `rd *= imm` |
| `0x48` | `ADDI rd, imm32` | 6 | `rd += imm` |
| `0xfe` | `XORI rd, imm32` | 6 | `rd ^= imm` |
| `0x72` | `MOV rd, rs` | 3 | `rd = rs` |
| `0x37` | `ADD rd, rs` | 3 | `rd += rs` |
| `0x2e` | `MUL rd, rs` | 3 | `rd *= rs` |
| `0x65` | `XOR rd, rs` | 3 | `rd ^= rs` |
| `0x6e` | `LOADB rd, rs` | 3 | `rd = input[rs]`, bounds-checked |
| `0x52` | `ROL rd, imm8` | 3 | `rd = rol32(rd, imm8 & 31)` |
| `0x9a` | `ROR rd, imm8` | 3 | `rd = ror32(rd, imm8 & 31)` |
| `0x28` | `LEN rd` | 2 | `rd = len(input)` |
| `0x56` | `INC rd` | 2 | `rd++` |
| `0x24` | `EQ rd, a, b` | 4 | `rd = (r[b] == r[a])` |
| `0x8b` | `GT rd, a, b` | 4 | `rd = (r[b] > r[a])`, unsigned |
| `0xa6` | `JNZ rd, rel16` | 4 | `if (rd) pc += rel16` |
| `0xd3` | `JMP rel16` | 3 | `pc += rel16` |
| `0x5f` | `HALT` | 1 | emit `r0..r3`, return success |

Two details decide whether the disassembly is right. Both jumps are relative to the **end** of the instruction (`pc + 4 + rel` and `pc + 3 + rel`), and `HALT` writes exactly four dwords out — `r0`, `r1`, `r2`, `r3`. Four 32-bit words is four groups of eight hex digits, which is the serial format. So the VM does not verify anything: it *derives* the expected serial and the caller compares.

##### 9. The program is an ARX hash

469 bytes disassemble cleanly into 119 instructions ending exactly on `HALT` at `0x1d4` ([vmdis.py](vmdis.py), full listing in [vm_program.asm](vm_program.asm)):

```
0x000:  MOVI r0, 0x243f6a88      ; pi digits — Blowfish's init constants
0x006:  MOVI r1, 0x85a308d3
0x00c:  MOVI r2, 0x13198a2e
0x012:  MOVI r3, 0x03707344
0x018:  MOVI r4, 0x00000000      ; i
0x01e:  LEN  r5                  ; n
0x020:  GT   r7, r4, r5          ; r7 = (n > i)
0x024:  JNZ  r7, ->0x02b
0x028:  JMP  ->0x084             ; loop exit
0x02b:  LOADB r6, r4             ; c = id[i]
0x02e:  MOV  r7, r6
0x031:  ADDI r7, 0x9e3779b9
0x037:  ADD  r7, r4
0x03a:  XOR  r0, r7
0x03d:  ROL  r0, 5
0x040:  ADD  r0, r1
...
0x081:  JMP  ->0x020
```

No self-modification, no key material derived from anything but the input, no data-dependent control flow beyond the loop counter. It is a straight-line ARX hash, and the constants are all recognisable — golden ratio `0x9E3779B9`, MurmurHash3's finalisers `0x85EBCA6B` and `0xC2B2AE35`, the SHA-256 IVs `0x6A09E667` / `0xBB67AE85` / `0x510E527F` / `0x1F83D9AB`, and a round of `0xDEADBEEF` / `0xFEEDFACE` at the end.

Absorb one byte per iteration:

```c
t  = c + 0x9E3779B9 + i;   r0 = rol32(r0 ^ t, 5);  r0 += r1;
t  = r0 + 0x7F4A7C15;      r1 = rol32(r1 ^ t, 9);  r1 *= 0x85EBCA6B;
t  = (c * 0x045D9F3B) ^ r1;                        r2 = ror32(r2 + t, 7);
t  = i * 0x27D4EB2D + r2 + r0;                     r3 = rol32(r3 ^ t, 13);
```

then six finalisation rounds over constant quadruples, then mix the length in:

```c
for (c0,c1,c2,c3 in ROUNDS) {
    r0 = rol32(r0 + r3, 7) ^ c0;
    r1 = ror32(r1 ^ r0, 11) + c1;
    r2 = rol32(r2 + r1, 17) ^ c2;
    r3 = ror32(r3 ^ r2, 3) + c3;
}
r0 ^= n * 0xA5B35705;  r1 += n * 0xC2B2AE3D;
r2 ^= n * 0x27D4EB2F;  r3 += n * 0x165667B1;
```

Because the serial is *derived* rather than checked, there is nothing to invert and no solver needed — compute forward and print `r0..r3` as uppercase hex ([keygen.py](keygen.py)).

##### 10. Verify on the pristine binary

`keygen.py` reimplements the hash directly instead of emulating the VM, so it is worth checking the reimplementation against the emulator ([vmemu.py](vmemu.py)) before trusting it — 2,000 random IDs across the full charset and length range, zero mismatches.

Then the real test, on the untouched executable with no debugger attached:

```bash
$ python3 keygen.py NINTH_CIRCLE
NINTH_CIRCLE               3C05D0BF-476FB6CF-DA7B4AFD-C1F28728

$ printf 'NINTH_CIRCLE\n3C05D0BF-476FB6CF-DA7B4AFD-C1F28728\n' | wine NinthCircle.exe
NINTH CIRCLE // key derivation terminal
...
operator> serial>   ACCESS GRANTED :: VM KEY ACCEPTED
```

14 IDs total pass, covering both length bounds and every allowed character class:

```
ABCD                       ACF9F38A-02C35B96-C106DC3B-918B6801    PASS
1234                       4A4E10CC-2DDB90EA-16A70764-B811526D    PASS
A_B-C9                     90A2C67B-1E170EA4-D3D55F89-FFBAB1E6    PASS
WHISTLEDEV                 FA242DBB-98E46F00-59F82701-036F9B31    PASS
NINTH-CIRCLE-2026          9A3F5FEB-C2927CA5-31B5A55E-B840B0DB    PASS
ZZZZZZZZZZZZZZZZZZZZZZZZ   29C8647D-D291DB2D-67282B83-D802D3CD    PASS
...
----- 10 passed, 0 failed -----
```

A wrong serial still gives `ACCESS DENIED`, and lowercase IDs are accepted because `main.main` upper-cases before hashing — `abcd` takes the serial for `ABCD`. Nothing in the binary was patched at any point.

**Keygen:** `python3 keygen.py NINTH_CIRCLE` -> `NINTH_CIRCLE  3C05D0BF-476FB6CF-DA7B4AFD-C1F28728` (`ACCESS GRANTED :: VM KEY ACCEPTED`)

### Takeaways

A bad magic number is not the same as a missing structure. Garble scrambles only the four-byte pclntab magic and leaves `nfunc`, `funcnametab` and `ftab` completely intact, which is enough to defeat every tool that validates the magic before parsing — and that is the entire "stripped and obfuscated Go build metadata" claim. Locating `runtime.firstmoduledata` by searching for pointers to the `.text` base, then parsing the table while ignoring the magic, recovered all 3,940 names and collapsed a 3,787-function binary into 45 functions worth reading. For any Go target where the symbol table "isn't there", check whether it is merely unrecognisable before treating the binary as stripped.

Anti-debug that poisons a key instead of refusing to run is worth expecting specifically. There is no branch to find and patch here: the debugger check feeds a `cmovne` that swaps `key0` for `key0 ^ 0x0CCE9E69`, and a debugged run decrypts the bytecode to noise and reports the ordinary failure message. If a binary behaves differently under a debugger but never *says* so, look for the check's result being consumed as data rather than tested as a condition. The tell here was the anti-debug result being passed as a function *argument* to the decryptor.

`ptrace_scope=1` blocks attaching, not reading a descendant. Spawning the target from the analysis script and reading `/proc/<pid>/mem` needed no ptrace, no debugger, and — usefully against this challenge — never set the PEB flag the anti-debug looks for. Driving the process to a prompt so that package init has finished, then dereferencing a known global, was strictly less work than getting gdb to follow wine through its fork-and-exec.

A VM that *derives* the answer is a much softer target than one that checks it. The obvious plan against a virtualised crackme is to recover the ISA and then invert whatever the bytecode computes, and the immediates being position-encrypted and the opcodes randomised per build are both aimed at making that expensive. But `HALT` emitting exactly four dwords, against a serial format of exactly four hex groups, gave it away before any of the cipher was read: the VM computes the expected serial and hands it back. Counting a terminator's outputs and matching them against the shape of the required answer is a cheap check worth doing early — it decides whether you need an inverse at all.
