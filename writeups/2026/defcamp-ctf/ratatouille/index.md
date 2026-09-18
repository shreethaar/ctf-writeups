# RATatouille

- Category: rev

"We recovered a half-finished telemetry implant from a Michelin inspector's workstation. It stays dormant on our analysis hosts, but incident-response telemetry says it briefly prepared a secret 'signature dish' on the original machine. Reconstruct its activation profile and recover the volatile secret."

A 5 MB stripped Rust binary carrying a full implant (reqwest, rustls, tokio, systemd user-service persistence, browser-profile collection). None of that is the challenge. The flag is in a custom ELF section, and the key to it is the *machine* the implant expected to be running on — so the work is recovering an environment, not an algorithm.

### Solution:

##### 1. The flag is a section, and it is exactly flag-sized

`diec` says Rust 1.98, and the section table has one entry that does not belong to any toolchain:

```
  [14] .rodata   PROGBITS  00000000003e7000  3e7000  0941b6
  [15] .recipe   PROGBITS  000000000047b1b6  47b1b6  000046
  [16] .eh_frame_hdr PROGBITS 000000000047b1fc 47b1fc 009814
```

`0x46` is 70 bytes. The stated flag format is `DCTF{<64 lowercase hex>}` — which is `5 + 64 + 1` = **70 bytes exactly**. So `.recipe` is the flag, encrypted in place, and there is no need to guess what the plaintext looks like.

```
$ xxd -s 0x47b1b6 -l 32 ratatouille
0047b1b6: 565c bcc4 fd91 c4b6 1c1a 2114 a9dc 9955  V\........!....U
0047b1c6: 1276 bdd5 a28f 7941 788f 2c0b f054 86cf  .v....yAx.,..T..
```

The whole binary references it once, at `0x1d768`.

##### 2. The activation profile is spelled out in the gate's compare immediates

`main` (`sub_12dc0`, reached via `lang_start` from `0x1f050`) builds a struct at `rsp+0xb0`, passes it to `sub_125f0`, and demands the return value be `0x1ff` — nine bits, all set:

```asm
1c462:  lea    rdi,[rsp+0xb0]
1c46a:  call   125f0                  ; profile gate
1c46f:  movzx  eax,ax
1c472:  cmp    eax,0x1ff              ; all 9 checks must pass
1c477:  jne    1d488                  ; -> "Workstation rejected. Recipe calibration incomplete."
1c48d:  call   1d6c0                  ; -> decrypt .recipe
```

That gate is the whole prize. It compares each profile field against inline immediates rather than against `.rodata` strings, which is why grepping the binary for the expected hostname or username finds nothing. Decompiled, bit 4 looks like this:

```rust
if *((a0 + 0x28) as *mut i64) != 7 { v5 = 0; }
else {
  v5 = ((*((*((a0 + 0x20) as *mut *mut i32) as i64 + 3) as *mut i32) == 0x75616574
     && **((a0 + 0x20) as *mut *mut i32) == 0x74737567) as u16) << 4;
}
```

Length 7, bytes 0-3 `0x74737567` = `gust`, bytes 3-6 `0x75616574` = `teau` — the field is `gusteau`. Reading all nine the same way recovers the profile the implant was built for:

| bit | field | required value |
|---|---|---|
| 0 | `std::env::consts::OS` | `linux` |
| 1 | `std::env::consts::ARCH` | `x86_64` |
| 2 | anti-VM probe | must come back clean |
| 3 | station | `remy` |
| 4 | user | `gusteau` |
| 5 | shell | `/bin/bash` |
| 6 | hostname | `auguste-gusteau` |
| 7 | menu file | `confit-byaldi\n` |
| 8 | RAM / CPUs | `>= 0x200000` kB and `>= 2` |

Bit 2 is the dormancy the prompt advertises — `/sys/class/dmi/id/product_name` and `/proc/cpuinfo` matched against `vmware`, `virtualbox`, `kvm`, `qemu`, `xen`, `bochs`, `parallels`, `microsoft hyper-v`. It gates execution but contributes nothing to the key.

##### 3. How the pieces connect

![Call graph of RATatouille: Rust main collects the activation profile and runs an inlined anti-VM probe, feeding a nine-bit gate; a failing mask reaches the rejection sink, while a passing mask flows through field marshalling, the FNV-1a-64 seed, the xorshift64 keystream and a plaintext validator to the success sink that prints the flag](callgraph.png)

Curated from `kuna decompile-all --json` rather than `r2 -A` — the profile collection and the entire anti-VM probe are *inlined into `main`*, so an automatic call graph draws them as nothing at all. The green path is the only one that prints a flag.

##### 4. The seed is an FNV-1a-64 of seven of those fields

`sub_1d6c0` marshals the profile into a compact array of seven `&str` before hashing, and reorders it while doing so — `linux` and `x86_64` are moved to the front:

```asm
1d6ca:  mov    rax,[rsi+0x68]         ; last String: ptr
1d6ce:  mov    rdx,[rsi+0x70]         ;              len
1d6dd:  cmp    BYTE PTR [rax+rdx-1],0xa   ; trailing '\n'?
1d6e2:  cmove  rdi,rax
1d6f1:  cmove  rcx,rdx                ; if so, use len-1
1d6f5:  movups xmm0,[rsi+0x78]        ; "linux"   -> field 1
1d6f9:  movups xmm1,[rsi+0x88]        ; "x86_64"  -> field 2
1d700:  movups xmm2,[rsi+0x8]         ; station   -> field 3
1d73d:  call   12840                  ; FNV-1a-64
```

That `cmove` pair matters: the menu field is read from a file and arrives as `confit-byaldi\n`, but it is hashed **without** the newline. `sub_12840` is a textbook FNV-1a-64 (`basis 0xcbf29ce484222325`, prime `0x100000001b3`) with one twist — a `^0xff` then multiply after *every* field, including the last, so the seven fields cannot be run together as one string:

```asm
12907:  xor    rcx,0xff
1290e:  imul   rcx,rax                ; separator, repeated after each field
12da0:  xor    rcx,0xff
12da7:  imul   rcx,rax
12dab:  movabs rax,0x72617461746f7569 ; "ratatoui"
12db5:  xor    rax,rcx                ; seed
```

##### 5. The keystream is xorshift64\*

Back at the single `.recipe` xref, the loop is unrolled two bytes at a time but is plain xorshift64\* with the standard `0x2545F4914F6CDD1D` multiplier, taking the top byte of the product:

```asm
1d75e:  movabs rdx,0x2545f4914f6cdd1d
1d768:  lea    rsi,[rip+0x45da47]     ; 0x47b1b6 -> .recipe
1d770:  mov    rdi,r14
1d773:  shr    rdi,0xc
1d777:  xor    rdi,r14                ; x ^= x >> 12
1d77d:  shl    r8,0x19
1d781:  xor    r8,rdi                 ; x ^= x << 25
1d787:  shr    rdi,0x1b
1d78b:  xor    rdi,r8                 ; x ^= x >> 27
1d794:  imul   r9,rdx
1d798:  shr    r9,0x38                ; (x * M) >> 56
1d79c:  xor    r9b,BYTE PTR [rcx+rsi-0x1]
1d7d8:  cmp    rcx,0x47               ; 70 bytes
```

##### 6. Recover it

Seven fields, seven separators, the `"ratatoui"` mix, then 70 bytes of keystream:

```python
h = 0xcbf29ce484222325
for f in [b"linux", b"x86_64", b"remy", b"gusteau",
          b"/bin/bash", b"auguste-gusteau", b"confit-byaldi"]:
    for b in f:
        h = ((h ^ b) * 0x100000001b3) & M
    h = ((h ^ 0xff) * 0x100000001b3) & M
seed = h ^ 0x72617461746f7569
```

```
$ ./solve.py
seed  = 0x21ce941768b41192
flag  = DCTF{e132475cf5b732c2ba714f028a159d957ace5f790edb629b99387621d03bbc61}
```

Full script: [solve.py](solve.py)

##### 7. The binary confirms its own answer

No need to build the fake workstation to check this. `sub_127e0` — the call at `0x1c4a8` that decides between "Calibration accepted" and "Pantry integrity failure" — is a validator for the decrypted plaintext:

```rust
if ((a1 == 0x46 && (a0[1] as u8 == b'{' && *a0 == 0x46544344))
    && (*((a0 as i64 + 0x45) as *mut u8) == b'}')) {
    // then: all 64 bytes at +5 must be [0-9a-fA-F]
```

Length 70, `0x46544344` = `DCTF`, `{` at offset 4, `}` at offset 0x45, 64 hex digits between. The recovered plaintext satisfies every one of those, and on failure `sub_1d650` zeroes the buffer before the rejection message — the "volatile secret" is wiped rather than leaked. A wrong 64-bit seed producing 70 bytes that pass that check by chance is not a thing that happens.

**Flag:** `DCTF{e132475cf5b732c2ba714f028a159d957ace5f790edb629b99387621d03bbc61}`

### Takeaways

- A non-standard ELF section name is worth more than any string dump. `.recipe` was 70 bytes in a 5 MB binary, had exactly one cross-reference, and matched the stated flag length exactly — that alone reduced the challenge to "find the seed".
- When a check compares against *inline immediates* rather than `.rodata` strings, the expected values are invisible to `strings` and `grep`. Here `grep SHELL` and `grep HOSTNAME` both returned nothing while the binary was demanding `/bin/bash` and `auguste-gusteau`; the values were sitting in `cmp` operands. Read the comparison, not the data section.
- Environment-keyed decryption doesn't need the environment reproduced. The profile is only an input to a hash — deriving the seven strings statically is strictly easier than building a VM named `auguste-gusteau` with a user called `gusteau`, and it sidesteps the anti-VM check entirely.
- Look for the target's own validator before building one. `sub_127e0` made the solve self-verifying, which is worth more than any amount of "this looks right".
